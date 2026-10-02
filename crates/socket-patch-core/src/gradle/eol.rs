//! Line endings of the text files socket-patch owns or edits in a Gradle
//! build. A clone with `core.autocrlf=true` checks those files out with
//! CRLF, so "is this still our file" compares must not see the line-ending
//! difference, and edits must hand the file back in the style they found.

use std::borrow::Cow;

/// Whether `a` and `b` are equal once every `\r\n` is read as `\n`.
/// Nothing else is normalised: a lone `\r`, trailing whitespace or a
/// missing final newline still differ.
pub fn eol_eq(a: &[u8], b: &[u8]) -> bool {
    to_lf(a) == to_lf(b)
}

/// Whether the file uses CRLF: its first line break is `\r\n`. A file
/// without any line break is not CRLF.
pub fn sniff_crlf(text: &[u8]) -> bool {
    match text.iter().position(|&b| b == b'\n') {
        Some(i) => i > 0 && text[i - 1] == b'\r',
        None => false,
    }
}

/// `text` with every line break spelled `\r\n` when `crlf`, else `\n`.
/// Existing `\r\n` pairs are folded first, so the result never holds
/// `\r\r\n`.
pub fn apply_eol(text: &str, crlf: bool) -> String {
    let lf = text.replace("\r\n", "\n");
    if crlf {
        lf.replace('\n', "\r\n")
    } else {
        lf
    }
}

/// The line break [`sniff_crlf`] found in `text`.
pub fn newline_of(text: &str) -> &'static str {
    if sniff_crlf(text.as_bytes()) {
        "\r\n"
    } else {
        "\n"
    }
}

/// `bytes` with every `\r\n` folded to `\n` (borrowed when there is none).
pub fn to_lf(bytes: &[u8]) -> Cow<'_, [u8]> {
    if !bytes.windows(2).any(|w| w == b"\r\n") {
        return Cow::Borrowed(bytes);
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eol_eq_ignores_only_crlf() {
        assert!(eol_eq(b"a\nb\n", b"a\r\nb\r\n"));
        assert!(eol_eq(b"a\r\nb", b"a\nb"));
        assert!(eol_eq(b"", b""));
        assert!(!eol_eq(b"a\n", b"a"));
        assert!(!eol_eq(b"a\rb", b"a\nb"));
        assert!(!eol_eq(b"a \n", b"a\n"));
    }

    #[test]
    fn sniff_reads_the_first_break() {
        assert!(sniff_crlf(b"a\r\nb\n"));
        assert!(!sniff_crlf(b"a\nb\r\n"));
        assert!(!sniff_crlf(b"abc"));
        assert!(!sniff_crlf(b"\n"));
        assert!(sniff_crlf(b"\r\n"));
        assert_eq!(newline_of("x\r\ny"), "\r\n");
        assert_eq!(newline_of("x"), "\n");
    }

    #[test]
    fn apply_eol_round_trips() {
        assert_eq!(apply_eol("a\nb\n", true), "a\r\nb\r\n");
        assert_eq!(apply_eol("a\r\nb\n", true), "a\r\nb\r\n");
        assert_eq!(apply_eol("a\r\nb\r\n", false), "a\nb\n");
        assert_eq!(apply_eol("a", true), "a");
        let crlf = "x\r\ny\r\n";
        assert_eq!(apply_eol(&apply_eol(crlf, false), true), crlf);
    }
}
