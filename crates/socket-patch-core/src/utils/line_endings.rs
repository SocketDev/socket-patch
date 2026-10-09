//! A text file's line-ending style, for the writers that must hand a file
//! back in the style they found it.
//!
//! The round trip the yarn-berry writers use (the pattern the other
//! CRLF-preserving rewriters in this crate follow too): classify the file,
//! refuse [`LineEndings::Mixed`] (there is no single style to restore),
//! operate on the LF-normalized text ([`to_lf`]), and re-expand whatever is
//! written or recorded with [`LineEndings::restore`].
//!
//! Writers that insert lines pick their terminator with [`terminator`] and
//! look for what they wrote with [`respell`]; "is this still our file"
//! checks, which a `core.autocrlf` checkout must not defeat, compare with
//! [`eol_eq`].

use std::borrow::Cow;

/// How a text file ends its lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LineEndings {
    /// No line break at all: an empty file, or one unterminated line.
    None,
    /// Every line break is `\n`.
    Lf,
    /// Every line break is `\r\n`.
    Crlf,
    /// `\r\n` and bare `\n` both occur, or a `\r` stands outside a `\r\n`
    /// pair. There is no single style to restore, so an LF-normalize and
    /// re-expand round trip would rewrite lines nobody asked to touch.
    Mixed,
}

impl LineEndings {
    /// Classify `text`.
    pub(crate) fn of(text: &str) -> Self {
        let bytes = text.as_bytes();
        let (mut crlf, mut lf) = (false, false);
        for (i, &b) in bytes.iter().enumerate() {
            match b {
                b'\n' if i > 0 && bytes[i - 1] == b'\r' => crlf = true,
                b'\n' => lf = true,
                b'\r' if bytes.get(i + 1) != Some(&b'\n') => return Self::Mixed,
                _ => {}
            }
        }
        match (crlf, lf) {
            (false, false) => Self::None,
            (false, true) => Self::Lf,
            (true, false) => Self::Crlf,
            (true, true) => Self::Mixed,
        }
    }

    /// `lf` — text built or edited in LF form — spelled in this style:
    /// every `\n` becomes `\r\n` for a CRLF file; any other style is
    /// returned as is.
    pub(crate) fn restore(self, lf: &str) -> Cow<'_, str> {
        match self {
            Self::Crlf => Cow::Owned(lf.replace('\n', "\r\n")),
            _ => Cow::Borrowed(lf),
        }
    }
}

/// `text` with every `\r\n` folded to `\n` (borrowed when there is none).
pub(crate) fn to_lf(text: &str) -> Cow<'_, str> {
    if text.contains("\r\n") {
        Cow::Owned(text.replace("\r\n", "\n"))
    } else {
        Cow::Borrowed(text)
    }
}

/// The line terminator yarn berry itself would write into a file holding
/// `text`, minus its operating-system fallback: `\r\n` when CRLF breaks
/// strictly outnumber LF ones, `\n` otherwise (a tie, a file with no break
/// at all, bare `\r`s). Mirrors `getEndOfLine` in yarnpkg-fslib's
/// `FakeFS.ts`, which falls back to `os.EOL` where this falls back to LF —
/// a re-serialization must not depend on the OS it runs on.
pub(crate) fn majority_terminator(text: &str) -> &'static str {
    let crlf = text.matches("\r\n").count();
    let lf = text.matches('\n').count() - crlf;
    if crlf > lf {
        "\r\n"
    } else {
        "\n"
    }
}

/// The terminator a writer uses for the lines it inserts into `text`:
/// `\r\n` for a CRLF file, `\n` for an LF file or one with no break at all,
/// and the [`majority_terminator`] for a mixed file. Majority is stable
/// under appending lines in its own style, so a revert that removes
/// `{line}{terminator}` matches what the forward pass wrote.
pub(crate) fn terminator(text: &str) -> &'static str {
    match LineEndings::of(text) {
        LineEndings::Crlf => "\r\n",
        LineEndings::Mixed => majority_terminator(text),
        LineEndings::Lf | LineEndings::None => "\n",
    }
}

/// `text` with every line break spelled `nl` (`"\r\n"` or `"\n"`):
/// existing `\r\n` pairs are folded first, so the result never holds
/// `\r\r\n`. How a writer spells a recorded fragment in the
/// [`terminator`] of the file it is looking for that fragment in.
pub(crate) fn respell(text: &str, nl: &str) -> String {
    let lf = to_lf(text);
    if nl == "\r\n" {
        lf.replace('\n', "\r\n")
    } else {
        lf.into_owned()
    }
}

/// Whether `a` and `b` are equal once every `\r\n` is read as `\n`.
/// Nothing else is normalised: a lone `\r`, trailing whitespace or a
/// missing final newline still differ. Bytes, not text: the files compared
/// need not be UTF-8.
pub(crate) fn eol_eq(a: &[u8], b: &[u8]) -> bool {
    to_lf_bytes(a) == to_lf_bytes(b)
}

/// [`to_lf`] for bytes not known to be UTF-8.
fn to_lf_bytes(bytes: &[u8]) -> Cow<'_, [u8]> {
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
    fn classifies_every_style() {
        assert_eq!(LineEndings::of(""), LineEndings::None);
        assert_eq!(LineEndings::of("one line"), LineEndings::None);
        assert_eq!(LineEndings::of("a\nb\n"), LineEndings::Lf);
        assert_eq!(LineEndings::of("a\r\nb\r\n"), LineEndings::Crlf);
        assert_eq!(LineEndings::of("a\r\nb"), LineEndings::Crlf);
        assert_eq!(LineEndings::of("a\r\nb\n"), LineEndings::Mixed);
        assert_eq!(LineEndings::of("a\nb\r\n"), LineEndings::Mixed);
        // A bare CR is never a style we can restore, alone or beside CRLF.
        assert_eq!(LineEndings::of("a\rb"), LineEndings::Mixed);
        assert_eq!(LineEndings::of("a\r\nb\rc\r\n"), LineEndings::Mixed);
        assert_eq!(LineEndings::of("trailing\r"), LineEndings::Mixed);
        // A BOM is not a line ending.
        assert_eq!(LineEndings::of("\u{feff}a\r\n"), LineEndings::Crlf);
    }

    #[test]
    fn normalize_and_restore_round_trip_a_uniform_file() {
        for text in ["a\nb\n\nc", "a\r\nb\r\n\r\nc", "no break", ""] {
            let style = LineEndings::of(text);
            assert_eq!(style.restore(&to_lf(text)), text, "{text:?}");
        }
        assert!(matches!(to_lf("a\nb"), Cow::Borrowed(_)));
        assert!(matches!(LineEndings::Lf.restore("a\nb"), Cow::Borrowed(_)));
    }

    #[test]
    fn majority_terminator_follows_yarn_but_never_the_os() {
        assert_eq!(majority_terminator("a\r\nb\r\nc\n"), "\r\n");
        assert_eq!(majority_terminator("a\r\nb\nc\n"), "\n");
        assert_eq!(majority_terminator("a\r\nb\n"), "\n", "a tie is LF");
        assert_eq!(majority_terminator("{}"), "\n", "no break: LF, not os.EOL");
    }

    #[test]
    fn terminator_follows_the_file_and_the_majority_when_mixed() {
        assert_eq!(terminator("a\nb\n"), "\n");
        assert_eq!(terminator("a\r\nb\r\n"), "\r\n");
        assert_eq!(terminator("a\r\nb"), "\r\n");
        assert_eq!(terminator(""), "\n");
        assert_eq!(terminator("one line"), "\n");
        assert_eq!(terminator("a\r\nb\r\nc\n"), "\r\n", "CRLF majority");
        assert_eq!(terminator("a\nb\nc\r\n"), "\n", "LF majority");
        assert_eq!(terminator("a\r\nb\n"), "\n", "a tie is LF");
        // A bare CR makes the file mixed; it is not counted as a break.
        assert_eq!(terminator("a\rb\r\n"), "\r\n");
    }

    #[test]
    fn eol_eq_ignores_only_crlf() {
        assert!(eol_eq(b"a\nb\n", b"a\r\nb\r\n"));
        assert!(eol_eq(b"a\r\nb", b"a\nb"));
        assert!(eol_eq(b"", b""));
        assert!(!eol_eq(b"a\n", b"a"));
        assert!(!eol_eq(b"a\rb", b"a\nb"));
        assert!(!eol_eq(b"a \n", b"a\n"));
        // Not UTF-8: still compared byte for byte past the folding.
        assert!(eol_eq(b"\xff\r\n", b"\xff\n"));
        assert!(matches!(to_lf_bytes(b"a\nb"), Cow::Borrowed(_)));
        for text in ["a\r\nb\n", "a\rb", "\r\n\r\n", "x"] {
            assert_eq!(to_lf_bytes(text.as_bytes()), to_lf(text).as_bytes());
        }
    }

    #[test]
    fn respell_round_trips() {
        assert_eq!(respell("a\nb\n", "\r\n"), "a\r\nb\r\n");
        assert_eq!(respell("a\r\nb\n", "\r\n"), "a\r\nb\r\n");
        assert_eq!(respell("a\r\nb\r\n", "\n"), "a\nb\n");
        assert_eq!(respell("a", "\r\n"), "a");
        let crlf = "x\r\ny\r\n";
        assert_eq!(respell(&respell(crlf, "\n"), terminator(crlf)), crlf);
    }
}
