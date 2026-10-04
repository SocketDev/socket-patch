//! A text file's line-ending style, for the writers that must hand a file
//! back in the style they found it.
//!
//! The round trip the yarn-berry writers use (the pattern the other
//! CRLF-preserving rewriters in this crate follow too): classify the file,
//! refuse [`LineEndings::Mixed`] (there is no single style to restore),
//! operate on the LF-normalized text ([`to_lf`]), and re-expand whatever is
//! written or recorded with [`LineEndings::restore`].

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

}
