//! Starlark lexer over bytes, with byte spans (design 2.2).
//!
//! It is a port of the scanner Bazel itself runs
//! (`net.starlark.java.syntax.Lexer`, read at 5.4.1, 9.3.2 and 10.0.0rc3),
//! so what it refuses is what Bazel refuses: a byte-order mark, a tab in
//! the indentation of a line, a byte outside a string or comment that is
//! not ASCII Starlark, an unclosed string, an escape Bazel rejects, an
//! unmatched bracket. Bytes that are not UTF-8, and NUL, are legal inside
//! comments and string literals and are read; so are mixed line endings
//! and a missing final newline.
//!
//! Two rules are stricter than Bazel, because a wrong reading there is
//! silent:
//!
//! - A carriage return that is not part of a CRLF line end refuses the
//!   file unless it is inside a string. Bazel takes it for a space, so a
//!   CR-only file is one logical line, and a statement after a CR in a
//!   comment is part of the comment (it does not run on Bazel 7.7.2 or
//!   9.3.2), while every editor shows separate statements.
//! - A string is `plain` only when its value is its source bytes on every
//!   Bazel line: no prefix, single-line quotes, no backslash, printable
//!   ASCII only. Any other string is lexed and never given a value: `"é"`
//!   has one length in `MODULE.bazel` up to Bazel 7 and another elsewhere.

use super::MAX_FILE_BYTES;
use crate::formats::text::strip_bom_bytes;

/// A byte range `[start, end)` of the file.
pub type Span = (usize, usize);

/// Why a file cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnreadableKind {
    /// Larger than [`MAX_FILE_BYTES`].
    TooLarge,
    /// Starts with a UTF-8 or UTF-16 byte-order mark.
    Bom,
    /// A carriage return that is not followed by a line feed.
    CrLineEnd,
    /// A tab in the indentation of a line.
    TabIndent,
    /// A byte that starts no Starlark token.
    InvalidByte,
    UnclosedString,
    /// An escape sequence every Bazel line rejects.
    BadEscape,
    /// A number every Bazel line rejects (`017`, `0x`, `1e`).
    BadNumber,
    /// A bracket that is never closed, or closed by another kind.
    Unbalanced,
    /// A backslash outside a string that does not end its line.
    StrayBackslash,
    /// A line indented deeper or shallower than its block.
    Indent,
    /// A `load` whose module or symbols are not plain string literals, so
    /// the names it binds are unknown.
    Load,
    /// A name Bazel predeclares (`bazel_dep`, `include`, `True`) is bound
    /// in the file: later uses of it mean something else.
    Rebound,
}

impl UnreadableKind {
    /// The construct at fault, for the `bazel_workspace_unreadable` detail.
    pub const fn describe(self) -> &'static str {
        match self {
            Self::TooLarge => "the file is larger than 1 MiB",
            Self::Bom => "a byte-order mark, which Bazel rejects",
            Self::CrLineEnd => "a carriage return that is not part of a CRLF line end",
            Self::TabIndent => "a tab used as indentation, which Bazel rejects",
            Self::InvalidByte => "a byte that is not valid outside a string or comment",
            Self::UnclosedString => "an unclosed string literal",
            Self::BadEscape => "an escape sequence Bazel rejects",
            Self::BadNumber => "a number literal Bazel rejects",
            Self::Unbalanced => "an unmatched bracket",
            Self::StrayBackslash => "a backslash that does not end its line",
            Self::Indent => "a line indented differently from its block",
            Self::Load => "a load statement that does not name plain strings",
            Self::Rebound => "an assignment to a name Bazel predeclares",
        }
    }
}

/// A file the reader refuses, and the byte offset of the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unreadable {
    pub kind: UnreadableKind,
    pub at: usize,
}

pub(super) fn fail<T>(kind: UnreadableKind, at: usize) -> Result<T, Unreadable> {
    Err(Unreadable { kind, at })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tok {
    /// An identifier or keyword: `[A-Za-z_][A-Za-z0-9_]*`.
    Ident,
    Int,
    Float,
    /// A string literal. `inner` is the range between its quotes. `plain`
    /// says the value is exactly those bytes on every Bazel line (module
    /// docs); only a plain string is ever read as a value or edited.
    Str {
        inner: Span,
        plain: bool,
    },
    /// An operator, a bracket or punctuation: one to three bytes.
    Op,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    pub tok: Tok,
    pub start: usize,
    pub end: usize,
    /// How many brackets are open around the token. A bracket carries the
    /// depth outside itself, so an opener and its closer agree.
    pub depth: usize,
}

/// One logical line: the tokens up to a line end outside every bracket.
/// Blank and comment-only lines are not lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Line {
    /// Token range `[first, end)`.
    pub first: usize,
    pub end: usize,
    /// Leading spaces of the physical line the first token is on.
    pub indent: usize,
}

/// A `#` comment: from the `#` to the end of the line, without the line
/// end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Comment {
    pub span: Span,
    /// Nothing but whitespace precedes it on its line.
    pub own_line: bool,
}

/// The line endings of a file. A file with no line end at all is `Lf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eol {
    Lf,
    Crlf,
    /// Both kinds. Bazel reads such a file and so does the reader; only an
    /// edit refuses it.
    Mixed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lexed {
    pub tokens: Vec<Token>,
    pub lines: Vec<Line>,
    pub comments: Vec<Comment>,
    pub eol: Eol,
}

/// Tokenize a Starlark file, or say why Bazel (or this reader) refuses it.
pub fn lex(src: &[u8]) -> Result<Lexed, Unreadable> {
    if src.len() > MAX_FILE_BYTES {
        return fail(UnreadableKind::TooLarge, MAX_FILE_BYTES);
    }
    // What a UTF-8 mark is belongs to the shared helper (#905); here it is
    // not stripped, since Bazel rejects the file. The UTF-16 marks are
    // this reader's own.
    let utf8_bom = strip_bom_bytes(src).len() != src.len();
    let utf16_boms: [&[u8]; 2] = [&[0xFF, 0xFE], &[0xFE, 0xFF]];
    if utf8_bom || utf16_boms.iter().any(|bom| src.starts_with(bom)) {
        return fail(UnreadableKind::Bom, 0);
    }
    let mut lexer = Lexer {
        src,
        at: 0,
        open: Vec::new(),
        tokens: Vec::new(),
        lines: Vec::new(),
        comments: Vec::new(),
    };
    lexer.run()?;
    let crlf = src.windows(2).filter(|w| w == b"\r\n").count();
    let lf = src.iter().filter(|b| **b == b'\n').count() - crlf;
    Ok(Lexed {
        tokens: lexer.tokens,
        lines: lexer.lines,
        comments: lexer.comments,
        eol: match (crlf, lf) {
            (0, _) => Eol::Lf,
            (_, 0) => Eol::Crlf,
            _ => Eol::Mixed,
        },
    })
}

/// Operators longer than one byte, longest first; and the one-byte ones.
/// `!` alone, `$`, `?`, `@` and a backtick are not Starlark.
const LONG_OPS: [&[u8]; 20] = [
    b"//=", b"<<=", b">>=", b"**", b"==", b"!=", b"<=", b">=", b"+=", b"-=", b"*=", b"/=", b"%=",
    b"&=", b"|=", b"^=", b"//", b"<<", b">>", b"->",
];
const SHORT_OPS: &[u8] = b"+-*/%<>=,:;.|&^~";

struct Lexer<'a> {
    src: &'a [u8],
    at: usize,
    /// The closer each open bracket waits for.
    open: Vec<u8>,
    tokens: Vec<Token>,
    lines: Vec<Line>,
    comments: Vec<Comment>,
}

impl Lexer<'_> {
    fn run(&mut self) -> Result<(), Unreadable> {
        let src = self.src;
        // Bazel measures indentation at the start of the file and after
        // each line end outside brackets, and nowhere else.
        let mut line_start = true;
        let (mut first, mut indent) = (0, 0);
        while self.at < src.len() {
            if line_start {
                indent = self.indentation()?;
                first = self.tokens.len();
                line_start = false;
                continue;
            }
            let at = self.at;
            match src[at] {
                b' ' | b'\t' => self.at += 1,
                b'\r' => self.carriage_return()?,
                b'\n' => {
                    self.at += 1;
                    if self.open.is_empty() {
                        self.end_line(first, indent);
                        first = self.tokens.len();
                        line_start = true;
                    }
                }
                // A backslash joins the next line, whose leading whitespace
                // is then not indentation.
                b'\\' => match &src[at + 1..] {
                    [b'\n', ..] => self.at += 2,
                    [b'\r', b'\n', ..] => self.at += 3,
                    _ => return fail(UnreadableKind::StrayBackslash, at),
                },
                b'#' => self.comment()?,
                b'"' | b'\'' => self.string(at, at)?,
                b'r' if matches!(src.get(at + 1), Some(b'"' | b'\'')) => self.string(at, at + 1)?,
                b'0'..=b'9' => self.number()?,
                b'.' if src.get(at + 1).is_some_and(u8::is_ascii_digit) => self.number()?,
                b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                    let word = |b: &&u8| b.is_ascii_alphanumeric() || **b == b'_';
                    let len = src[at..].iter().take_while(word).count();
                    self.push(Tok::Ident, at, at + len);
                }
                c @ (b'(' | b'[' | b'{') => {
                    self.push(Tok::Op, at, at + 1);
                    self.open.push(match c {
                        b'(' => b')',
                        b'[' => b']',
                        _ => b'}',
                    });
                }
                c @ (b')' | b']' | b'}') => {
                    if self.open.pop() != Some(c) {
                        return fail(UnreadableKind::Unbalanced, at);
                    }
                    self.push(Tok::Op, at, at + 1);
                }
                c => {
                    let long = LONG_OPS.iter().find(|op| src[at..].starts_with(op));
                    if long.is_none() && !SHORT_OPS.contains(&c) {
                        return fail(UnreadableKind::InvalidByte, at);
                    }
                    self.push(Tok::Op, at, at + long.map_or(1, |op| op.len()));
                }
            }
        }
        if !self.open.is_empty() {
            return fail(UnreadableKind::Unbalanced, src.len());
        }
        self.end_line(first, indent);
        Ok(())
    }

    fn push(&mut self, tok: Tok, start: usize, end: usize) {
        let depth = self.open.len();
        self.tokens.push(Token {
            tok,
            start,
            end,
            depth,
        });
        self.at = end;
    }

    fn end_line(&mut self, first: usize, indent: usize) {
        let end = self.tokens.len();
        if end > first {
            self.lines.push(Line { first, end, indent });
        }
    }

    /// The indentation of the next line that holds a token. Blank and
    /// comment-only lines are skipped, as Bazel skips them. A tab is an
    /// error on any of those lines too: Bazel reports it before it knows
    /// what the line holds (so on 7.7.2 and 9.3.2).
    fn indentation(&mut self) -> Result<usize, Unreadable> {
        let mut indent = 0;
        while let Some(&c) = self.src.get(self.at) {
            match c {
                b' ' => {
                    indent += 1;
                    self.at += 1;
                }
                b'\t' => return fail(UnreadableKind::TabIndent, self.at),
                b'\r' => self.carriage_return()?,
                b'\n' => {
                    indent = 0;
                    self.at += 1;
                }
                b'#' => {
                    self.comment()?;
                    indent = 0;
                }
                _ => break,
            }
        }
        Ok(indent)
    }

    /// Step over the CR of a CRLF line end; a CR anywhere else is refused
    /// (module docs).
    fn carriage_return(&mut self) -> Result<(), Unreadable> {
        if self.src.get(self.at + 1) != Some(&b'\n') {
            return fail(UnreadableKind::CrLineEnd, self.at);
        }
        self.at += 1;
        Ok(())
    }

    /// The comment at `self.at`; stops at its line end.
    fn comment(&mut self) -> Result<(), Unreadable> {
        let (src, start) = (self.src, self.at);
        let len = src[start..].iter().position(|b| *b == b'\n');
        let end = len.map_or(src.len(), |len| start + len);
        let mut text = &src[start..end];
        if end < src.len() {
            text = text.strip_suffix(b"\r").unwrap_or(text);
        }
        if let Some(cr) = text.iter().position(|b| *b == b'\r') {
            return fail(UnreadableKind::CrLineEnd, start + cr);
        }
        let line = src[..start].iter().rposition(|b| *b == b'\n');
        let before = &src[line.map_or(0, |nl| nl + 1)..start];
        self.comments.push(Comment {
            span: (start, start + text.len()),
            own_line: before.iter().all(|b| matches!(b, b' ' | b'\t' | b'\r')),
        });
        self.at = end;
        Ok(())
    }

    /// The string literal whose opening quote is at `quote`; `start` is
    /// where the token starts (the `r` of a raw string).
    fn string(&mut self, start: usize, quote: usize) -> Result<(), Unreadable> {
        let src = self.src;
        let (q, raw) = (src[quote], quote > start);
        let triple = src[quote + 1..].starts_with(&[q, q]);
        let body = quote + if triple { 3 } else { 1 };
        let mut plain = !raw && !triple;
        let mut i = body;
        let close = loop {
            let Some(&c) = src.get(i) else {
                return fail(UnreadableKind::UnclosedString, start);
            };
            match c {
                b'\n' if !triple => return fail(UnreadableKind::UnclosedString, start),
                b'\\' => {
                    plain = false;
                    i = escape(src, i, raw, start)?;
                }
                _ if c == q && (!triple || src[i + 1..].starts_with(&[q, q])) => break i,
                _ => {
                    plain &= (0x20..=0x7E).contains(&c);
                    i += 1;
                }
            }
        };
        let inner = (body, close);
        self.push(Tok::Str { inner, plain }, start, close + body - quote);
        Ok(())
    }

    /// An integer or float at `self.at`, by Bazel's own scan. Only a
    /// decimal integer is later read as a value.
    fn number(&mut self) -> Result<(), Unreadable> {
        let (src, start) = (self.src, self.at);
        let run = |from: usize, ok: fn(&u8) -> bool| {
            from + src[from..].iter().take_while(|b| ok(b)).count()
        };
        let bad = fail(UnreadableKind::BadNumber, start);
        let radix = match (src[start], src.get(start + 1).map(u8::to_ascii_lowercase)) {
            (b'0', Some(b'x')) => 16,
            (b'0', Some(b'o')) => 8,
            (b'0', Some(b'b')) => 2,
            _ => 10,
        };
        if radix != 10 {
            let digit: fn(&u8) -> bool = match radix {
                16 => u8::is_ascii_hexdigit,
                8 => u8::is_ascii_digit,
                _ => |b| matches!(b, b'0' | b'1'),
            };
            let end = run(start + 2, digit);
            let digits = &src[start + 2..end];
            if digits.is_empty() || (radix == 8 && digits.iter().any(|b| *b > b'7')) {
                return bad;
            }
            self.push(Tok::Int, start, end);
            return Ok(());
        }
        let mut end = run(start, u8::is_ascii_digit);
        let mut float = false;
        if src.get(end) == Some(&b'.') {
            float = true;
            end = run(end + 1, u8::is_ascii_digit);
        }
        if matches!(src.get(end), Some(b'e' | b'E')) {
            float = true;
            let digits = end + 1 + usize::from(matches!(src.get(end + 1), Some(b'+' | b'-')));
            end = run(digits, u8::is_ascii_digit);
            if end == digits {
                return bad;
            }
        }
        // The Python 2 octal `017` is an error on every Bazel line.
        if !float && end - start > 1 && src[start] == b'0' {
            return bad;
        }
        self.push(if float { Tok::Float } else { Tok::Int }, start, end);
        Ok(())
    }
}

/// The offset after the backslash sequence at `at` in a string literal
/// that starts at `literal`. A raw string keeps the backslash and the byte
/// after it. Otherwise the sequence must be one Bazel accepts: `\a`, `\b`,
/// `\f` and `\v` are errors on Bazel 5 only and are let through, since
/// such a string never gets a value here; `\x`, `\u`, `\U`, `\N`, an
/// unknown letter and an octal value above `\377` are errors on every line.
fn escape(src: &[u8], at: usize, raw: bool, literal: usize) -> Result<usize, Unreadable> {
    let Some(&c) = src.get(at + 1) else {
        return fail(UnreadableKind::UnclosedString, literal);
    };
    Ok(match c {
        b'\r' if src.get(at + 2) == Some(&b'\n') => at + 3,
        _ if raw => at + 2,
        b'\n' | b'\r' | b'n' | b'r' | b't' | b'\\' | b'\'' | b'"' | b'a' | b'b' | b'f' | b'v' => {
            at + 2
        }
        b'0'..=b'7' => {
            let digits = src[at + 1..].iter().take(3);
            let digits = digits.take_while(|b| (b'0'..=b'7').contains(b)).count();
            let octal = &src[at + 1..at + 1 + digits];
            if octal.iter().fold(0, |v, b| v * 8 + u32::from(b - b'0')) > 0xFF {
                return fail(UnreadableKind::BadEscape, at);
            }
            at + 1 + digits
        }
        _ => return fail(UnreadableKind::BadEscape, at),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One token per item: its source text, `"…"` for a plain string and
    /// `~…~` for any other, with `@depth` when inside brackets.
    fn render(src: &str) -> Vec<String> {
        let lexed = lex(src.as_bytes()).expect("lexes");
        let tokens = lexed.tokens.iter().map(|t| {
            let text = match t.tok {
                Tok::Str { inner, plain: true } => format!("\"{}\"", &src[inner.0..inner.1]),
                Tok::Str { inner, .. } => format!("~{}~", &src[inner.0..inner.1]),
                _ => src[t.start..t.end].to_string(),
            };
            match t.depth {
                0 => text,
                depth => format!("{text}@{depth}"),
            }
        });
        tokens.collect()
    }

    fn refusal(src: &[u8]) -> Option<(UnreadableKind, usize)> {
        lex(src).err().map(|e| (e.kind, e.at))
    }

    #[test]
    fn tokens_carry_spans_and_bracket_depth() {
        assert_eq!(
            render("x = f(a, [1, 2.5], k = 'v')  # tail\n"),
            [
                "x", "=", "f", "(", "a@1", ",@1", "[@1", "1@2", ",@2", "2.5@2", "]@1", ",@1",
                "k@1", "=@1", "\"v\"@1", ")"
            ]
        );
        // Multi-byte operators are one token, so `==` is never an assignment.
        assert_eq!(
            render("a //= b ** c == d != e <<= f -> g <= h"),
            ["a", "//=", "b", "**", "c", "==", "d", "!=", "e", "<<=", "f", "->", "g", "<=", "h"]
        );
        assert_eq!(render("a.b(.5, 0x1F, 0o17, 0b1, 1e3, 0)").len(), 16);
        let lexed = lex(b"ab = \"cd\"").unwrap();
        let spans: Vec<Span> = lexed.tokens.iter().map(|t| (t.start, t.end)).collect();
        assert_eq!(spans, [(0, 2), (3, 4), (5, 9)]);
    }

    /// Only a string whose value is its bytes on every Bazel line is plain
    /// (probe S5: `"café"` has length 4 in `MODULE.bazel` up to 7.7.2 and 5
    /// elsewhere; `\a` is an error on 5.4.1).
    #[test]
    fn a_string_is_plain_only_when_every_bazel_reads_the_same_value() {
        for (src, want) in [
            (r#""plain""#, r#""plain""#),
            (r#"'it "is"'"#, r#""it "is"""#),
            (r#""""#, r#""""#),
            (r#""a\nb""#, r"~a\nb~"),
            (r#""a\101""#, r"~a\101~"),
            (r#""a\"b""#, r#"~a\"b~"#),
            (r#"r"a\nb""#, r"~a\nb~"),
            (r#"r"plain""#, "~plain~"),
            (r#""""doc""""#, "~doc~"),
            ("'''a\nb'''", "~a\nb~"),
            (r#""""a"b""c""""#, r#"~a"b""c~"#),
            ("\"caf\u{e9}\"", "~caf\u{e9}~"),
            ("\"a\tb\"", "~a\tb~"),
            ("\"a\\\nb\"", "~a\\\nb~"),
        ] {
            assert_eq!(render(src), [want], "{src:?}");
        }
        // Bytes that are not UTF-8, NUL and a lone CR are content.
        for src in [
            &b"\"caf\xe9\""[..],
            b"'a\x80b'",
            b"\"pl\x00ain\"",
            b"\"a\rb\"",
        ] {
            let lexed = lex(src).unwrap();
            let inner = (1, src.len() - 1);
            assert_eq!(
                lexed.tokens[0].tok,
                Tok::Str {
                    inner,
                    plain: false
                }
            );
        }
    }

    /// One case per refusal, with the offset the message points at.
    #[test]
    fn what_bazel_rejects_is_refused() {
        use UnreadableKind::*;
        let cases: [(&[u8], UnreadableKind, usize); 31] = [
            (b"\xef\xbb\xbfmodule()\n", Bom, 0),
            (b"\xff\xfem\x00", Bom, 0),
            (b"\xfe\xff\x00m", Bom, 0),
            (b"a = 1\n\xef\xbb\xbfb = 2\n", InvalidByte, 6),
            (b"a()\rb()\r", CrLineEnd, 3),
            (b"# note\ra()\n", CrLineEnd, 6),
            (b"a()\r\r\n", CrLineEnd, 3),
            (b"\ta = 1\n", TabIndent, 0),
            (b"a = 1\n\t\nb = 2\n", TabIndent, 6),
            (b"a = 1\n \t# c\n", TabIndent, 7),
            (b"def f():\n\treturn 1\n", TabIndent, 9),
            (b"a = 1 \x0c\n", InvalidByte, 6),
            (b"a\x0b= 1\n", InvalidByte, 1),
            (b"a\xc2\xa0= 1\n", InvalidByte, 1),
            (b"a = 1\n\x1a", InvalidByte, 6),
            (b"a = \x00\n", InvalidByte, 4),
            (b"a = $b\n", InvalidByte, 4),
            (b"a = !b\n", InvalidByte, 4),
            (b"a = \"b\nc\"\n", UnclosedString, 4),
            (b"a = '''b\n", UnclosedString, 4),
            (b"a = \"b\\", UnclosedString, 4),
            (b"a = \"\\x41\"\n", BadEscape, 5),
            (b"a = \"\\u00e9\"\n", BadEscape, 5),
            (b"a = \"\\q\"\n", BadEscape, 5),
            (b"a = \"\\777\"\n", BadEscape, 5),
            (b"a = 017\n", BadNumber, 4),
            (b"a = 0x\n", BadNumber, 4),
            (b"a = 0o8\n", BadNumber, 4),
            (b"a = 1e\n", BadNumber, 4),
            (b"f(a]\n", Unbalanced, 3),
            (b"a = \\ 1\n", StrayBackslash, 4),
        ];
        for (src, kind, at) in cases {
            assert_eq!(
                refusal(src),
                Some((kind, at)),
                "{:?}",
                src.escape_ascii().to_string()
            );
        }
        assert_eq!(refusal(b"f(a\n"), Some((Unbalanced, 4)));
        assert_eq!(refusal(b")\n"), Some((Unbalanced, 0)));
        let big = vec![b'\n'; MAX_FILE_BYTES + 1];
        assert_eq!(refusal(&big), Some((TooLarge, MAX_FILE_BYTES)));
        assert!(lex(&big[1..]).is_ok());
    }

    /// Probe S5: Bazel accepts each of these on every line, so none of
    /// them may refuse the file.
    #[test]
    fn what_bazel_accepts_is_read() {
        for (src, eol) in [
            (&b"a = 1\r\nb = 2\r\n"[..], Eol::Crlf),
            (b"a = 1\r\nb = 2\n", Eol::Mixed),
            (b"a = 1\nb = 2", Eol::Lf),
            (b"a = 1", Eol::Lf),
            (b"# caf\xe9 \x00 \xf0\x9f\n", Eol::Lf),
            (b"a =\t1\nf(\n\t1,\n)\n", Eol::Lf),
            (b"a = 1 \n  \n   # c\n", Eol::Lf),
            (b"", Eol::Lf),
        ] {
            let lexed = lex(src).unwrap_or_else(|e| panic!("{e:?}: {src:?}"));
            assert_eq!(lexed.eol, eol, "{src:?}");
        }
        // `\a`, `\b`, `\f`, `\v` and octal escapes: valid from Bazel 6.
        assert_eq!(render(r#""\a\b\f\v\0\377\\\'""#).len(), 1);
    }

    #[test]
    fn logical_lines_follow_brackets_continuations_and_semicolons() {
        let src = "a = 1; b = 2\n\n  # c\nf(\n    x,\n)\ndef g():\n    h = \\\n        3\n";
        let lexed = lex(src.as_bytes()).unwrap();
        let lines: Vec<(String, usize)> = lexed
            .lines
            .iter()
            .map(|l| {
                let text = &src[lexed.tokens[l.first].start..lexed.tokens[l.end - 1].end];
                (
                    text.split_whitespace().collect::<Vec<_>>().join(" "),
                    l.indent,
                )
            })
            .collect();
        let want = [
            ("a = 1; b = 2", 0),
            ("f( x, )", 0),
            ("def g():", 0),
            ("h = \\ 3", 4),
        ];
        assert_eq!(lines, want.map(|(text, indent)| (text.to_string(), indent)));
        // A CRLF continuation joins lines too, and a final line needs no
        // line end.
        let crlf = lex(b"a = \\\r\n  1\r\nb = 2").unwrap();
        assert_eq!(crlf.lines.len(), 2);
        assert_eq!((crlf.lines[1].first, crlf.lines[1].end), (3, 6));
    }

    #[test]
    fn comments_keep_their_span_and_whether_they_own_the_line() {
        let src =
            "# top\r\nf(  # open\r\n    # inner\r\n    a,\r\n)  # tail\r\n\"\"\"x\ny\"\"\" # s\n";
        let lexed = lex(src.as_bytes()).unwrap();
        let got: Vec<(&str, bool)> = lexed
            .comments
            .iter()
            .map(|c| (&src[c.span.0..c.span.1], c.own_line))
            .collect();
        assert_eq!(
            got,
            [
                ("# top", true),
                ("# open", false),
                ("# inner", true),
                ("# tail", false),
                ("# s", false)
            ]
        );
        // A comment at the end of a file with no final newline keeps a
        // trailing CR out of nothing: that CR is a lone one.
        assert_eq!(refusal(b"a()  # c\r"), Some((UnreadableKind::CrLineEnd, 8)));
    }
}
