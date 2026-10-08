//! A small Groovy / Kotlin script tokenizer: enough of either DSL to find
//! blocks, calls and string literals without being fooled by comments or
//! strings.
//!
//! Comments are skipped (Kotlin block comments nest). A string literal is
//! one [`Tok::Str`]: Groovy `'…'`, `"…"`, `'''…'''`, `"""…"""` and Kotlin
//! `"…"`, `"""…"""` (raw, no escapes) and `'c'`. A string is `literal`
//! only when its value is fully known: any `$name` / `${…}` interpolation,
//! an escape we do not decode or a missing close quote makes it
//! non-literal (its `value` then holds the raw text, interpolations kept).
//! Everything else is an identifier, a number or one punctuation byte.
//! Slashy strings are not recognised (a `/` is punctuation).

/// Which DSL a script is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dsl {
    Groovy,
    Kotlin,
}

/// The DSL of a script from its file name: `*.gradle.kts` (and `*.kts`) is
/// Kotlin, `*.gradle` is Groovy, anything else is not a Gradle script.
pub fn dsl_of(rel: &str) -> Option<Dsl> {
    if rel.ends_with(".kts") {
        Some(Dsl::Kotlin)
    } else if rel.ends_with(".gradle") {
        Some(Dsl::Groovy)
    } else {
        None
    }
}

/// Script bytes as text: a leading BOM is dropped and anything that is not
/// UTF-8 is `None` (unparseable), never decoded lossily.
pub fn decode(bytes: &[u8]) -> Option<String> {
    let bytes = crate::formats::text::strip_bom_bytes(bytes);
    String::from_utf8(bytes.to_vec()).ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    Ident(String),
    /// A string literal. `literal` is false when it interpolates, uses an
    /// escape we do not decode, or is unterminated.
    Str {
        value: String,
        literal: bool,
    },
    /// A run of digits and the letters / underscores glued to it.
    Num(String),
    Punct(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub tok: Tok,
    /// Byte range in the source.
    pub start: usize,
    pub end: usize,
}

/// Tokenize `text` (a BOM is skipped).
pub fn tokens(text: &str, dsl: Dsl) -> Vec<Token> {
    lex(text, dsl).0
}

/// Whether `text` tokenizes cleanly: every string and block comment is
/// closed and every bracket is matched. A script that fails this is
/// treated as unparseable by the callers that must fail safe.
pub fn well_formed(text: &str, dsl: Dsl) -> bool {
    let (toks, clean) = lex(text, dsl);
    if !clean {
        return false;
    }
    let mut stack = Vec::new();
    for t in &toks {
        match t.tok {
            Tok::Punct(c @ (b'(' | b'[' | b'{')) => stack.push(c),
            Tok::Punct(c @ (b')' | b']' | b'}')) => {
                let want = match c {
                    b')' => b'(',
                    b']' => b'[',
                    _ => b'{',
                };
                if stack.pop() != Some(want) {
                    return false;
                }
            }
            _ => {}
        }
    }
    stack.is_empty()
}

/// The tokens and whether every string / comment was closed.
fn lex(src: &str, dsl: Dsl) -> (Vec<Token>, bool) {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut clean = true;
    let mut i = crate::formats::text::split_bom(src).0.len();
    // A `#!` first line (shebang) is a comment in both DSLs.
    if b[i..].starts_with(b"#!") {
        while i < b.len() && b[i] != b'\n' {
            i += 1;
        }
    }
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
        } else if b[i..].starts_with(b"//") {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i..].starts_with(b"/*") {
            match skip_block_comment(b, i, dsl == Dsl::Kotlin) {
                Some(end) => i = end,
                None => {
                    clean = false;
                    i = b.len();
                }
            }
        } else if c == b'\'' || c == b'"' {
            let s = scan_string(src, i, dsl);
            clean &= s.closed;
            out.push(Token {
                tok: Tok::Str {
                    value: s.value,
                    literal: s.literal,
                },
                start: i,
                end: s.end,
            });
            i = s.end;
        } else if c == b'`' && dsl == Dsl::Kotlin {
            // A backticked Kotlin identifier.
            let start = i;
            let close = src[i + 1..].find(['`', '\n']).map(|j| i + 1 + j);
            match close {
                Some(j) if b[j] == b'`' => {
                    out.push(Token {
                        tok: Tok::Ident(src[i + 1..j].to_string()),
                        start,
                        end: j + 1,
                    });
                    i = j + 1;
                }
                _ => {
                    out.push(Token {
                        tok: Tok::Punct(b'`'),
                        start,
                        end: i + 1,
                    });
                    i += 1;
                }
            }
        } else if c.is_ascii_digit() {
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            out.push(Token {
                tok: Tok::Num(src[start..i].to_string()),
                start,
                end: i,
            });
        } else if is_ident_start(src, i) {
            let start = i;
            while i < b.len() && is_ident_part(src, i) {
                i += src[i..].chars().next().map_or(1, char::len_utf8);
            }
            out.push(Token {
                tok: Tok::Ident(src[start..i].to_string()),
                start,
                end: i,
            });
        } else if c.is_ascii() {
            out.push(Token {
                tok: Tok::Punct(c),
                start: i,
                end: i + 1,
            });
            i += 1;
        } else {
            i += src[i..].chars().next().map_or(1, char::len_utf8);
        }
    }
    (out, clean)
}

fn is_ident_start(src: &str, i: usize) -> bool {
    src[i..]
        .chars()
        .next()
        .is_some_and(|ch| ch.is_alphabetic() || ch == '_' || ch == '$')
}

fn is_ident_part(src: &str, i: usize) -> bool {
    src[i..]
        .chars()
        .next()
        .is_some_and(|ch| ch.is_alphanumeric() || ch == '_' || ch == '$')
}

/// The end of the block comment opening at `i`; `None` when unclosed.
fn skip_block_comment(b: &[u8], mut i: usize, nests: bool) -> Option<usize> {
    let mut depth = 0usize;
    while i < b.len() {
        if b[i..].starts_with(b"/*") && (nests || depth == 0) {
            depth += 1;
            i += 2;
        } else if b[i..].starts_with(b"*/") {
            depth -= 1;
            i += 2;
            if depth == 0 {
                return Some(i);
            }
        } else {
            i += 1;
        }
    }
    None
}

struct Scanned {
    value: String,
    literal: bool,
    closed: bool,
    end: usize,
}

/// Scan the string literal whose opening quote is at `start`.
fn scan_string(src: &str, start: usize, dsl: Dsl) -> Scanned {
    let b = src.as_bytes();
    let q = b[start];
    let triple = b[start..].starts_with(&[q, q, q]) && !(dsl == Dsl::Kotlin && q == b'\'');
    // Kotlin raw strings decode no escapes; every other form does.
    let raw = dsl == Dsl::Kotlin && triple;
    // Groovy single-quoted strings never interpolate.
    let templates = q == b'"';
    let mut i = start + if triple { 3 } else { 1 };
    let mut value = String::new();
    let mut literal = true;
    loop {
        if i >= b.len() {
            return Scanned {
                value,
                literal: false,
                closed: false,
                end: b.len(),
            };
        }
        if triple {
            if b[i..].starts_with(&[q, q, q]) {
                // Kotlin: a run of more than three quotes keeps the extras.
                let mut run = 3;
                while dsl == Dsl::Kotlin && b.get(i + run) == Some(&q) {
                    run += 1;
                }
                for _ in 3..run {
                    value.push(q as char);
                }
                i += run;
                break;
            }
        } else if b[i] == q {
            i += 1;
            break;
        } else if b[i] == b'\n' {
            return Scanned {
                value,
                literal: false,
                closed: false,
                end: i,
            };
        }
        if b[i] == b'\\' && !raw {
            match decode_escape(src, i) {
                Some((ch, len)) => {
                    if let Some(ch) = ch {
                        value.push(ch);
                    }
                    i += len;
                }
                None => {
                    literal = false;
                    let len = src[i + 1..].chars().next().map_or(0, char::len_utf8);
                    value.push_str(&src[i..i + 1 + len]);
                    i += 1 + len;
                }
            }
            continue;
        }
        if b[i] == b'$' && templates {
            if b.get(i + 1) == Some(&b'{') {
                literal = false;
                let end = skip_template(src, i + 1, dsl);
                value.push_str(&src[i..end]);
                i = end;
                continue;
            }
            let ident = i + 1 < b.len() && is_ident_start(src, i + 1) && b[i + 1] != b'$';
            if ident || dsl == Dsl::Groovy {
                // Groovy rejects a bare `$` in a GString; either way the
                // value is not known.
                literal = false;
            }
        }
        let ch = src[i..].chars().next().unwrap_or('\u{fffd}');
        value.push(ch);
        i += ch.len_utf8();
    }
    Scanned {
        value,
        literal,
        closed: true,
        end: i,
    }
}

/// Decode the escape at `i` (a backslash): `(char, bytes consumed)`, with
/// `None` for a line continuation. `None` overall for an escape we do not
/// decode.
fn decode_escape(src: &str, i: usize) -> Option<(Option<char>, usize)> {
    let b = src.as_bytes();
    let e = *b.get(i + 1)?;
    let ch = match e {
        b'\\' | b'\'' | b'"' | b'$' => e as char,
        b'n' => '\n',
        b't' => '\t',
        b'r' => '\r',
        b'b' => '\u{8}',
        b'f' => '\u{c}',
        b'\n' => return Some((None, 2)),
        b'u' => {
            let hex = src.get(i + 2..i + 6)?;
            if !hex.bytes().all(|h| h.is_ascii_hexdigit()) {
                return None;
            }
            return Some((Some(char::from_u32(u32::from_str_radix(hex, 16).ok()?)?), 6));
        }
        _ => return None,
    };
    Some((Some(ch), 2))
}

/// The end (one past the `}`) of the `${…}` template whose `{` is at
/// `open`; nested strings and braces are skipped.
fn skip_template(src: &str, open: usize, dsl: Dsl) -> usize {
    let b = src.as_bytes();
    let mut depth = 0usize;
    let mut i = open;
    while i < b.len() {
        match b[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            b'\'' | b'"' => {
                i = scan_string(src, i, dsl).end;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    b.len()
}

// ── token helpers ───────────────────────────────────────────────────────────────

pub fn is_ident(t: Option<&Token>, name: &str) -> bool {
    matches!(t, Some(Token { tok: Tok::Ident(n), .. }) if n == name)
}

pub fn is_punct(t: Option<&Token>, p: u8) -> bool {
    matches!(t, Some(Token { tok: Tok::Punct(c), .. }) if *c == p)
}

/// The literal value of a string token.
pub fn literal_of(t: Option<&Token>) -> Option<&str> {
    match t {
        Some(Token {
            tok: Tok::Str {
                value,
                literal: true,
            },
            ..
        }) => Some(value),
        _ => None,
    }
}

/// Index of the bracket closing the `(`, `[` or `{` at `open`.
pub fn matching_close(toks: &[Token], open: usize) -> Option<usize> {
    let (o, c) = match toks.get(open)?.tok {
        Tok::Punct(b'(') => (b'(', b')'),
        Tok::Punct(b'[') => (b'[', b']'),
        Tok::Punct(b'{') => (b'{', b'}'),
        _ => return None,
    };
    let mut depth = 0usize;
    for (i, t) in toks.iter().enumerate().skip(open) {
        match t.tok {
            Tok::Punct(p) if p == o => depth += 1,
            Tok::Punct(p) if p == c => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Every `name {` block at any depth: `(open index, close index)` of the
/// braces.
pub fn all_blocks(toks: &[Token], name: &str) -> Vec<(usize, usize)> {
    (0..toks.len())
        .filter(|&i| is_ident(toks.get(i), name) && is_punct(toks.get(i + 1), b'{'))
        .filter_map(|i| matching_close(toks, i + 1).map(|c| (i + 1, c)))
        .collect()
}

/// The string values (literal or not) in `toks`.
pub fn strings(toks: &[Token]) -> impl Iterator<Item = &str> {
    toks.iter().filter_map(|t| match &t.tok {
        Tok::Str { value, .. } => Some(value.as_str()),
        _ => None,
    })
}

/// Whether a line break separates tokens `a` and `b` (`a` before `b`).
pub fn newline_between(text: &str, toks: &[Token], a: usize, b: usize) -> bool {
    match (toks.get(a), toks.get(b)) {
        (Some(x), Some(y)) if x.end <= y.start => text[x.end..y.start].contains('\n'),
        _ => false,
    }
}

// ── calls ───────────────────────────────────────────────────────────────────────

/// One argument of a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallArg {
    /// The name of a named argument (Groovy `group: 'g'`, Kotlin
    /// `group = "g"`).
    pub name: Option<String>,
    /// The value when it is exactly one literal string.
    pub literal: Option<String>,
    /// The value's token range `[first, last)`.
    pub first: usize,
    pub last: usize,
}

/// One call of a named method: `f(a, b)`, `f(a) { … }`, Groovy's
/// parenthesis-free `f a, b` and a closure-only `f { … }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSite {
    /// Token index of the callee name.
    pub callee: usize,
    /// The identifier before a `.` / `?.` in front of the callee
    /// (`settings.include` → `settings`); `Some("")` when the receiver is
    /// an expression (`project(':a').include`).
    pub receiver: Option<String>,
    /// 1-based line of the callee.
    pub line: usize,
    pub args: Vec<CallArg>,
    /// Token range `(open, close)` of a trailing closure.
    pub closure: Option<(usize, usize)>,
    /// Token index one past the call (closure included).
    pub end: usize,
}

impl CallSite {
    /// Every argument's literal value, or `None` when any argument is not a
    /// literal string (or the call has none).
    pub fn literals(&self) -> Option<Vec<String>> {
        if self.args.is_empty() {
            return None;
        }
        self.args.iter().map(|a| a.literal.clone()).collect()
    }

    /// The literal value of the named argument `name`; `Some(None)` when
    /// it is present but not a literal.
    pub fn named(&self, name: &str) -> Option<Option<&str>> {
        self.args
            .iter()
            .find(|a| a.name.as_deref() == Some(name))
            .map(|a| a.literal.as_deref())
    }
}

/// Every call of `callee` in `text`.
pub fn literal_strings_in_call(text: &str, dsl: Dsl, callee: &str) -> Vec<CallSite> {
    call_sites(text, &tokens(text, dsl), callee)
}

/// Every call of `callee` among `toks` (the tokens of `text`).
pub fn call_sites(text: &str, toks: &[Token], callee: &str) -> Vec<CallSite> {
    (0..toks.len())
        .filter(|&i| is_ident(toks.get(i), callee))
        .filter_map(|i| call_at(text, toks, i))
        .collect()
}

/// The call whose callee is token `i`, if `i` is called at all.
pub fn call_at(text: &str, toks: &[Token], i: usize) -> Option<CallSite> {
    let prev = |k: usize| i.checked_sub(k).and_then(|p| toks.get(p));
    // A named-argument key or a declaration (`fun include(`) is no call.
    if is_ident(prev(1), "fun") || is_ident(prev(1), "def") {
        return None;
    }
    let receiver = if is_punct(prev(1), b'.') {
        let recv = if is_punct(prev(2), b'?') {
            prev(3)
        } else {
            prev(2)
        };
        Some(match recv {
            Some(Token {
                tok: Tok::Ident(n), ..
            }) => n.clone(),
            _ => String::new(),
        })
    } else {
        None
    };
    let line = super::line_of(text, toks[i].start);
    let next = toks.get(i + 1)?;
    let (args, mut end) = match next.tok {
        Tok::Punct(b'(') => {
            let close = matching_close(toks, i + 1)?;
            (split_args(toks, i + 2, close), close + 1)
        }
        Tok::Punct(b'{') => (Vec::new(), i + 1),
        Tok::Punct(_) => return None,
        _ if newline_between(text, toks, i, i + 1) => return None,
        _ => {
            let end = command_end(text, toks, i + 1);
            (split_args(toks, i + 1, end), end)
        }
    };
    let closure = if is_punct(toks.get(end), b'{') {
        let close = matching_close(toks, end)?;
        let c = (end, close);
        end = close + 1;
        Some(c)
    } else {
        None
    };
    Some(CallSite {
        callee: i,
        receiver,
        line,
        args,
        closure,
        end,
    })
}

/// The end (token index) of a Groovy command expression's argument list,
/// or of an assignment's right-hand side, starting at `from`: a line
/// break, `;` or an unmatched closer at bracket depth 0 (a trailing `,`
/// continues the list on the next line), or a `{` at depth 0 (a trailing
/// closure).
pub fn command_end(text: &str, toks: &[Token], from: usize) -> usize {
    let mut depth = 0isize;
    let mut i = from;
    while i < toks.len() {
        match toks[i].tok {
            Tok::Punct(b'(' | b'[') => depth += 1,
            Tok::Punct(b'{') if depth > 0 => depth += 1,
            // A `{` at depth 0 is a trailing closure.
            Tok::Punct(b'{') => return i,
            Tok::Punct(b')' | b']' | b'}') => {
                if depth == 0 {
                    return i;
                }
                depth -= 1;
            }
            Tok::Punct(b';') if depth == 0 => return i,
            _ => {}
        }
        if depth == 0
            && i > from
            && newline_between(text, toks, i - 1, i)
            && !is_punct(toks.get(i - 1), b',')
        {
            return i;
        }
        i += 1;
    }
    i
}

/// Split `toks[from..to]` at depth-0 commas.
fn split_args(toks: &[Token], from: usize, to: usize) -> Vec<CallArg> {
    let mut out = Vec::new();
    if from >= to {
        return out;
    }
    let mut depth = 0isize;
    let mut start = from;
    for i in from..=to {
        let at_end = i == to;
        if !at_end {
            match toks[i].tok {
                Tok::Punct(b'(' | b'[' | b'{') => depth += 1,
                Tok::Punct(b')' | b']' | b'}') => depth -= 1,
                _ => {}
            }
        }
        if at_end || (depth == 0 && is_punct(toks.get(i), b',')) {
            if i > start {
                out.push(make_arg(toks, start, i));
            }
            start = i + 1;
        }
    }
    out
}

fn make_arg(toks: &[Token], first: usize, last: usize) -> CallArg {
    let key = match &toks[first].tok {
        Tok::Ident(n) => Some(n.clone()),
        Tok::Str {
            value,
            literal: true,
        } => Some(value.clone()),
        _ => None,
    };
    let named = key.is_some()
        && (is_punct(toks.get(first + 1), b':')
            || (is_punct(toks.get(first + 1), b'=') && !is_punct(toks.get(first + 2), b'=')));
    let (name, vfirst) = if named {
        (key, first + 2)
    } else {
        (None, first)
    };
    let literal = (last == vfirst + 1)
        .then(|| literal_of(toks.get(vfirst)).map(str::to_string))
        .flatten();
    CallArg {
        name,
        literal,
        first: vfirst,
        last,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A compact rendering of the tokens: `I:name`, `S:value` (literal),
    /// `s:value` (not literal), `N:digits`, `P:c`.
    fn render(text: &str, dsl: Dsl) -> Vec<String> {
        tokens(text, dsl)
            .into_iter()
            .map(|t| match t.tok {
                Tok::Ident(n) => format!("I:{n}"),
                Tok::Str {
                    value,
                    literal: true,
                } => format!("S:{value}"),
                Tok::Str { value, .. } => format!("s:{value}"),
                Tok::Num(n) => format!("N:{n}"),
                Tok::Punct(c) => format!("P:{}", c as char),
            })
            .collect()
    }

    #[test]
    fn groovy_golden_tokens() {
        let table: &[(&str, &[&str])] = &[
            ("include ':a'", &["I:include", "S::a"]),
            ("x \"a$b\"", &["I:x", "s:a$b"]),
            ("x \"a${b.c('}')}d\"", &["I:x", "s:a${b.c('}')}d"]),
            ("x \"a\\$b\"", &["I:x", "S:a$b"]),
            ("x 'a$b'", &["I:x", "S:a$b"]),
            ("x '''a\n'b'\n'''", &["I:x", "S:a\n'b'\n"]),
            ("x \"\"\"a\n$b\"\"\"", &["I:x", "s:a\n$b"]),
            ("x 'it\\'s'", &["I:x", "S:it's"]),
            ("x '\\u0041\\n'", &["I:x", "S:A\n"]),
            ("x '\\q'", &["I:x", "s:\\q"]),
            ("// 'no'\nx /* 'no' */ y", &["I:x", "I:y"]),
            ("a /* /* */ b", &["I:a", "I:b"]),
            ("v = 1.10", &["I:v", "P:=", "N:1", "P:.", "N:10"]),
            ("#!/usr/bin/env groovy\nx", &["I:x"]),
            ("x 'unterminated\ny", &["I:x", "s:unterminated", "I:y"]),
            ("x \"a\" + \"b\"", &["I:x", "S:a", "P:+", "S:b"]),
        ];
        for (src, want) in table {
            assert_eq!(render(src, Dsl::Groovy), *want, "{src:?}");
        }
    }

    #[test]
    fn kotlin_golden_tokens() {
        let table: &[(&str, &[&str])] = &[
            ("include(\":a\")", &["I:include", "P:(", "S::a", "P:)"]),
            ("x(\"a$b\")", &["I:x", "P:(", "s:a$b", "P:)"]),
            ("x(\"a${'$'}b\")", &["I:x", "P:(", "s:a${'$'}b", "P:)"]),
            ("x(\"a$\")", &["I:x", "P:(", "S:a$", "P:)"]),
            ("x(\"a\\$b\")", &["I:x", "P:(", "S:a$b", "P:)"]),
            ("x(\"\"\"a\\nb\"\"\")", &["I:x", "P:(", "S:a\\nb", "P:)"]),
            ("x(\"\"\"a$b\"\"\")", &["I:x", "P:(", "s:a$b", "P:)"]),
            ("x(\"\"\"q\"\"\"\")", &["I:x", "P:(", "S:q\"", "P:)"]),
            ("x('c')", &["I:x", "P:(", "S:c", "P:)"]),
            ("a /* x /* y */ z */ b", &["I:a", "I:b"]),
            (
                "`my-conf`(\"g:a:1\")",
                &["I:my-conf", "P:(", "S:g:a:1", "P:)"],
            ),
            ("val é = 1", &["I:val", "I:é", "P:=", "N:1"]),
        ];
        for (src, want) in table {
            assert_eq!(render(src, Dsl::Kotlin), *want, "{src:?}");
        }
    }

    #[test]
    fn gstring_interpolation_is_non_literal_but_escaped_dollar_is() {
        let toks = tokens("apply from: \"$rootDir/x.gradle\"", Dsl::Groovy);
        assert!(
            matches!(&toks[3].tok, Tok::Str { literal: false, value } if value == "$rootDir/x.gradle")
        );
        let toks = tokens("apply from: \"\\$rootDir/x.gradle\"", Dsl::Groovy);
        assert_eq!(literal_of(toks.get(3)), Some("$rootDir/x.gradle"));
    }

    #[test]
    fn bom_is_skipped() {
        let src = "\u{feff}include ':a'\n";
        assert_eq!(render(src, Dsl::Groovy), ["I:include", "S::a"]);
        assert_eq!(
            decode(b"\xef\xbb\xbfinclude ':a'").as_deref(),
            Some("include ':a'")
        );
        assert_eq!(decode(b"include '\xff'"), None);
        let calls = literal_strings_in_call(src, Dsl::Groovy, "include");
        assert_eq!(calls[0].literals(), Some(vec![":a".to_string()]));
        assert_eq!(calls[0].line, 1);
    }

    #[test]
    fn well_formed_detects_unclosed() {
        assert!(well_formed("a { b(c) [d] }", Dsl::Groovy));
        assert!(!well_formed("a { b(c) ", Dsl::Groovy));
        assert!(!well_formed("a ) (", Dsl::Groovy));
        assert!(!well_formed("x 'open", Dsl::Groovy));
        assert!(!well_formed("x /* open", Dsl::Kotlin));
        assert!(!well_formed("x \"\"\"open", Dsl::Kotlin));
    }

    #[test]
    fn dsl_of_by_extension() {
        assert_eq!(dsl_of("a/settings.gradle"), Some(Dsl::Groovy));
        assert_eq!(dsl_of("build.gradle.kts"), Some(Dsl::Kotlin));
        assert_eq!(dsl_of("init.d/x.init.kts"), Some(Dsl::Kotlin));
        assert_eq!(dsl_of("pom.xml"), None);
    }

    #[test]
    fn call_forms() {
        let g = "include ':a', ':b'\nsettings.include(':c')\ninclude \"$x\"\ninclude ':d',\n  ':e'\nfoo.include ':f'\n";
        let calls = literal_strings_in_call(g, Dsl::Groovy, "include");
        let lits: Vec<_> = calls.iter().map(CallSite::literals).collect();
        assert_eq!(
            lits,
            vec![
                Some(vec![":a".into(), ":b".into()]),
                Some(vec![":c".into()]),
                None,
                Some(vec![":d".into(), ":e".into()]),
                Some(vec![":f".into()]),
            ]
        );
        assert_eq!(calls[1].receiver.as_deref(), Some("settings"));
        assert_eq!(calls[4].receiver.as_deref(), Some("foo"));
        assert_eq!(calls[3].line, 4);

        let k = "include(listOf(\"x\"))\ninclude(\":a\", \":b\")\n";
        let calls = literal_strings_in_call(k, Dsl::Kotlin, "include");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].literals(), None);
        assert_eq!(calls[0].args.len(), 1);
        assert_eq!(calls[1].literals().map(|v| v.len()), Some(2));
    }

    #[test]
    fn named_args_and_closures() {
        let g = "implementation group: 'g', name: 'a', version: \"$v\"\n";
        let c = &literal_strings_in_call(g, Dsl::Groovy, "implementation")[0];
        assert_eq!(c.named("group"), Some(Some("g")));
        assert_eq!(c.named("name"), Some(Some("a")));
        assert_eq!(c.named("version"), Some(None));
        assert_eq!(c.named("classifier"), None);

        let k = "implementation(group = \"g\", name = \"a\") { isTransitive = false }\nx == y\n";
        let toks = tokens(k, Dsl::Kotlin);
        let c = &call_sites(k, &toks, "implementation")[0];
        assert_eq!(c.named("group"), Some(Some("g")));
        let (open, close) = c.closure.expect("closure");
        assert!(is_punct(toks.get(open), b'{') && is_punct(toks.get(close), b'}'));

        // A property assignment is not a call.
        let g = "classifier = 'tests'\nversion 'x'\n";
        assert!(literal_strings_in_call(g, Dsl::Groovy, "classifier").is_empty());
        assert_eq!(literal_strings_in_call(g, Dsl::Groovy, "version").len(), 1);
    }
}
