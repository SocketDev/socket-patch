//! A reader of the Starlark in Bazel workspace files: `MODULE.bazel` and
//! the files it includes today, `WORKSPACE` and the `.bzl` files it loads
//! next.
//!
//! [`index`] lists every call of a file with its arguments, every name a
//! statement binds, and every other place a name stands for its value.
//! Nothing is evaluated. An argument is a literal that can be stated
//! outright (a string, a list or a dict of strings, a bare name) or it is
//! [`Value::Other`], and a name means what the last statement before it
//! bound it to. That is how a `MODULE.bazel` and a `WORKSPACE` file run:
//! Bazel allows no `if`, `for` or `def` statement and no `lambda` in them
//! (`DotBazelFileSyntaxChecker`, the same at 7.7.2, 8.8.2 and 9.3.2).
//!
//! A `.bzl` file has all of them. Its calls, bindings and uses are listed
//! the same way, but [`Call::bind`], [`Use::bind`] and [`Call::whole`] do
//! not hold there: an assignment inside one function rebinds the name
//! for the rest of the file, and a call in an `if` or a `for` block is
//! whole. A reader of such a file has to tell the functions apart first.
//!
//! It takes bytes and panics on none. Every step consumes a byte or a
//! token, nothing recurses, the literal of an argument is given up at its
//! first token that is not part of one, and a name that is bound again
//! shares what it stands for, so time and memory grow with the size of the
//! file, which [`MAX_BYTES`] bounds. The tests hold that for the shapes
//! they name. Bytes that are not UTF-8 are content in a comment or a
//! string, as they are for Bazel; a string that holds them has no value.
//!
//! A file is refused ([`Unreadable`]) for what Bazel refuses it for too: a
//! string or a bracket that is never closed, a bracket closed by another
//! kind. Other text Bazel rejects (`$`, a tab as indentation) becomes
//! tokens: Bazel builds nothing from such a file, so no reading of it is
//! acted on.

use std::collections::HashMap;
use std::ops::Range;
use std::sync::Arc;

/// The largest file that is read. The largest of 17,842 workspace and
/// `.bzl` files of the rulesets and the Bazel Central Registry is 0.6 MiB.
pub const MAX_BYTES: usize = 1 << 20;

/// Why a file is not read, and the line the reason is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unreadable {
    pub line: usize,
    pub why: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// An identifier or a keyword.
    Name,
    /// A string literal in any form: either quote, tripled or not, with an
    /// `r` before it or not. [`value`] decodes it.
    Str,
    Number,
    /// `(`, `[` or `{`.
    Open,
    /// `)`, `]` or `}`.
    Close,
    /// An operator or punctuation, the longest one that matches.
    Op,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Token {
    kind: Kind,
    /// The bytes `start..end` of the file.
    start: usize,
    end: usize,
    /// The line it starts on, from 1.
    line: usize,
    /// The first token of a line, outside every bracket: where a statement
    /// starts. A line joined to the one before by a backslash is no line.
    first: bool,
    /// For a bracket, the index of the token that closes or opens it.
    mate: usize,
}

/// The operators longer than a byte, longest first.
const LONG_OPS: [&[u8]; 20] = [
    b"//=", b"<<=", b">>=", b"**", b"==", b"!=", b"<=", b">=", b"+=", b"-=", b"*=", b"/=", b"%=",
    b"&=", b"|=", b"^=", b"//", b"<<", b">>", b"->",
];

/// A byte of a name.
fn word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The tokens of a file. Blanks, comments, line ends and the backslash
/// that joins two lines are not tokens.
fn tokens(src: &[u8]) -> Result<Vec<Token>, Unreadable> {
    let fail = |line, why| Err(Unreadable { line, why });
    if src.len() > MAX_BYTES {
        return fail(1, "it is larger than 1 MiB");
    }
    let mut out: Vec<Token> = Vec::new();
    // The brackets that are open: the index of each in `out`, and the byte
    // that closes it.
    let mut open: Vec<(usize, u8)> = Vec::new();
    let (mut start, mut line, mut first) = (0, 1, true);
    while let Some(&c) = src.get(start) {
        let rest = &src[start..];
        let run = |part: fn(u8) -> bool| rest.iter().take_while(|b| part(**b)).count();
        let (kind, len) = match c {
            b' ' | b'\t' | b'\r' | b'\n' => (None, Some(1)),
            b'\\' if rest.starts_with(b"\\\n") => (None, Some(2)),
            b'\\' if rest.starts_with(b"\\\r\n") => (None, Some(3)),
            b'#' => (None, Some(run(|b| b != b'\n'))),
            b'"' | b'\'' => (Some(Kind::Str), string(rest)),
            b'r' if matches!(rest.get(1), Some(b'"' | b'\'')) => {
                (Some(Kind::Str), string(&rest[1..]).map(|len| len + 1))
            }
            b'0'..=b'9' => (Some(Kind::Number), Some(number(rest))),
            b'A'..=b'Z' | b'a'..=b'z' | b'_' => (Some(Kind::Name), Some(run(word))),
            b'(' | b'[' | b'{' => (Some(Kind::Open), Some(1)),
            b')' | b']' | b'}' => (Some(Kind::Close), Some(1)),
            _ => {
                let long = LONG_OPS.iter().find(|op| rest.starts_with(op));
                (Some(Kind::Op), Some(long.map_or(1, |op| op.len())))
            }
        };
        let Some(end) = len.map(|len| start + len) else {
            return fail(line, "a string is never closed");
        };
        if let Some(kind) = kind {
            let (mut mate, outside) = (0, open.is_empty());
            if kind == Kind::Open {
                // `)` follows `(` in ASCII; `]` and `}` are two after theirs.
                open.push((out.len(), c + 1 + u8::from(c != b'(')));
            } else if kind == Kind::Close {
                let Some((opener, _)) = open.pop().filter(|(_, closer)| *closer == c) else {
                    return fail(line, "a bracket closes one that is not open");
                };
                (mate, out[opener].mate) = (opener, out.len());
            }
            let first = std::mem::take(&mut first) && outside;
            out.push(Token {
                kind,
                start,
                end,
                line,
                first,
                mate,
            });
        }
        // A line end, alone or after a backslash, and those in a string.
        line += src[start..end].iter().filter(|b| **b == b'\n').count();
        (start, first) = (end, first || c == b'\n');
    }
    match open.last() {
        Some(&(opener, _)) => fail(out[opener].line, "a bracket is never closed"),
        None => Ok(out),
    }
}

/// The length of the number that `s` starts with, as Bazel's lexer scans
/// it (`Lexer.scanNumberOrDot`, the same rule at 7.7.2, 8.8.2 and 9.3.2):
/// `0x`, `0o` or `0b` and their digits, or digits, a fraction and an
/// exponent. A word right after it is a token of its own: the `for` of
/// `0for`.
fn number(s: &[u8]) -> usize {
    let run =
        |at: usize, part: fn(&u8) -> bool| at + s[at..].iter().take_while(|b| part(b)).count();
    let digits = |at| run(at, u8::is_ascii_digit);
    match s.get(1).filter(|_| s[0] == b'0') {
        Some(b'x' | b'X') => return run(2, u8::is_ascii_hexdigit),
        Some(b'b' | b'B') => return run(2, |b| matches!(b, b'0' | b'1')),
        Some(b'o' | b'O') => return digits(2),
        _ => {}
    }
    let mut at = digits(0);
    if s.get(at) == Some(&b'.') {
        at = digits(at + 1);
    }
    if matches!(s.get(at), Some(b'e' | b'E')) {
        at = digits(at + 1 + usize::from(matches!(s.get(at + 1), Some(b'+' | b'-'))));
    }
    at
}

/// The length of the string literal whose opening quote is `s[0]`, or
/// `None` when it is never closed. A backslash keeps the byte after it (a
/// whole CRLF) out of the search for the end, in a raw string too, as in
/// Bazel's lexer.
fn string(s: &[u8]) -> Option<usize> {
    let quote = s[0];
    let triple = s[1..].starts_with(&[quote, quote]);
    let mut at = if triple { 3 } else { 1 };
    loop {
        match *s.get(at)? {
            b'\\' => at += 2 + usize::from(s[at + 1..].starts_with(b"\r\n")),
            b'\n' if !triple => return None,
            c if c == quote && (!triple || s[at + 1..].starts_with(&[quote, quote])) => {
                return Some(at + if triple { 3 } else { 1 });
            }
            _ => at += 1,
        }
    }
}

/// The value of a string token, decoded as Bazel's lexer decodes it
/// (`Lexer.escapedStringLiteral`, the same at 7.7.2, 8.8.2 and 9.3.2).
/// `None` for an escape Bazel rejects (`\x41`, `\N{DASH}`, `\q`, an octal
/// one above `\377`), for bytes that are not UTF-8, and for a token that
/// is no string.
fn value(src: &[u8], token: &Token) -> Option<String> {
    let text = src.get(token.start..token.end)?;
    let raw = text.first() == Some(&b'r');
    let text = text.get(usize::from(raw)..)?;
    let quotes = 1 + 2 * usize::from(text.len() >= 6 && text[1..3] == [text[0], text[0]]);
    let inside = quotes..text.len().checked_sub(quotes)?;
    let body = text.get(inside).filter(|_| token.kind == Kind::Str)?;
    let mut out = Vec::with_capacity(body.len());
    let mut at = 0;
    while let Some(&c) = body.get(at) {
        at += 1;
        if c != b'\\' {
            out.push(c);
            continue;
        }
        let next = *body.get(at)?;
        at += 1;
        let octal = body[at..]
            .iter()
            .take(2)
            .take_while(|b| (b'0'..=b'7').contains(b));
        match next {
            // A line end after a backslash: a line feed in a raw string,
            // nothing in any other.
            b'\r' | b'\n' => {
                at += usize::from(next == b'\r' && body.get(at) == Some(&b'\n'));
                out.extend(&b"\\\n"[..2 * usize::from(raw)]);
            }
            _ if raw => out.extend([b'\\', next]),
            b'0'..=b'7' => {
                let digits = octal.count();
                let digits = &body[at - 1..at + digits];
                at += digits.len() - 1;
                let byte = digits
                    .iter()
                    .fold(0, |byte, digit| byte * 8 + u32::from(digit - b'0'));
                out.push(u8::try_from(byte).ok()?);
            }
            _ => {
                let mut escapes = b"n\nr\rt\ta\x07b\x08f\x0cv\x0b\\\\''\"\"".chunks(2);
                out.push(escapes.find(|escape| escape[0] == next)?[1]);
            }
        }
    }
    String::from_utf8(out).ok()
}

/// What an argument is, when it can be stated without running anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// One string literal, decoded.
    Str(String),
    /// A list display of string literals.
    List(Vec<String>),
    /// A dict display from string literals to [`Value::Str`] or
    /// [`Value::List`], in the order written.
    Dict(Vec<(String, Value)>),
    /// One bare name: `True`, `None`, a constant, a loop variable. There
    /// is no class for a Bool: `True` is the name, and means Bazel's `True`
    /// only in a file that gives the name no other value.
    Name(String),
    /// Any other expression: a concatenation, a call, `select()`, a
    /// comprehension, a number, a string Bazel does not take.
    Other,
}

/// How an argument is passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum How {
    Positional,
    /// `name = value`.
    Keyword(String),
    /// `*value`.
    Star,
    /// `**value`.
    StarStar,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arg {
    pub how: How,
    pub value: Value,
    /// The bytes of the argument, with its keyword or stars.
    pub span: Range<usize>,
}

/// A call `name(...)` or `a.b(...)`. A call on a computed value
/// (`f(x).g()`, `"{}".format(x)`) is not one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Call {
    /// The callee as written, its parts joined by dots: `pip.parse`.
    pub callee: String,
    /// What the first name of the callee is bound to here: an index into
    /// [`File::binds`]. `None` for a name no statement before it has bound,
    /// which is what a name Bazel predeclares is.
    pub bind: Option<usize>,
    /// The line of the callee, from 1.
    pub line: usize,
    /// The bytes from the callee to the closing parenthesis.
    pub span: Range<usize>,
    pub args: Vec<Arg>,
    /// The call is a statement of its own, or the whole right side of an
    /// assignment. Only this says that the call runs, and runs once: any
    /// other call may stand behind an `and`, in a conditional or in a
    /// comprehension that has no item.
    pub whole: bool,
    /// It is inside the parentheses of another call.
    pub in_call: bool,
    /// It is inside the brackets of a comprehension: it may run once per
    /// item, or not at all.
    pub in_comprehension: bool,
}

impl Call {
    /// The value passed for the keyword `name`. `None` also when the call
    /// passes it in a `**` dict: ask [`Self::unpacks`] before taking the
    /// keyword for absent.
    pub fn arg(&self, name: &str) -> Option<&Value> {
        let named = |arg: &&Arg| matches!(&arg.how, How::Keyword(key) if key == name);
        self.args.iter().find(named).map(|arg| &arg.value)
    }

    /// The value of the positional argument `at`, from 0.
    pub fn positional(&self, at: usize) -> Option<&Value> {
        let arg = self.args.get(at).filter(|arg| arg.how == How::Positional);
        arg.map(|arg| &arg.value)
    }

    /// The call passes `*` or `**`: it has arguments that are not listed.
    pub fn unpacks(&self) -> bool {
        let stars = |arg: &Arg| matches!(arg.how, How::Star | How::StarStar);
        self.args.iter().any(stars)
    }
}

/// What a name is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bound {
    /// The result of a call, an index into [`File::calls`]: `x = f(...)`.
    /// `y = x` binds `y` to the same.
    Call(usize),
    /// A symbol of another file: the `load` call, an index into
    /// [`File::calls`], and the symbol's name there. `load(file, "f")`
    /// binds `f` to `f`, `load(file, g = "f")` binds `g` to `f`.
    Loaded(usize, Arc<str>),
    /// Anything else.
    Other,
}

/// A statement `name = ...`, or one symbol of a `load`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bind {
    pub name: String,
    pub line: usize,
    pub to: Bound,
}

/// A name where it is neither called nor bound by a statement `name =
/// ...`: an argument, an operand, an item of a list, an attribute read
/// without a call (`f = pip.parse`). The `y` of a statement `x = y` is
/// none when the file has bound `y`: `x` is then bound to the same.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Use {
    pub name: String,
    /// As [`Call::bind`].
    pub bind: Option<usize>,
    pub line: usize,
    /// The byte the name starts at.
    pub at: usize,
    /// The name may be given a value here instead of standing for one: it
    /// is between a `for` and its `in` (the variable of a comprehension),
    /// or before the `=` of its statement (`a, b = ...`). So are the `d`
    /// and the `k` of `d[k] = ...`, which are read: the mark is one too
    /// many there, never one too few.
    pub assigned: bool,
}

/// What a file says, as far as it can be read without running it. Each
/// list is in the order of the file.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct File {
    pub calls: Vec<Call>,
    pub binds: Vec<Bind>,
    pub uses: Vec<Use>,
}

/// Words of the language: never a callee, never a use.
const KEYWORDS: &[u8] = b"and break continue def elif else for if in lambda not or pass return";

/// An open bracket; the first one of the stack stands for the statement.
#[derive(Default)]
struct Frame {
    /// The call whose parenthesis this is.
    call: Option<usize>,
    /// The token the argument being read starts at.
    arg: usize,
    /// How many calls the file had when the bracket opened.
    before: usize,
    /// A `for` at this level: the bracket is a comprehension.
    comprehension: bool,
    /// A `for` at this level whose `in` has not come yet.
    looping: bool,
}

#[derive(Default)]
struct Reader<'a> {
    src: &'a [u8],
    tokens: Vec<Token>,
    file: File,
    /// The binding each name has at the token being read.
    env: HashMap<Vec<u8>, usize>,
    frames: Vec<Frame>,
    /// The first token of the statement being read.
    statement: usize,
    /// The call that starts the statement, or the right side of its
    /// assignment, and the token that closes it (0 while it is open).
    leading: Option<(usize, usize)>,
    /// The parenthesis the newest call of the file opens with.
    awaited: Option<usize>,
    /// How many brackets are between a `for` and its `in`: above none,
    /// the names being read may be variables of that `for`.
    looping: usize,
    /// How many uses the file had when the statement began, or at its
    /// last `=`: the ones since then stand before the next `=`.
    targets: usize,
    /// The ranges of [`File::calls`] that lie in a call and in a
    /// comprehension.
    inside: [Vec<Range<usize>>; 2],
}

/// The calls, bindings and uses of a file.
pub fn index(src: &[u8]) -> Result<File, Unreadable> {
    let (tokens, frames) = (tokens(src)?, vec![Frame::default()]);
    let mut reader = Reader {
        src,
        tokens,
        frames,
        ..Reader::default()
    };
    for at in 0..reader.tokens.len() {
        reader.token(at);
    }
    reader.end_statement(reader.tokens.len());
    // A call is inside when it lies in at least one of the ranges.
    for (flag, ranges) in reader.inside.iter().enumerate() {
        let mut depth = vec![0_i64; reader.file.calls.len() + 1];
        for range in ranges {
            depth[range.start] += 1;
            depth[range.end] -= 1;
        }
        let mut inside = 0;
        for (call, change) in reader.file.calls.iter_mut().zip(depth) {
            inside += change;
            let flags = [&mut call.in_call, &mut call.in_comprehension];
            *flags[flag] = inside > 0;
        }
    }
    Ok(reader.file)
}

impl<'a> Reader<'a> {
    fn text(&self, at: usize) -> &'a [u8] {
        let src = self.src;
        let token = self.tokens.get(at);
        token.map_or(&src[..0], |token| &src[token.start..token.end])
    }

    fn is(&self, at: usize, kind: Kind, text: &[u8]) -> bool {
        self.kind(at) == Some(kind) && self.text(at) == text
    }

    fn kind(&self, at: usize) -> Option<Kind> {
        self.tokens.get(at).map(|token| token.kind)
    }

    fn name(&self, at: usize) -> String {
        String::from_utf8_lossy(self.text(at)).into_owned()
    }

    fn token(&mut self, at: usize) {
        let (token, text) = (self.tokens[at], self.text(at));
        let (top, calls) = (self.frames.len() == 1, self.file.calls.len());
        if top && token.first {
            self.end_statement(at);
        }
        let Some(frame) = self.frames.last_mut() else {
            return;
        };
        match (token.kind, text) {
            (Kind::Name, _) => self.name_at(at),
            (Kind::Open, _) => {
                let call = (self.awaited.take() == Some(at)).then(|| calls - 1);
                self.frames.push(Frame {
                    call,
                    arg: at + 1,
                    before: calls,
                    ..Frame::default()
                });
            }
            (Kind::Close, _) if !top => self.close(at),
            // A comma ends an argument.
            (Kind::Op, b",") => {
                let from = std::mem::replace(&mut frame.arg, at + 1);
                let call = frame.call;
                self.argument(call, from, at);
            }
            // The names of a statement before its `=` may be given values.
            (Kind::Op, b"=") if top => {
                let targets = std::mem::replace(&mut self.targets, self.file.uses.len());
                for used in self.file.uses.iter_mut().skip(targets) {
                    used.assigned = true;
                }
            }
            (Kind::Op, b";") if top => {
                self.end_statement(at);
                self.statement = at + 1;
            }
            _ => {}
        }
    }

    /// The bracket that the token `at` closes: the calls since it opened
    /// are inside it.
    fn close(&mut self, at: usize) {
        let Some(frame) = self.frames.pop() else {
            return;
        };
        let within = frame.before..self.file.calls.len();
        self.inside[0].extend(frame.call.map(|_| within.clone()));
        self.inside[1].extend(frame.comprehension.then_some(within));
        self.argument(frame.call, frame.arg, at);
        if let Some(call) = frame.call {
            self.file.calls[call].span.end = self.tokens[at].end;
            let closed = |(leading, close)| (leading, if leading == call { at } else { close });
            self.leading = self.leading.map(closed);
        }
    }

    /// A name: an attribute, a word of the language, the head of a call,
    /// the name of a keyword argument, the target of an assignment, or a
    /// use.
    fn name_at(&mut self, at: usize) {
        let (token, text) = (self.tokens[at], self.text(at));
        let (top, calls) = (self.frames.len() == 1, self.file.calls.len());
        let after = |kind, text: &[u8]| at > 0 && self.is(at - 1, kind, text);
        let skipped = after(Kind::Op, b".") || after(Kind::Name, b"def");
        let Some(frame) = self.frames.last_mut().filter(|_| !skipped) else {
            return;
        };
        match text {
            b"for" => {
                frame.comprehension = !top;
                self.looping += usize::from(!std::mem::replace(&mut frame.looping, true));
            }
            b"in" => self.looping -= usize::from(std::mem::take(&mut frame.looping)),
            _ => {}
        }
        if KEYWORDS.split(|b| *b == b' ').any(|word| word == text) {
            return;
        }
        let target = if top {
            at == self.statement
        } else {
            frame.call.is_some() && frame.arg == at
        };
        let mut last = at;
        while self.is(last + 1, Kind::Op, b".") && self.kind(last + 2) == Some(Kind::Name) {
            last += 2;
        }
        let (bind, line) = (self.env.get(text).copied(), token.line);
        // A parenthesis that starts a line outside every bracket starts a
        // statement, as it does for Bazel: `f` and then `(x)` is no call.
        let opens = self.tokens.get(last + 1).is_some_and(|open| !open.first);
        if opens && self.is(last + 1, Kind::Open, b"(") {
            let parts: Vec<String> = (at..=last).step_by(2).map(|part| self.name(part)).collect();
            if top && at == self.statement + 2 * usize::from(self.assigns(self.statement)) {
                self.leading = Some((calls, 0));
            }
            self.awaited = Some(last + 1);
            self.file.calls.push(Call {
                callee: parts.join("."),
                bind,
                line,
                span: token.start..token.end,
                ..Call::default()
            });
        } else if !(target && self.is(at + 1, Kind::Op, b"=")) {
            self.file.uses.push(Use {
                name: self.name(at),
                bind,
                line,
                at: token.start,
                assigned: self.looping > 0,
            });
        }
    }

    /// The tokens from `at` on start with `name =`.
    fn assigns(&self, at: usize) -> bool {
        self.kind(at) == Some(Kind::Name) && self.is(at + 1, Kind::Op, b"=")
    }

    /// The argument `from..to` of `call`, when there is one.
    fn argument(&mut self, call: Option<usize>, from: usize, to: usize) {
        let Some(call) = call.filter(|_| from < to) else {
            return;
        };
        let span = self.tokens[from].start..self.tokens[to - 1].end;
        let (how, skip) = if self.is(from, Kind::Op, b"*") {
            (How::Star, 1)
        } else if self.is(from, Kind::Op, b"**") {
            (How::StarStar, 1)
        } else if self.assigns(from) {
            (How::Keyword(self.name(from)), 2)
        } else {
            (How::Positional, 0)
        };
        let value = self.value(from + skip, to);
        self.file.calls[call].args.push(Arg { how, value, span });
    }

    /// The literal the tokens `from..to` are, when they are one.
    fn value(&self, from: usize, to: usize) -> Value {
        let Some(first) = self.tokens.get(from).filter(|_| from < to) else {
            return Value::Other;
        };
        let display = first.kind == Kind::Open && first.mate + 1 == to;
        let literal = match first.kind {
            Kind::Str if from + 1 == to => value(self.src, first).map(Value::Str),
            Kind::Name if from + 1 == to => Some(Value::Name(self.name(from))),
            Kind::Open if display && self.text(from) == b"[" => self.list(from).map(Value::List),
            Kind::Open if display && self.text(from) == b"{" => self.dict(from).map(Value::Dict),
            _ => None,
        };
        literal.unwrap_or(Value::Other)
    }

    /// The token after `at` and after the comma that may stand there, in
    /// a display that closes at `close`: `None` when `at` is neither.
    fn next(&self, at: usize, close: usize) -> Option<usize> {
        let comma = self.is(at, Kind::Op, b",");
        (comma || at == close).then_some(at + usize::from(comma))
    }

    /// The strings of the list display that opens at the token `open`.
    fn list(&self, open: usize) -> Option<Vec<String>> {
        let close = self.tokens[open].mate;
        let (mut items, mut at) = (Vec::new(), open + 1);
        while at < close {
            items.push(value(self.src, self.tokens.get(at)?)?);
            at = self.next(at + 1, close)?;
        }
        Some(items)
    }

    /// The entries of the dict display that opens at the token `open`: a
    /// string, a colon, and a string or a list of strings.
    fn dict(&self, open: usize) -> Option<Vec<(String, Value)>> {
        let close = self.tokens[open].mate;
        let (mut items, mut at) = (Vec::new(), open + 1);
        while at < close {
            let key = value(self.src, self.tokens.get(at)?)?;
            let item = self.tokens.get(at + 2)?;
            let (value, end) = match self.text(at + 2) {
                _ if !self.is(at + 1, Kind::Op, b":") => return None,
                b"[" => (Value::List(self.list(at + 2)?), item.mate),
                _ => (Value::Str(value(self.src, item)?), at + 2),
            };
            items.push((key, value));
            at = self.next(end + 1, close)?;
        }
        Some(items)
    }

    /// The statement that started at `self.statement` ends before the
    /// token `end`: note what it binds, and start the next one there.
    fn end_statement(&mut self, end: usize) {
        let start = std::mem::replace(&mut self.statement, end);
        let whole = self.leading.take().filter(|(_, close)| close + 1 == end);
        let call = whole.map(|(call, _)| call);
        if let Some(call) = call {
            self.file.calls[call].whole = true;
        }
        let line = self.tokens.get(start).map_or(0, |token| token.line);
        if start + 2 < end && self.assigns(start) {
            // `x = y` binds `x` to what `y` is bound to, and is no use of `y`.
            let alias = self.tokens[start + 2];
            let aliased = self.env.get(self.text(start + 2)).copied();
            let aliased = aliased.filter(|_| start + 3 == end && alias.kind == Kind::Name);
            let to = match (call, aliased) {
                (Some(call), _) => Bound::Call(call),
                (None, Some(aliased)) => {
                    self.file.uses.pop_if(|used| used.at == alias.start);
                    self.file.binds[aliased].to.clone()
                }
                (None, None) => Bound::Other,
            };
            self.bind(self.name(start), line, to);
        }
        // `load(file, "name", other = "name")` binds its symbols.
        let load = call.filter(|call| {
            let call = &self.file.calls[*call];
            call.callee == "load" && call.bind.is_none()
        });
        let symbols = load.map_or(Vec::new(), |load| self.file.calls[load].args.clone());
        for arg in symbols.into_iter().skip(1) {
            let (Some(load), Value::Str(symbol)) = (load, arg.value) else {
                continue;
            };
            let name = match arg.how {
                How::Positional => symbol.clone(),
                How::Keyword(name) => name,
                How::Star | How::StarStar => continue,
            };
            self.bind(name, line, Bound::Loaded(load, symbol.into()));
        }
        self.targets = self.file.uses.len();
    }

    fn bind(&mut self, name: String, line: usize, to: Bound) {
        let bind = self.file.binds.len();
        self.env.insert(name.clone().into_bytes(), bind);
        self.file.binds.push(Bind { name, line, to });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_rng::Rng;

    /// The tokens of `src`, each as its kind and its text; `^` marks the
    /// first token of a statement.
    fn spell(src: &str) -> String {
        let spell = |token: &Token| {
            let kind = match token.kind {
                Kind::Name => "n",
                Kind::Str => "s",
                Kind::Number => "d",
                Kind::Open | Kind::Close => "b",
                Kind::Op => "o",
            };
            let first = if token.first { "^" } else { "" };
            format!("{first}{kind}:{}", &src[token.start..token.end])
        };
        let tokens = tokens(src.as_bytes()).unwrap();
        tokens.iter().map(spell).collect::<Vec<_>>().join(" ")
    }

    fn read(src: &str) -> File {
        index(src.as_bytes()).unwrap()
    }

    /// The calls of `callee` in `file`.
    fn calls<'a>(file: &'a File, callee: &str) -> Vec<&'a Call> {
        let named = |call: &&Call| call.callee == callee;
        file.calls.iter().filter(named).collect()
    }

    fn string(value: &str) -> Value {
        Value::Str(value.to_string())
    }

    fn list(items: &[&str]) -> Value {
        Value::List(items.iter().map(|item| item.to_string()).collect())
    }

    #[test]
    fn every_token_form() {
        for (src, want) in [
            ("x = 1", "^n:x o:= d:1"),
            ("_a1 B_2 for", "^n:_a1 n:B_2 n:for"),
            (
                "0 12 0x1F 0XfF 0o17 0O7 0b101 0B1 08 1.5 0.5 1e3 1E-2 1e+5 1.5e-3",
                "^d:0 d:12 d:0x1F d:0XfF d:0o17 d:0O7 d:0b101 d:0B1 d:08 d:1.5 d:0.5 d:1e3 d:1E-2 \
                 d:1e+5 d:1.5e-3",
            ),
            // A number ends where Bazel's lexer ends it: a word right after
            // it is a word, but for an `e`, which is its exponent, and a
            // number that starts with a dot is a dot and a number.
            (
                "0for 1if 2else 3in 4or 5and 1_0 1.real",
                "^d:0 n:for d:1 n:if d:2e n:lse d:3 n:in d:4 n:or d:5 n:and d:1 n:_0 d:1. n:real",
            ),
            (
                "0xg 0b12 0x 1e 1.e3 0. .5 1..2",
                "^d:0x n:g d:0b1 d:2 d:0x d:1e d:1.e3 d:0. o:. d:5 d:1. o:. d:2",
            ),
            // Strings: both quotes, tripled, raw, empty, with the other
            // quote, an escaped quote or a `#` inside.
            (
                r#""a" 'b' """c""" '''d'''"#,
                r#"^s:"a" s:'b' s:"""c""" s:'''d'''"#,
            ),
            (
                r#"r"e\n" r'f' r"""g""" r'''h'''"#,
                r#"^s:r"e\n" s:r'f' s:r"""g""" s:r'''h'''"#,
            ),
            (r#""" '' """""" ''''''"#, r#"^s:"" s:'' s:"""""" s:''''''"#),
            (
                r#""it's" 'say "hi"' "a\"b" 'a\'b' "\\""#,
                r#"^s:"it's" s:'say "hi"' s:"a\"b" s:'a\'b' s:"\\""#,
            ),
            (
                r##""""a"b""c""" "#no comment""##,
                r##"^s:"""a"b""c""" s:"#no comment""##,
            ),
            ("\"\"\"a\nb\"\"\" c", "^s:\"\"\"a\nb\"\"\" n:c"),
            ("\"a\\\nb\" c", "^s:\"a\\\nb\" n:c"),
            ("r\"a\\\r\nb\" c", "^s:r\"a\\\r\nb\" n:c"),
            // Only a lower-case `r` right before the quote makes a prefix.
            (
                r#"R"x" br"y" rb"z" r "w""#,
                r#"^n:R s:"x" n:br s:"y" n:rb s:"z" n:r s:"w""#,
            ),
            // A comment ends with its line, whatever it holds.
            ("a # b ( \" '''\nc#d", "^n:a ^n:c"),
            (
                "f(a[1], {2: (3)})",
                "^n:f b:( n:a b:[ d:1 b:] o:, b:{ d:2 o:: b:( d:3 b:) b:} b:)",
            ),
            (
                "a == b != c <= d >= e += f -= g *= h /= i //= j %= k &= l |= m ^= n <<= o >>= p",
                "^n:a o:== n:b o:!= n:c o:<= n:d o:>= n:e o:+= n:f o:-= n:g o:*= n:h o:/= n:i \
                 o://= n:j o:%= n:k o:&= n:l o:|= n:m o:^= n:n o:<<= n:o o:>>= n:p",
            ),
            (
                "a ** b // c << d >> e -> f",
                "^n:a o:** n:b o:// n:c o:<< n:d o:>> n:e o:-> n:f",
            ),
            (
                "a=-1 b=*c d==e",
                "^n:a o:= o:- d:1 n:b o:= o:* n:c n:d o:== n:e",
            ),
            (
                "+ - * / % < > = , : ; . | & ^ ~",
                "^o:+ o:- o:* o:/ o:% o:< o:> o:= o:, o:: o:; o:. o:| o:& o:^ o:~",
            ),
            // A statement starts on a new line outside every bracket, and
            // not on a line that a backslash joins to the one before.
            (
                "f(\n  a,\n)\ng = \\\n  1\n\n# c\n  h",
                "^n:f b:( n:a o:, b:) ^n:g o:= d:1 ^n:h",
            ),
            ("a = \\\r\n 1\r\nb\rc", "^n:a o:= d:1 ^n:b n:c"),
        ] {
            assert_eq!(spell(src), want, "{src:?}");
        }
        // What Bazel rejects outside a string is a token a byte.
        let odd = tokens("$ ? ! @ ` \\ \u{e9}".as_bytes()).unwrap();
        assert_eq!(odd.len(), 8);
        assert!(odd.iter().all(|token| token.kind == Kind::Op));
    }

    #[test]
    fn tokens_know_their_line_and_brackets_their_mate() {
        let src = "a(\n  [b],\n  '''x\ny''', {\n})\nc \\\n  d";
        let tokens = tokens(src.as_bytes()).unwrap();
        let lines: Vec<usize> = tokens.iter().map(|token| token.line).collect();
        assert_eq!(lines, [1, 1, 2, 2, 2, 2, 3, 4, 4, 5, 5, 6, 7]);
        let mates: Vec<(usize, usize)> = (tokens.iter().enumerate())
            .filter(|(_, token)| token.kind == Kind::Open)
            .map(|(at, token)| (at, token.mate))
            .collect();
        assert_eq!(mates, [(1, 10), (2, 4), (8, 9)]);
        for (open, close) in mates {
            assert_eq!(tokens[close].mate, open);
        }
    }

    #[test]
    fn a_string_has_the_value_bazel_gives_it() {
        for (src, want) in [
            (&br#""abc""#[..], Some("abc")),
            (br#"'abc'"#, Some("abc")),
            (br#""""a"b""""#, Some("a\"b")),
            (br#"'''it's'''"#, Some("it's")),
            (br#""""#, Some("")),
            (br#""""""""#, Some("")),
            (b"\"\"\"a\nb\"\"\"", Some("a\nb")),
            (
                br#""a\nb\t\\\'\"\a\b\f\v\r""#,
                Some("a\nb\t\\'\"\x07\x08\x0c\x0b\r"),
            ),
            // Octal: one to three digits, at most \377; above 0o177 it is a
            // byte, and bytes must be UTF-8 to be a value.
            (br#""\101\60\0\1012""#, Some("A0\0A2")),
            (br#""\303\251""#, Some("\u{e9}")),
            (br#""\377""#, None),
            (br#""\400""#, None),
            // The escapes Bazel rejects.
            (br#""\x41""#, None),
            (br#""\u00e9""#, None),
            (br#""\N{DASH}""#, None),
            (br#""a\qb""#, None),
            // A backslash before a line end joins the lines.
            (b"\"a\\\nb\"", Some("ab")),
            (b"\"a\\\r\nb\"", Some("ab")),
            // A raw string keeps the backslash and what follows it.
            (br#"r"a\nb\"c\\""#, Some(r#"a\nb\"c\\"#)),
            (br#"r'''\d+'''"#, Some(r"\d+")),
            (b"r\"a\\\r\nb\"", Some("a\\\nb")),
            ("\"caf\u{e9}\"".as_bytes(), Some("caf\u{e9}")),
            (b"\"\xff\"", None),
            (b"name", None),
            (b"12", None),
        ] {
            let tokens = tokens(src).unwrap();
            assert_eq!(tokens.len(), 1, "{src:?}");
            assert_eq!(value(src, &tokens[0]).as_deref(), want, "{src:?}");
        }
        // A token that is not one of the file's is no string either.
        let stray = Token {
            kind: Kind::Str,
            start: 3,
            end: 2,
            line: 1,
            first: false,
            mate: 0,
        };
        assert_eq!(value(b"\"abc\"", &stray), None);
        assert_eq!(
            value(
                b"\"",
                &Token {
                    start: 0,
                    end: 1,
                    ..stray
                }
            ),
            None
        );
    }

    #[test]
    fn what_bazel_refuses_is_refused_with_its_line() {
        let large = vec![b' '; MAX_BYTES + 1];
        for (src, line, why) in [
            (&b"\n\"abc"[..], 2, "a string is never closed"),
            (b"x = \"a\nb\"", 1, "a string is never closed"),
            (b"'''abc''", 1, "a string is never closed"),
            (b"\"a\\", 1, "a string is never closed"),
            (b"r\"a\\\"", 1, "a string is never closed"),
            (b"\n\n)", 3, "a bracket closes one that is not open"),
            (b"f(]", 1, "a bracket closes one that is not open"),
            (b"{)}", 1, "a bracket closes one that is not open"),
            (b"a\nf(\n[1]\n", 2, "a bracket is never closed"),
            (&large[..], 1, "it is larger than 1 MiB"),
        ] {
            let want = Err(Unreadable { line, why });
            assert_eq!(tokens(src), want, "{:?}", &src[..src.len().min(20)]);
            assert_eq!(index(src).map(|_| ()), want.map(|_| ()));
        }
        // At the limit, and with a line of 5 MB above it.
        assert!(tokens(&large[1..]).is_ok());
        assert!(index(&vec![b'a'; 5 << 20]).is_err());
    }

    #[test]
    fn every_argument_class() {
        let file = read(
            r#"f(
    "s", ["a", "b",], [], name, True,
    one = "//:x",
    raw = r"a\b",
    many = ["a", "b"],
    table = {"k": "v", "l": ["x", "y"], "m": [],},
    none = {},
    flag = False,
    # Everything below is an expression: never a guess.
    joined = "p" + "q",
    adjacent = "p" "q",
    call = g("x"),
    label = Label("//:x"),
    chosen = select({"k": "v"}),
    made = "{}".format(v),
    old = "%s.txt" % v,
    comp = [x for x in y],
    keyed = {"//:" + os: "v" for os in ["a"]},
    number = 3,
    minus = -1,
    tuple = ("a", "b"),
    wrapped = ("a"),
    mixed = ["a", 1],
    nested = [["a"]],
    named = ["a", b],
    values = {"k": 1},
    keys = {k: "v"},
    deep = {"k": {"l": "v"}},
    listed = {"k": ["a", ["b"]]},
    unset = {"k": "v" "w"},
    bad = "\x41",
    if_else = "a" if c else "b",
    *rest,
    **more,
    **{"k": "v"}
)"#,
        );
        let call = &file.calls[0];
        let keyword = |name: &str| call.arg(name).unwrap_or_else(|| panic!("{name}"));
        assert_eq!(call.positional(0), Some(&string("s")));
        assert_eq!(call.positional(1), Some(&list(&["a", "b"])));
        assert_eq!(call.positional(2), Some(&list(&[])));
        assert_eq!(call.positional(3), Some(&Value::Name("name".into())));
        assert_eq!(call.positional(4), Some(&Value::Name("True".into())));
        assert_eq!(call.positional(5), None, "a keyword is no position");
        assert_eq!(keyword("one"), &string("//:x"));
        assert_eq!(keyword("raw"), &string(r"a\b"));
        assert_eq!(keyword("many"), &list(&["a", "b"]));
        let table = [
            ("k", string("v")),
            ("l", list(&["x", "y"])),
            ("m", list(&[])),
        ];
        let table = table.map(|(key, value)| (key.to_string(), value));
        assert_eq!(keyword("table"), &Value::Dict(table.to_vec()));
        assert_eq!(keyword("none"), &Value::Dict(Vec::new()));
        assert_eq!(keyword("flag"), &Value::Name("False".into()));
        for other in [
            "joined", "adjacent", "call", "label", "chosen", "made", "old", "comp", "keyed",
            "number", "minus", "tuple", "wrapped", "mixed", "nested", "named", "values", "keys",
            "deep", "listed", "unset", "bad", "if_else",
        ] {
            assert_eq!(keyword(other), &Value::Other, "{other}");
        }
        let stars: Vec<(&How, &Value)> = (call.args.iter())
            .filter(|arg| matches!(arg.how, How::Star | How::StarStar))
            .map(|arg| (&arg.how, &arg.value))
            .collect();
        let dict = Value::Dict(vec![("k".into(), string("v"))]);
        assert_eq!(
            stars,
            [
                (&How::Star, &Value::Name("rest".into())),
                (&How::StarStar, &Value::Name("more".into())),
                (&How::StarStar, &dict),
            ]
        );
        assert!(call.unpacks());
        assert!(!read("f(a, b = 1)").calls[0].unpacks());
        assert_eq!(call.args.len(), 5 + 29 + 3, "every argument is listed");
        assert_eq!(read("f()").calls[0].args, []);
        assert_eq!(read("f(a,)").calls[0].args.len(), 1);
    }

    #[test]
    fn a_call_has_its_line_and_its_bytes() {
        let src = "# one\nx = [\n    pip.parse(\n        a = 'b',  # c\n    ),\n]\n";
        let file = read(src);
        let call = &file.calls[0];
        assert_eq!((call.callee.as_str(), call.line), ("pip.parse", 3));
        assert_eq!(
            &src[call.span.clone()],
            "pip.parse(\n        a = 'b',  # c\n    )"
        );
        assert_eq!(&src[call.args[0].span.clone()], "a = 'b'");
    }

    #[test]
    fn the_callee_is_the_dotted_name_as_written() {
        let callees = |src: &str| -> Vec<String> {
            let file = read(src);
            file.calls.into_iter().map(|call| call.callee).collect()
        };
        assert_eq!(
            callees("a(1)\nb.c(2)\nd . e\\\n . f (3)"),
            ["a", "b.c", "d.e.f"]
        );
        // A call on a value that is computed is not one.
        assert_eq!(
            callees("f(x).g(y)\n'{}'.format(z)\nh[0].i()\nj()()"),
            ["f", "j"]
        );
        // Neither is a definition, nor a word of the language before `(`.
        let words = "def f(a, b = g()):\n    return (a)\nif (a) and (b) or not (c) in (d): pass\n\
                     for (x) in (y): pass\nz = lambda (w): w\nprint(1)\n";
        assert_eq!(callees(words), ["g", "print"]);
        assert_eq!(callees("load('//:a.bzl', 'b')"), ["load"]);
    }

    /// Bazel reads a name that ends a line and a parenthesis that starts
    /// the next one as two statements: any expression is a statement
    /// (`Parser.parseSmallStatement` at 7.7.2, 8.8.2 and 9.3.2).
    #[test]
    fn a_parenthesis_that_starts_a_line_starts_a_statement() {
        for src in [
            "f\n(1)\n",
            "f  # c\n(1)\n",
            "x = f\n(1)\n",
            "a.b\n(1)\n",
            "f;(1)\n",
        ] {
            assert_eq!(read(src).calls, [], "{src:?}");
        }
        // In a bracket and after a backslash the line goes on.
        for src in ["[f\n(1)]\n", "f \\\n(1)\n", "g(f\n(1))\n"] {
            assert_eq!(calls(&read(src), "f").len(), 1, "{src:?}");
        }
    }

    #[test]
    fn where_a_call_stands() {
        let file = read(
            "a(b(c()), [d()])\n\
             x = [e(v) for v in f(1)]\n\
             {g(): h() for k in l}\n\
             s(t = [m() for u in n()], w = aa())\n\
             bb()\n\
             [cc() and 0for dd in ee()]\n",
        );
        let stands = |callee: &str| {
            let call = calls(&file, callee)[0];
            (call.in_call, call.in_comprehension)
        };
        for (callee, want) in [
            ("a", (false, false)),
            ("b", (true, false)),
            ("c", (true, false)),
            ("d", (true, false)),
            ("e", (false, true)),
            ("f", (false, true)),
            ("g", (false, true)),
            ("h", (false, true)),
            ("s", (false, false)),
            ("m", (true, true)),
            ("n", (true, true)),
            ("aa", (true, false)),
            ("bb", (false, false)),
            // A `for` right after a number is the `for` of a comprehension.
            ("cc", (false, true)),
            ("ee", (false, true)),
        ] {
            assert_eq!(stands(callee), want, "{callee}");
        }
    }

    #[test]
    fn a_call_that_is_a_whole_statement_or_a_whole_right_side() {
        let file = read(
            "a()\nx = b()\nc() + 1\ny = d() if e else None\nf(); g()\nz = h(1)(2)\nw = i.j()\n\
             [k()]\nu, v = l()\nm(\n    n(),\n)\nt = \\\n    o()\n",
        );
        let whole: Vec<&str> = (file.calls.iter())
            .filter(|call| call.whole)
            .map(|call| call.callee.as_str())
            .collect();
        assert_eq!(whole, ["a", "b", "f", "g", "i.j", "m", "o"]);
    }

    #[test]
    fn a_name_means_what_the_last_statement_bound_it_to() {
        let file = read(
            "pip = use_extension('@rules_python//python/extensions:pip.bzl', 'pip')\n\
             alias = pip\n\
             other = 1\n\
             same = True\n\
             pip.parse(hub_name = 'a')\n\
             alias.parse(hub_name = 'b')\n\
             unbound.parse(hub_name = 'c')\n\
             pip = 'rebound'\n\
             pip.parse(hub_name = 'd')\n\
             again = pip\n",
        );
        let binds: Vec<(&str, usize, &Bound)> = (file.binds.iter())
            .map(|bind| (bind.name.as_str(), bind.line, &bind.to))
            .collect();
        assert_eq!(
            binds,
            [
                ("pip", 1, &Bound::Call(0)),
                // `alias = pip` binds `alias` to what `pip` is.
                ("alias", 2, &Bound::Call(0)),
                ("other", 3, &Bound::Other),
                // A name the file has not bound is no alias.
                ("same", 4, &Bound::Other),
                ("pip", 8, &Bound::Other),
                ("again", 10, &Bound::Other),
            ]
        );
        let bound: Vec<(&str, Option<usize>)> = (file.calls.iter())
            .map(|call| (call.callee.as_str(), call.bind))
            .collect();
        assert_eq!(
            bound,
            [
                ("use_extension", None),
                ("pip.parse", Some(0)),
                ("alias.parse", Some(1)),
                ("unbound.parse", None),
                ("pip.parse", Some(4)),
            ]
        );
        // The right side of an alias is not a use of the name; `True` is.
        let uses: Vec<&str> = file.uses.iter().map(|used| used.name.as_str()).collect();
        assert_eq!(uses, ["True"]);
    }

    #[test]
    fn load_binds_its_symbols() {
        let file = read(
            "load('@rules_python//python:pip.bzl', 'pip_parse', parse = 'pip_parse', bad = 1)\n\
             pip_parse(name = 'a')\n\
             parse(name = 'b')\n\
             f(load('//:x.bzl', 'inner'))\n\
             inner()\n\
             load = g\n\
             load('//:y.bzl', 'late')\n\
             late()\n",
        );
        let loaded = |symbol: &str| Bound::Loaded(0, symbol.into());
        let binds: Vec<(&str, &Bound)> = (file.binds.iter())
            .map(|bind| (bind.name.as_str(), &bind.to))
            .collect();
        assert_eq!(
            binds,
            [
                ("pip_parse", &loaded("pip_parse")),
                ("parse", &loaded("pip_parse")),
                // A `load` inside a call, and one after `load` was bound
                // to something else, bind nothing.
                ("load", &Bound::Other),
            ]
        );
        assert_eq!(
            file.calls[0].positional(0),
            Some(&string("@rules_python//python:pip.bzl"))
        );
        assert_eq!(calls(&file, "pip_parse")[0].bind, Some(0));
        assert_eq!(calls(&file, "parse")[0].bind, Some(1));
        assert_eq!(calls(&file, "inner")[0].bind, None);
        assert_eq!(calls(&file, "late")[0].bind, None);
    }

    /// The names bound to one loaded symbol hold its name once: a copy
    /// each would be the square of the file.
    #[test]
    fn the_names_of_one_loaded_symbol_share_it() {
        let (symbol, aliases) = ("s".repeat(32 << 10), "a=s\n".repeat(8 << 10));
        let src = format!("load('//:f.bzl', s = '{symbol}')\n{aliases}");
        let file = read(&src);
        assert_eq!(file.binds.len(), (8 << 10) + 1);
        let mut held = std::collections::BTreeMap::new();
        for bind in &file.binds {
            let Bound::Loaded(_, symbol) = &bind.to else {
                panic!("{:?}", bind.name);
            };
            held.insert(symbol.as_ptr(), symbol.len());
        }
        assert!(held.values().sum::<usize>() <= src.len());
    }

    #[test]
    fn every_use_of_a_name_but_calling_it_is_listed() {
        let file = read(
            "pip = use_extension('//:e.bzl', 'pip')\n\
             pip.parse()\n\
             use_repo(pip, 'hub')\n\
             use_repo(npm, pip = 'hub')\n\
             f(x = pip)\n\
             g = pip.parse\n\
             h = [pip]\n\
             pip += 1\n\
             a, pip = 1, 2\n\
             [pip.tag() for pip in x]\n\
             i(*pip)\n\
             j = pip if k else None\n",
        );
        let lines: Vec<usize> = (file.uses.iter())
            .filter(|used| used.name == "pip")
            .map(|used| {
                assert_eq!(used.bind, Some(0), "line {}", used.line);
                used.line
            })
            .collect();
        // Line 2 calls a tag on it, line 4 names a keyword argument.
        assert_eq!(lines, [3, 5, 6, 7, 8, 9, 10, 11, 12]);
        // The use on line 3 is where the first argument of the call is.
        let handed = &calls(&file, "use_repo")[0].args[0];
        assert_eq!(handed.value, Value::Name("pip".into()));
        assert_eq!(file.uses[0].at, handed.span.start);
    }

    #[test]
    fn a_name_that_may_be_given_a_value_is_marked() {
        let file = read(
            "a, b = c, d\n\
             (e) = f\n\
             [g, [h]] = i\n\
             x = [j(k) for l, (m, n) in o if p for q in r]\n\
             s = t\n\
             u(v = w)\n\
             y.z = aa; bb[cc] = dd\n\
             [ee and 0for ff in gg]\n\
             hh == ii\n\
             [jj for kk[ll in mm], nn in oo]\n\
             [pp for qq[[rr for ss in tt][0]], uu in vv if ww in xx]\n",
        );
        let assigned: Vec<&str> = (file.uses.iter())
            .filter(|used| used.assigned)
            .map(|used| used.name.as_str())
            .collect();
        // The targets of an assignment that is not `name = ...` and the
        // variables of a comprehension, also after an `in` or a whole
        // comprehension inside an item they index; `y`, `bb`, `cc` and
        // what stands in such an index are read, and marked all the same.
        assert_eq!(
            assigned,
            [
                "a", "b", "e", "g", "h", "l", "m", "n", "q", "y", "bb", "cc", "ff", "kk", "ll",
                "mm", "nn", "qq", "rr", "ss", "tt", "uu"
            ]
        );
        let read: Vec<&str> = (file.uses.iter())
            .filter(|used| !used.assigned)
            .map(|used| used.name.as_str())
            .collect();
        assert_eq!(
            read,
            [
                "c", "d", "f", "i", "k", "o", "p", "r", "t", "w", "aa", "dd", "ee", "gg", "hh",
                "ii", "jj", "oo", "pp", "vv", "ww", "xx"
            ]
        );
    }

    #[test]
    fn a_rule_named_in_a_comment_or_a_string_is_no_call() {
        let file = read(
            "# pip.parse(requirements_lock = '//:a.txt')\n\
             \"\"\"pip.parse(requirements_lock = '//:b.txt')\"\"\"\n\
             x = \"pip.parse(requirements_lock = '//:c.txt')\"  # pip.parse()\n\
             y = 'use_extension(\"//:e.bzl\", \"pip\")'\n",
        );
        assert_eq!(file.calls, []);
        assert_eq!(file.binds.len(), 2);
    }

    /// What must hold of whatever a file is read as.
    fn sound(src: &[u8]) {
        let Ok(tokens) = tokens(src) else {
            assert!(index(src).is_err());
            return;
        };
        let mut end = 0;
        for (at, token) in tokens.iter().enumerate() {
            assert!(end <= token.start && token.start < token.end && token.end <= src.len());
            end = token.end;
            let _ = value(src, token);
            if matches!(token.kind, Kind::Open | Kind::Close) {
                assert_eq!(tokens[token.mate].mate, at);
            }
        }
        let file = index(src).unwrap();
        for call in &file.calls {
            assert!(call.span.start < call.span.end && call.span.end <= src.len());
            assert_eq!(src[call.span.end - 1], b')');
            assert!(call.bind.is_none_or(|bind| bind < file.binds.len()));
            for arg in &call.args {
                assert!(call.span.start < arg.span.start && arg.span.end < call.span.end);
            }
        }
        for bind in &file.binds {
            assert!(
                !matches!(bind.to, Bound::Call(call) | Bound::Loaded(call, _) if call >= file.calls.len())
            );
        }
    }

    #[test]
    fn no_bytes_make_it_panic() {
        let sample = "module(name = 'm')  # c\n\
                      pip = use_extension(\"@rules_python//python/extensions:pip.bzl\", \"pip\")\n\
                      [pip.parse(a = r'\\x', b = {\"k\": [\"v\"]}, **{'c': '''d\ne'''}) for v in w]\n\
                      load('//:a.bzl', 'b', c = \"d\")\nx = y; z = lambda q: q(1.5e3)\n";
        let table: [&[u8]; 24] = [
            b"",
            b"\0",
            b"\0\0\0(",
            b"\xff\xfe\xfd",
            b"\xef\xbb\xbfx = 1",
            b"\"",
            b"'",
            b"'''",
            b"\"\"\"\"",
            b"r\"",
            b"\\",
            b"\\\n",
            b"\\\r",
            b"a.",
            b".a(",
            b"a.b.",
            b"f(=)",
            b"f(**)",
            b"f(a=)",
            b"= =",
            b"x = ",
            b"f(,,,)",
            b"[for]",
            b"lambda: lambda:,",
        ];
        for src in table {
            sound(src);
        }
        // The sample cut at every byte, with every byte replaced by each
        // of a few that open, close or end something, and random bytes.
        let bytes = sample.as_bytes();
        for at in 0..=bytes.len() {
            sound(&bytes[..at]);
            sound(&bytes[at..]);
            for swap in *b"\0\n\\\"'()[]{},=.#:*\xff" {
                let mut changed = bytes.to_vec();
                if let Some(byte) = changed.get_mut(at) {
                    *byte = swap;
                }
                sound(&changed);
            }
        }
        let mut rng = Rng::new(7);
        let alphabet = b"ab.=,:*()[]{}\"'\\\n #r\0\xff\xc3\xa9";
        for _ in 0..4000 {
            let len = rng.below(60);
            let random: Vec<u8> = (0..len)
                .map(|_| alphabet[rng.below(alphabet.len())])
                .collect();
            sound(&random);
        }
    }

    /// The largest file that is read, in each shape that nests or repeats
    /// without end, and with one long thing that many names stand for. One
    /// pass over 1 MiB takes well under a second; a pass that walked the
    /// nesting again at each level, or copied the long thing for each
    /// name, would take 10^12 steps.
    #[test]
    fn the_work_grows_with_the_size_of_the_file() {
        let fill = |unit: &str, tail: &str| -> Vec<u8> {
            let times = MAX_BYTES / (unit.len() + tail.len());
            let mut src = unit.repeat(times);
            src.push_str(&tail.repeat(times));
            src.into_bytes()
        };
        let started = std::time::Instant::now();
        for (unit, tail) in [
            ("(", ""),
            ("(", ")"),
            ("[", "]"),
            ("f(", ")"),
            ("f(x=[", "])"),
            ("f([\"a\",", "])"),
            ("f({\"k\":[\"a\"],", "})"),
            ("[f() for x in ", "]"),
            ("f(lambda:", ")"),
            ("lambda:[", "]"),
            ("[x for x in ", "]"),
            ("a,", "=b"),
            ("a=", "1for b in c\n"),
            ("1.", "e"),
            ("0x", "0b"),
            ("a.", "b()"),
            ("a=b\n", ""),
            ("a=a\n", ""),
            ("x=f()\n", ""),
            ("f(a,b,c,d)\n", ""),
            ("\"\\", ""),
            ("\"a\" ", ""),
            ("'''", ""),
            ("a ", ""),
            ("\n", ""),
            ("# \\\n", ""),
            ("\0", ""),
            ("\u{e9}", ""),
        ] {
            let src = fill(unit, tail);
            assert!(
                src.len() <= MAX_BYTES && src.len() > MAX_BYTES - 64,
                "{unit:?}"
            );
            sound(&src);
        }
        let (long, args) = ("s".repeat(MAX_BYTES / 2), "x,".repeat(MAX_BYTES / 4));
        for head in [
            format!("load('//:f.bzl', s = '{long}')\n"),
            format!("s = f({args})\n"),
        ] {
            let names = "a=s\n".repeat((MAX_BYTES - head.len()) / 4);
            sound(format!("{head}{names}").as_bytes());
        }
        let took = started.elapsed();
        assert!(took < std::time::Duration::from_secs(120), "{took:?}");
    }
}
