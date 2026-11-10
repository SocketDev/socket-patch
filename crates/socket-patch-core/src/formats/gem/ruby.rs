//! A line-level reading of Ruby source, as much of the language as a
//! Gemfile needs: which bytes are code (not a string, `%`-literal, regexp,
//! comment, `=begin` block or heredoc body), which words are keywords, and
//! which blocks are open at a point of the file. Shared by the Gemfile
//! declaration model ([`super::declarations`]), the hosted rewriter and the
//! hosted unwind, so all three agree on where a `gem` call starts and ends.

/// The DSL call whose block gives the gems declared in it their source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockSource {
    /// `source "<url>" do`
    Source,
    /// `git "<url>" do`
    Git,
    /// `github "<owner>/<repo>" do`
    Github,
    /// `path "<dir>" do`
    Path,
}

impl BlockSource {
    fn of(word: &str) -> Option<Self> {
        match word {
            "source" => Some(BlockSource::Source),
            "git" => Some(BlockSource::Git),
            "github" => Some(BlockSource::Github),
            "path" => Some(BlockSource::Path),
            _ => None,
        }
    }

    /// The call's name, as the Gemfile spells it.
    pub(crate) fn word(self) -> &'static str {
        match self {
            BlockSource::Source => "source",
            BlockSource::Git => "git",
            BlockSource::Github => "github",
            BlockSource::Path => "path",
        }
    }
}

/// A Ruby construct still open at some point of the manifest.
pub(crate) struct Frame {
    /// The source-selecting call this block belongs to (`source … do`,
    /// `source(…) {`, `git … do`, `github … do`, `path … do`); `None` for
    /// anything else Ruby closes with `end` or `}`: `group … do`, `if`,
    /// `case`, `def`, a hash, ….
    pub(crate) source: Option<BlockSource>,
    /// Byte offset of the start of the line its statement began on.
    pub(crate) line: usize,
    /// Byte offset of the start of the line holding its opener (the `do`,
    /// `{` or keyword), below `line` when the statement spans lines.
    pub(crate) opener: usize,
}

/// The Ruby constructs still open at byte `at` (a line start) of the
/// manifest, outermost first. A word-level count over each line's code:
/// a construct opened and closed on one line nets out, and a keyword opens
/// one wherever it starts an expression (`v = if …`, `require: case …`,
/// #1476), not only at the start of a line, so its `end` never closes an
/// enclosing block. A `{` opens one that its `}` closes (a brace block or
/// a hash). A statement runs on while a `(` or `[` is open, so a `source(`
/// whose arguments span lines still owns the `do` or `{` that follows its
/// `)` (#1509). A `source` call (or `git`, `github`, `path`: the calls
/// whose block picks its gems' source) counts wherever it starts an
/// expression, as a keyword does (`x = 1; source "…" do`, `… then source
/// "…" do`, #1531). String, `%w[]`, regexp and backtick literals, comments,
/// `=begin` … `=end` blocks and heredoc bodies are not code.
pub(crate) fn block_stack(text: &str, at: usize) -> Vec<Frame> {
    let mut open: Vec<Frame> = Vec::new();
    let mut block_comment = false;
    // Pending heredoc terminators: (identifier, may be indented).
    let mut heredocs: std::collections::VecDeque<(String, bool)> = Default::default();
    // A string or `%`-literal still open at the end of the last line.
    let mut literal: Option<Literal> = None;
    // The code the last line left unfinished (a trailing `,`, `\`, `=`,
    // …): only its end matters, to tell what a keyword follows.
    let mut carried = String::new();
    // Open `(`, `[` and hash `{` of the statement.
    let mut depth = 0usize;
    // Each open `{`: a hash (counted in `depth`) or a block (a frame).
    let mut braces: Vec<bool> = Vec::new();
    // A `source` call whose block has not opened yet: the number of brace
    // blocks open around it (a `}` closing one of them ends the call, and
    // only a `do` or `{` at that level is its block), and which call.
    let mut source_pending: Option<(usize, BlockSource)> = None;
    // The `source(` call's argument list: (it is open, it has closed or
    // there is none).
    let mut source_call = (false, true);
    let mut statement_line = 0;
    let mut start = 0;
    for raw in text[..at].split_inclusive('\n') {
        let line_start = start;
        start += raw.len();
        let line = raw.trim_end_matches(['\n', '\r']);
        // `=begin` / `=end` start at column 0 and are followed by
        // whitespace or the end of the line (Ruby's own rule).
        let marker = |word: &str| {
            line.strip_prefix(word)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
        };
        if block_comment {
            block_comment = !marker("=end");
            continue;
        }
        if let Some((id, indented)) = heredocs.front() {
            let body = if *indented { line.trim_start() } else { line };
            if body == id {
                heredocs.pop_front();
            }
            continue;
        }
        if literal.is_none() && marker("=begin") {
            block_comment = true;
            continue;
        }
        // An open bracket carries only a `source` statement on to its
        // block opener: elsewhere a bracket the masker missed (one in an
        // interpolation) must not swallow the rest of the file.
        let continues =
            literal.is_some() || !carried.is_empty() || (depth > 0 && source_pending.is_some());
        let masked = masked_ruby_code(line, &mut literal);
        heredocs.extend(heredoc_openers(line, &masked));
        let masked = masked.trim();
        if !continues {
            depth = 0;
            statement_line = line_start;
            source_pending = None;
            source_call = (false, true);
        }
        for (n, statement) in masked.split(';').enumerate() {
            let lead = if n == 0 { carried.as_str() } else { "" };
            // A top-level `;` starts a new statement, unless it sits in a
            // brace block of the `source` call's own arguments.
            if n > 0 && depth == 0 && source_pending.is_none_or(|(level, _)| braces.len() <= level)
            {
                statement_line = line_start;
                source_pending = None;
                source_call = (false, true);
            }
            // A `while`/`until`/`for` takes its optional `do` as part of
            // the loop, not as a block of its own.
            let mut loop_do = false;
            // The word after `def` is the method's name (`def begin`).
            let mut method_name = false;
            // The last token closed the `source(…)` argument list.
            let mut after_source_call = false;
            for (word, start, end) in ruby_tokens(statement) {
                let closed_source_call = std::mem::take(&mut after_source_call);
                if is_ident_byte(word.as_bytes()[0]) && std::mem::take(&mut method_name) {
                    continue;
                }
                let expression = || starts_expression(&format!("{lead} {}", &statement[..start]));
                let (opens, source) = match word {
                    // One in a brace block of an outer call's arguments
                    // does not replace that call.
                    "source" | "git" | "github" | "path"
                        if depth == 0 && source_pending.is_none() && expression() =>
                    {
                        if let (Some(parenthesized), Some(call)) =
                            (source_call_args(&statement[end..]), BlockSource::of(word))
                        {
                            source_pending = Some((braces.len(), call));
                            source_call = (false, !parenthesized);
                        }
                        (false, None)
                    }
                    "(" | "[" => {
                        if depth == 0 && !source_call.1 {
                            source_call.0 = true;
                        }
                        depth += 1;
                        (false, None)
                    }
                    ")" | "]" => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 && std::mem::take(&mut source_call.0) {
                            source_call.1 = true;
                            after_source_call = true;
                        }
                        (false, None)
                    }
                    // A hash literal, part of the statement.
                    "{" if expression() && !statement[..start].trim_end().ends_with("->") => {
                        braces.push(true);
                        depth += 1;
                        (false, None)
                    }
                    // A brace block binds to the call before it, so only
                    // the one right after `source(…)` is the source's.
                    "{" => {
                        braces.push(false);
                        let source = closed_source_call
                            .then(|| take_source(&mut source_pending, braces.len() - 1))
                            .flatten();
                        (true, source)
                    }
                    "}" => {
                        match braces.pop() {
                            Some(true) => depth = depth.saturating_sub(1),
                            Some(false) => {
                                open.pop();
                                // A `source` call inside the block ends with it.
                                if source_pending.is_some_and(|(level, _)| braces.len() < level) {
                                    source_pending = None;
                                }
                            }
                            None => {}
                        }
                        (false, None)
                    }
                    "do" => {
                        let opens = !std::mem::take(&mut loop_do);
                        let source = (opens && depth == 0)
                            .then(|| take_source(&mut source_pending, braces.len()))
                            .flatten();
                        (opens, source)
                    }
                    "if" | "unless" => (expression(), None),
                    "while" | "until" => {
                        let opens = expression();
                        loop_do |= opens;
                        (opens, None)
                    }
                    "for" => {
                        loop_do = true;
                        (true, None)
                    }
                    "def" => {
                        method_name = true;
                        (!endless_def(&statement[end..]), None)
                    }
                    "case" | "begin" | "class" | "module" => (true, None),
                    "end" => {
                        open.pop();
                        (false, None)
                    }
                    _ => (false, None),
                };
                if opens {
                    open.push(Frame {
                        source,
                        line: statement_line,
                        opener: line_start,
                    });
                }
            }
        }
        // A line ending mid-expression; one that only leaves a bracket open
        // starts a fresh expression on the next line.
        let unfinished = literal.is_some()
            || masked.ends_with(['\\', ',', '(', '[', '+', '-', '*', '='])
            || masked.ends_with("||")
            || masked.ends_with("&&");
        carried = if unfinished {
            let tail = masked.rsplit(';').next().unwrap_or_default();
            tail.trim_end_matches('\\').trim().to_string()
        } else {
            String::new()
        };
    }
    open
}

/// The pending `source` call (see [`block_stack`]) when it sits at brace
/// level `level`, in which case the block opening there is its block.
fn take_source(pending: &mut Option<(usize, BlockSource)>, level: usize) -> Option<BlockSource> {
    pending.take_if(|(l, _)| *l == level).map(|(_, call)| call)
}

/// Whether `rest`, what follows the word `source` that starts an
/// expression, makes it a call with arguments, and whether those are in
/// parentheses (`source(…)`). `source = …` assigns a local variable.
pub(crate) fn source_call_args(rest: &str) -> Option<bool> {
    if rest.starts_with('(') {
        return Some(true);
    }
    let args = rest.strip_prefix([' ', '\t'])?.trim_start();
    (!args.is_empty() && !args.starts_with('=')).then_some(false)
}

/// [`ruby_words`] and the brackets (`(`, `)`, `[`, `]`, `{`, `}`) of a
/// masked code line, in order, with their byte range.
fn ruby_tokens(code: &str) -> impl Iterator<Item = (&str, usize, usize)> {
    let mut words = ruby_words(code).peekable();
    let mut brackets = code
        .match_indices(['(', ')', '[', ']', '{', '}'])
        .map(|(at, b)| (b, at, at + 1))
        .peekable();
    std::iter::from_fn(move || match (words.peek(), brackets.peek()) {
        (Some(w), Some(b)) if b.1 < w.1 => brackets.next(),
        (Some(_), _) => words.next(),
        (None, _) => brackets.next(),
    })
}

/// The keyword-like words of a masked code line, with their byte range: a
/// symbol (`:if`), method call (`.class`) or variable sigil is a name, and
/// so are a predicate or bang (`begin?`) and a hash label (`if:`).
pub(crate) fn ruby_words(code: &str) -> impl Iterator<Item = (&str, usize, usize)> {
    let bytes = code.as_bytes();
    let mut i = 0;
    std::iter::from_fn(move || {
        while i < bytes.len() {
            if !is_ident_byte(bytes[i]) {
                i += 1;
                continue;
            }
            let start = i;
            while i < bytes.len() && is_ident_byte(bytes[i]) {
                i += 1;
            }
            let prev_ok = start == 0 || !matches!(bytes[start - 1], b':' | b'.' | b'@' | b'$');
            let next_ok = match bytes.get(i) {
                Some(b'?' | b'!') => false,
                Some(b':') => bytes.get(i + 1) == Some(&b':'),
                _ => true,
            };
            if prev_ok && next_ok {
                return Some((&code[start..i], start, i));
            }
        }
        None
    })
}

pub(crate) fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || !b.is_ascii()
}

/// Whether a keyword or literal after `before` (the masked code before it
/// in its statement) starts an expression, as opposed to modifying the
/// statement before it (`gem "x" if cond`, `x.save! if y`) or dividing.
pub(crate) fn starts_expression(before: &str) -> bool {
    let before = before.trim_end();
    let Some(last) = before.bytes().next_back() else {
        return true;
    };
    match last {
        b'=' | b'(' | b'[' | b'{' | b',' | b';' | b'|' | b'&' | b'>' | b'<' | b'+' | b'-'
        | b'*' | b'~' => true,
        // A unary `!`, not a bang method (`x.save! if y`).
        b'!' => before.len() == 1 || !is_ident_byte(before.as_bytes()[before.len() - 2]),
        // A label (`require: if …`) or a ternary's `:`, not `Foo::`.
        b':' => !before.ends_with("::"),
        // A ternary's `?`, not a predicate (`x.empty? if y`).
        b'?' => before[..before.len() - 1].ends_with(char::is_whitespace),
        b if is_ident_byte(b) => {
            let word_start = before
                .bytes()
                .rposition(|b| !is_ident_byte(b))
                .map_or(0, |i| i + 1);
            let called = word_start > 0
                && matches!(before.as_bytes()[word_start - 1], b'.' | b':' | b'@' | b'$');
            !called
                && matches!(
                    &before[word_start..],
                    "then"
                        | "else"
                        | "elsif"
                        | "do"
                        | "begin"
                        | "ensure"
                        | "and"
                        | "or"
                        | "not"
                        | "when"
                        | "in"
                        | "if"
                        | "unless"
                        | "while"
                        | "until"
                        | "case"
                )
        }
        _ => false,
    }
}

/// Whether `rest` (what follows `def`) is an endless method (`def x = 1`,
/// `def x(a = f()) = a`, `def ==(o) = …`), which Ruby closes without an
/// `end`. A setter (`def x=(v)`) is not.
fn endless_def(rest: &str) -> bool {
    let rest = rest.trim_start();
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let name_len = if rest.starts_with(ident) {
        // `x`, `self.x`, `x?`, `x!`.
        let len = rest
            .find(|c: char| !(ident(c) || c == '.'))
            .unwrap_or(rest.len());
        len + usize::from(rest[len..].starts_with(['?', '!']))
    } else {
        // An operator method: `==`, `<=>`, `[]=`, `+@`, ….
        rest.find(|c: char| !"[]=!<>+-*/%~^&|@".contains(c))
            .unwrap_or(rest.len())
    };
    if name_len == 0 {
        return false;
    }
    let mut tail = &rest[name_len..];
    if tail.starts_with('(') {
        let mut depth = 0usize;
        let Some(close) = tail.find(|c: char| {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
            depth == 0
        }) else {
            return false;
        };
        tail = &tail[close + 1..];
    } else if !tail.starts_with([' ', '\t']) {
        return false;
    }
    tail.trim_start()
        .strip_prefix('=')
        .is_some_and(|t| !t.starts_with(['=', '~', '>']))
}

/// A string or `%`-literal left open at the end of a line.
#[derive(Clone, Copy)]
struct Literal {
    open: u8,
    close: u8,
    /// Nesting of `open` inside a bracketed literal (`%w[a [b] c]`).
    depth: usize,
}

/// `line` up to its `#` comment, with the contents of every string,
/// character literal, backtick, `%`-literal (`%w[…]`, `%i(…)`, `%q{…}`, …) and regexp literal
/// masked as `x`, byte for byte, so a keyword or `#` inside one never counts
/// as code. The delimiters stay. A string or `%`-literal still open at the
/// end of the line is carried in `literal` to mask the next line from its
/// start.
fn masked_ruby_code(line: &str, literal: &mut Option<Literal>) -> String {
    let bytes = line.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    if let Some(lit) = literal.take() {
        match mask_literal(bytes, &mut out, 0, lit) {
            Ok(end) => i = end + 1,
            Err(lit) => {
                *literal = Some(lit);
                i = bytes.len();
            }
        }
    }
    while i < bytes.len() {
        let b = bytes[i];
        let before = std::str::from_utf8(&out[..i]).unwrap_or_default();
        let (lit, body) = match b {
            b'#' => {
                out.truncate(i);
                break;
            }
            // A character literal (`?(`, `?}`, `?\n`): its character is
            // not code.
            b'?' if starts_expression(before) => {
                let len = match bytes.get(i + 1) {
                    Some(b'\\') => 2,
                    Some(c) if c.is_ascii_punctuation() => 1,
                    _ => 0,
                };
                let next = bytes.get(i + 1 + len).copied();
                if len > 0 && !next.is_some_and(is_ident_byte) {
                    out[i + 1..(i + 1 + len).min(bytes.len())].fill(b'x');
                }
                i += 1 + len;
                continue;
            }
            b'"' | b'\'' | b'`' => (
                Literal {
                    open: b,
                    close: b,
                    depth: 0,
                },
                i + 1,
            ),
            b'/' if starts_expression(before) => (
                Literal {
                    open: b,
                    close: b,
                    depth: 0,
                },
                i + 1,
            ),
            b'%' if starts_expression(before) => {
                let mut j = i + 1;
                if bytes.get(j).is_some_and(|c| b"wWiIqQrsx".contains(c)) {
                    j += 1;
                }
                match bytes.get(j) {
                    Some(&open) if open.is_ascii_punctuation() => {
                        let close = match open {
                            b'(' => b')',
                            b'[' => b']',
                            b'{' => b'}',
                            b'<' => b'>',
                            _ => open,
                        };
                        (
                            Literal {
                                open,
                                close,
                                depth: 0,
                            },
                            j + 1,
                        )
                    }
                    _ => {
                        i += 1;
                        continue;
                    }
                }
            }
            _ => {
                i += 1;
                continue;
            }
        };
        match mask_literal(bytes, &mut out, body, lit) {
            Ok(end) => i = end + 1,
            // An unclosed `/` was a division after all.
            Err(_) if b == b'/' => {
                out[body..].copy_from_slice(&bytes[body..]);
                i += 1;
            }
            Err(lit) => {
                *literal = Some(lit);
                break;
            }
        }
    }
    // The delimiters are ASCII, so a masked run never cuts a multi-byte
    // character: the result is still UTF-8.
    String::from_utf8(out).unwrap_or_default()
}

/// Masks `lit`'s body in `out` from byte `from` of `bytes`: `Ok` with the
/// closing delimiter's index, or `Err` with the literal still open at the
/// end of the line.
fn mask_literal(
    bytes: &[u8],
    out: &mut [u8],
    from: usize,
    mut lit: Literal,
) -> Result<usize, Literal> {
    let mut j = from;
    while j < bytes.len() {
        let c = bytes[j];
        if c == b'\\' {
            out[j] = b'x';
            if let Some(next) = out.get_mut(j + 1) {
                *next = b'x';
            }
            j += 2;
            continue;
        }
        if c == lit.close && lit.depth == 0 {
            return Ok(j);
        }
        if lit.open != lit.close && c == lit.open {
            lit.depth += 1;
        } else if lit.open != lit.close && c == lit.close {
            lit.depth -= 1;
        }
        out[j] = b'x';
        j += 1;
    }
    Err(lit)
}

/// The heredocs a line opens (`<<~EOS`, `<<-"EOS"`, `x = <<EOS`), in
/// order, as (terminator, may be indented). `masked` is `line` through
/// [`masked_ruby_code`], so an opener inside a literal or comment does not
/// count, and neither does an append (`list << x`, `a<<B`, `class <<self`):
/// a bare `<<NAME` must start an expression.
fn heredoc_openers(line: &str, masked: &str) -> Vec<(String, bool)> {
    let bytes = masked.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(at) = masked[i..].find("<<").map(|p| p + i) {
        i = at + 2;
        if at > 0 && (is_ident_byte(bytes[at - 1]) || matches!(bytes[at - 1], b')' | b']' | b'}')) {
            continue;
        }
        let mut j = at + 2;
        let indented = matches!(bytes.get(j), Some(b'~' | b'-'));
        if indented {
            j += 1;
        }
        let id = match bytes.get(j) {
            Some(&q @ (b'"' | b'\'' | b'`')) => masked[j + 1..]
                .find(q as char)
                .map(|end| &line[j + 1..j + 1 + end]),
            Some(&b)
                if (b.is_ascii_alphabetic() || b == b'_')
                    && (indented || starts_expression(&masked[..at])) =>
            {
                let len = masked[j..]
                    .bytes()
                    .position(|b| !is_ident_byte(b))
                    .unwrap_or(masked.len() - j);
                Some(&line[j..j + len])
            }
            _ => None,
        };
        if let Some(id) = id.filter(|id| !id.is_empty()) {
            out.push((id.to_string(), indented));
            i = j + 1;
        }
    }
    out
}

/// `text` with everything that is not code blanked, byte for byte: the
/// contents of strings and other literals are `x` ([`masked_ruby_code`]),
/// and comments, `=begin` … `=end` blocks, heredoc bodies, the `__END__`
/// data section and a leading BOM are spaces. Line breaks stay, so a byte
/// offset or a line of the result is the same offset or line of `text`.
pub(crate) fn masked_source(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut block_comment = false;
    let mut data_section = false;
    let mut heredocs: std::collections::VecDeque<(String, bool)> = Default::default();
    let mut literal: Option<Literal> = None;
    for (n, raw) in text.split_inclusive('\n').enumerate() {
        let line = raw.trim_end_matches(['\n', '\r']);
        let ending = &raw[line.len()..];
        let blank = |out: &mut String| {
            out.extend(std::iter::repeat_n(' ', line.len()));
            out.push_str(ending);
        };
        let marker = |word: &str| {
            line.strip_prefix(word)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
        };
        if data_section {
            blank(&mut out);
            continue;
        }
        if block_comment {
            block_comment = !marker("=end");
            blank(&mut out);
            continue;
        }
        if let Some((id, indented)) = heredocs.front() {
            let body = if *indented { line.trim_start() } else { line };
            if body == id {
                heredocs.pop_front();
            }
            blank(&mut out);
            continue;
        }
        if literal.is_none() && marker("=begin") {
            block_comment = true;
            blank(&mut out);
            continue;
        }
        if literal.is_none() && line.trim_end() == "__END__" {
            data_section = true;
            blank(&mut out);
            continue;
        }
        let bom = if n == 0 && line.starts_with('\u{feff}') {
            '\u{feff}'.len_utf8()
        } else {
            0
        };
        let masked = masked_ruby_code(&line[bom..], &mut literal);
        heredocs.extend(heredoc_openers(&line[bom..], &masked));
        out.extend(std::iter::repeat_n(' ', bom));
        out.push_str(&masked);
        out.extend(std::iter::repeat_n(' ', line.len() - bom - masked.len()));
        out.push_str(ending);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mask keeps every byte offset: literals are `x`, what is not code
    /// is blank, and line breaks (CRLF included) stay.
    #[test]
    fn masked_source_keeps_offsets_and_blanks_what_is_not_code() {
        let text = "\u{feff}gem \"rack\", '~> 2' # why\r\n=begin\ngem \"x\"\n=end\nx = <<~EOS\n  gem \"y\"\nEOS\ngem \"z\",\n  require: %w[a b]\n__END__\ngem \"w\"\n";
        let masked = masked_source(text);
        assert_eq!(masked.len(), text.len());
        assert_eq!(
            masked,
            "   gem \"xxxx\", 'xxxx'      \r\n      \n       \n    \nx = <<~EOS\n         \n   \ngem \"x\",\n  require: %w[xxx]\n       \n       \n"
        );
    }

    /// A block's source call is recorded with the frame it opens.
    #[test]
    fn block_stack_names_the_source_call_of_a_block() {
        let at = |text: &str| {
            block_stack(text, text.find("gem \"x\"").unwrap())
                .iter()
                .map(|f| f.source)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            at("source \"https://a.example\" do\n  group :test do\n    gem \"x\"\n"),
            [Some(BlockSource::Source), None]
        );
        assert_eq!(
            at("git \"https://a.example/x.git\" do\n  gem \"x\"\n"),
            [Some(BlockSource::Git)]
        );
        assert_eq!(
            at("github \"a/x\" do\n  gem \"x\"\n"),
            [Some(BlockSource::Github)]
        );
        assert_eq!(
            at("path \"components\" do\n  gem \"x\"\n"),
            [Some(BlockSource::Path)]
        );
        // A local variable of that name opens nothing.
        assert_eq!(at("path = \"x\"\ngroup :a do\n  gem \"x\"\n"), [None]);
        assert!(at("source \"https://a.example\"\ngem \"x\"\n").is_empty());
    }
}
