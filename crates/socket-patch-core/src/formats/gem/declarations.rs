//! The `gem` calls of a Gemfile / `gems.rb`: the ONE reader of where a
//! declaration starts and ends, which gem it names and which arguments it
//! carries, shared by the hosted rewriter (which appends a `source:` option
//! to a declaration), the hosted unwind (which takes it off again) and
//! lockfile discovery (which reads it).
//!
//! A declaration is edited in place, never rewritten: everything the user
//! wrote (version requirements, quote style, options, comment, position,
//! enclosing block, indentation) stays byte for byte, and removing the
//! appended option restores the file exactly. So the reader only has to
//! find the end of the call's last argument, on whatever line it sits:
//!
//! ```text
//! gem "rack", "~> 2.2.3"       # web server interface
//! gem("jmespath", "1.4.0")
//! gem "puma",
//!     "4.3.5",
//!     require: false
//! gem "rexml", ">= 3.2.4", "< 3.2.5" if RUBY_VERSION >= "3"
//! ```
//!
//! The reading is over [`masked_source`]: literals, comments and heredoc
//! bodies are not code, so a `gem` inside one is no call and a `,` or
//! keyword inside one ends nothing. A call the reader cannot follow to its
//! end (a heredoc argument, a `do` block, an interpolation that nests
//! quotes, a call sharing its line with other code) carries a
//! [`Declaration::problem`] and is never edited.

use super::gemfile::NON_SOURCE_KEYS;
use super::is_plain_gem_token;
use super::ruby::{is_ident_byte, masked_source, ruby_words, source_call_args};
use crate::utils::line_endings;

/// The trailing comment of a line the hosted rewriter ADDED for a gem the
/// Gemfile does not declare (a transitive dependency). It tells the reader
/// why the line is there, and tells the unwind that the whole line is
/// socket-patch's: without it an added line cannot be told from a
/// declaration the user wrote with the same arguments and the option
/// appended, and removing the wrong one would drop a declaration.
pub(crate) const ADDED_LINE_MARKER: &str = "# added by socket-patch (transitive dependency)";

/// One argument of a `gem` call, after the name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Arg {
    /// Byte offset of the `,` that separates it from what precedes it.
    pub(crate) comma: usize,
    /// Byte range of the argument, trimmed.
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) kind: ArgKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ArgKind {
    /// A string literal, or an array of them: a version requirement.
    Version,
    /// `key: v`, `"key": v`, `:key => v` or `"key" => v`.
    Option {
        key: String,
        /// The key as written (`gitlab:`, `:git`, `"git" =>`).
        spelling: String,
        /// The value when it is one plain string literal (no escape, no
        /// interpolation).
        value: Option<String>,
    },
    /// `**opts`, `*args` or a `{ … }` hash: arguments whose keys cannot be
    /// read.
    Dynamic,
    /// Any other positional argument (a constant, a local variable, a
    /// call, an array): its value is not known here. As the LAST argument
    /// it may be the options hash ([`Declaration::opaque_last`]).
    Opaque,
}

/// One `gem "<name>", …` call whose name is a plain string literal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Declaration {
    pub(crate) name: String,
    /// Byte range of the call, `gem` through its last argument (and the
    /// `)` of a parenthesized call).
    pub(crate) start: usize,
    pub(crate) end: usize,
    /// Where one more argument goes: just past the last argument.
    pub(crate) args_end: usize,
    /// The arguments after the name, in order.
    pub(crate) args: Vec<Arg>,
    /// Why the call cannot be edited in place; `None` when an argument can
    /// be appended at [`Self::args_end`].
    pub(crate) problem: Option<String>,
}

impl Declaration {
    /// The call's `source` option, with its URL when that is a plain
    /// string literal.
    pub(crate) fn source(&self) -> Option<(&Arg, Option<&str>)> {
        self.args.iter().find_map(|arg| match &arg.kind {
            ArgKind::Option { key, value, .. } if key == "source" => Some((arg, value.as_deref())),
            _ => None,
        })
    }

    /// The first option that picks where bundler fetches the gem from
    /// (`source:`, `git:`, `path:`, `github:`, a custom git source), as
    /// written.
    pub(crate) fn source_selecting(&self) -> Option<&str> {
        self.args.iter().find_map(|arg| match &arg.kind {
            ArgKind::Option { key, spelling, .. } if !NON_SOURCE_KEYS.contains(&key.as_str()) => {
                Some(spelling.as_str())
            }
            _ => None,
        })
    }

    /// The text of the first argument whose keys cannot be read (`**opts`,
    /// `*args`, a hash literal): it may select a source.
    pub(crate) fn dynamic<'t>(&self, text: &'t str) -> Option<&'t str> {
        self.args
            .iter()
            .find(|arg| arg.kind == ArgKind::Dynamic)
            .map(|arg| &text[arg.start..arg.end])
    }

    /// The call's positional arguments: its version requirements.
    pub(crate) fn positionals(&self) -> impl Iterator<Item = &Arg> {
        self.args
            .iter()
            .filter(|arg| matches!(arg.kind, ArgKind::Version | ArgKind::Opaque))
    }

    /// The last argument when it is a positional whose value is unknown and
    /// no option follows it: bundler takes a trailing Hash as the call's
    /// options (`OPTS = { git: "…" }` … `gem "rack", OPTS`), so it may hold
    /// options rather than a version requirement.
    pub(crate) fn opaque_last<'t>(&self, text: &'t str) -> Option<&'t str> {
        self.args
            .last()
            .filter(|arg| arg.kind == ArgKind::Opaque)
            .map(|arg| &text[arg.start..arg.end])
    }
}

/// Every `gem` call of a manifest.
#[derive(Debug, Default)]
pub(crate) struct Declarations {
    /// The calls naming their gem with a plain string literal, in file
    /// order.
    pub(crate) literal: Vec<Declaration>,
    /// Whether some `gem` call names its gem any other way (`gem name`,
    /// `gem *args`, `gem "#{prefix}-core"`): a declaration no reader can
    /// attribute to a gem.
    pub(crate) dynamic: bool,
}

impl Declarations {
    /// The declarations of `name`.
    pub(crate) fn of<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Declaration> {
        self.literal.iter().filter(move |d| d.name == name)
    }
}

/// Words that end a `gem` call's arguments as a statement modifier.
const MODIFIERS: [&str; 5] = ["if", "unless", "while", "until", "rescue"];

/// Words that can only follow a complete call when something other than a
/// plain declaration is going on (`gem "x" do`, `gem "x" and …`, the `end`
/// of a one-line block).
const BREAKERS: [&str; 17] = [
    "do", "and", "or", "not", "then", "else", "elsif", "end", "begin", "case", "def", "class",
    "module", "for", "in", "when", "ensure",
];

/// Read every `gem` call of `text` (see the module docs).
pub(crate) fn declarations(text: &str) -> Declarations {
    let masked = masked_source(text);
    let mut out = Declarations::default();
    // A `gem` word inside a call already read (`gem "x", require: gem`) is
    // part of that call.
    let mut resume = 0;
    for (word, start, end) in ruby_words(&masked) {
        if word != "gem" || start < resume {
            continue;
        }
        match read_call(text, &masked, start, end) {
            Some(Call::Literal(decl)) => {
                resume = decl.end;
                out.literal.push(decl);
            }
            Some(Call::Dynamic) => out.dynamic = true,
            None => {}
        }
    }
    out
}

enum Call {
    Literal(Declaration),
    Dynamic,
}

/// The `gem` word at `start..end` of `masked` as a call: `None` when it is
/// not one (a local variable, a bare word).
fn read_call(text: &str, masked: &str, start: usize, end: usize) -> Option<Call> {
    let m = masked.as_bytes();
    let paren = m.get(end) == Some(&b'(');
    // `gem "x"`, `gem("x")` or `gem"x"`.
    if !paren && !matches!(m.get(end), Some(b' ' | b'\t' | b'"' | b'\'')) {
        return None;
    }
    // The first argument: on the call's line, or anywhere inside its `(`.
    let mut p = end + usize::from(paren);
    while m
        .get(p)
        .is_some_and(|b| matches!(b, b' ' | b'\t') || (paren && matches!(b, b'\r' | b'\n')))
    {
        p += 1;
    }
    let quote = match m.get(p) {
        Some(q @ (b'"' | b'\'')) => *q,
        // The end of the line, or an operator: `gem` is a local variable.
        None
        | Some(
            b'\r' | b'\n' | b'=' | b'.' | b'|' | b'&' | b'+' | b'-' | b'/' | b'<' | b'>' | b'!'
            | b'?' | b'^' | b'~' | b',' | b')' | b']' | b'}' | b';',
        ) => return None,
        Some(_) => return Some(Call::Dynamic),
    };
    // A masked literal's body holds no quote, so the next one closes it.
    let Some(close) = masked[p + 1..].find(quote as char).map(|i| p + 1 + i) else {
        return Some(Call::Dynamic);
    };
    let name = &text[p + 1..close];
    let interpolated = quote == b'"' && name.contains("#{");
    if name.contains('\\') || interpolated || !is_plain_gem_token(name) {
        return Some(Call::Dynamic);
    }

    let line_start = masked[..start].rfind('\n').map_or(0, |i| i + 1);
    let lead = masked[line_start..start].trim();
    let mut problem: Option<String> = (!lead.is_empty() && !lead.ends_with(';'))
        .then(|| "it shares its line with other code".to_string());

    // The argument list: top-level commas split it, brackets nest, and it
    // ends at the call's `)`, at the end of a line that leaves nothing
    // open, at a `;`, or at a statement modifier.
    let mut args: Vec<(usize, Option<(usize, usize)>)> = Vec::new();
    let mut depth = 0usize;
    let mut closed = false;
    // The last code byte read: a line ending on `,` or `\` carries the
    // call on to the next line.
    let mut last = quote;
    let mut i = close + 1;
    let mut call_end = close + 1;
    while i < m.len() {
        let b = m[i];
        match b {
            b' ' | b'\t' | b'\r' => {
                i += 1;
                continue;
            }
            b'\n' => {
                if !(paren || depth > 0 || matches!(last, b',' | b'\\')) {
                    // A line ending on an operator or a label goes on too,
                    // but where it ends is not followed here.
                    let code = masked[..i].trim_end();
                    let label = code.ends_with(':')
                        && !code.ends_with("::")
                        && code[..code.len() - 1]
                            .bytes()
                            .next_back()
                            .is_some_and(|c| is_ident_byte(c) || matches!(c, b'"' | b'\''));
                    if label
                        || ["=>", "||", "&&", "+", "-", "*", "=", "."]
                            .iter()
                            .any(|op| code.ends_with(op))
                    {
                        problem.get_or_insert_with(|| {
                            "its last line ends in the middle of an expression".into()
                        });
                    }
                    break;
                }
                // A `\` carries the call on to the next line only: a blank
                // or comment-only line after it ends the statement, as in
                // Ruby. A `,` keeps carrying it over such lines.
                if last == b'\\' {
                    last = b'\n';
                }
                i += 1;
                continue;
            }
            b'\\' if matches!(m.get(i + 1), Some(b'\r' | b'\n')) => {
                last = b;
                i += 1;
                continue;
            }
            b';' if depth == 0 && !paren => break,
            b',' if depth == 0 => {
                if matches!(args.last(), Some((_, None))) {
                    problem
                        .get_or_insert_with(|| "an argument is missing between two commas".into());
                }
                args.push((i, None));
                last = b;
                i += 1;
                continue;
            }
            b')' | b']' | b'}' if depth == 0 => {
                if paren && b == b')' {
                    closed = true;
                    call_end = i + 1;
                } else if paren {
                    problem.get_or_insert_with(|| "its brackets do not balance".into());
                }
                // Unparenthesized: the closer of an enclosing block.
                break;
            }
            _ => {}
        }
        // A word: a modifier or block keyword ends the arguments.
        let mut len = 1;
        if is_ident_byte(b) {
            len = m[i..]
                .iter()
                .position(|c| !is_ident_byte(*c))
                .unwrap_or(m.len() - i);
            let word = &masked[i..i + len];
            // Whether an argument (or the name) is complete before the
            // word. `if:` is a hash key only where an argument can start;
            // straight after a value, `if:FLAG` is a modifier on `:FLAG`.
            let complete = !matches!(args.last(), Some((_, None)));
            let bare = !matches!(m.get(i.wrapping_sub(1)), Some(b':' | b'.' | b'@' | b'$'))
                && match m.get(i + len) {
                    Some(b'?' | b'!') => false,
                    Some(b':') => complete || m.get(i + len + 1) == Some(&b':'),
                    _ => true,
                };
            if bare && depth == 0 && !paren {
                if MODIFIERS.contains(&word) && complete {
                    break;
                }
                if MODIFIERS.contains(&word) || BREAKERS.contains(&word) {
                    problem.get_or_insert_with(|| format!("a `{word}` follows its arguments"));
                    break;
                }
            }
        }
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            _ => {}
        }
        match args.last_mut() {
            Some((_, span)) => {
                let s = span.map_or(i, |(s, _)| s);
                *span = Some((s, i + len));
            }
            // Code right after the name with no comma (`gem "a" "b"`).
            None => {
                problem.get_or_insert_with(|| "unexpected code follows the gem name".into());
            }
        }
        last = m[i + len - 1];
        i += len;
        if !paren {
            call_end = i;
        }
    }
    if paren && !closed {
        problem.get_or_insert_with(|| "its closing `)` is missing".into());
        call_end = call_end.max(i.min(m.len()));
    }
    if depth > 0 {
        problem.get_or_insert_with(|| "its brackets do not balance".into());
    }
    // A trailing comma is legal inside parentheses; elsewhere the call
    // goes on into something this reader did not follow.
    if matches!(args.last(), Some((_, None))) {
        if !paren {
            problem.get_or_insert_with(|| "it ends on a comma".into());
        }
        args.pop();
    }
    if paren && closed {
        // Only a modifier or a statement end may follow the `)`.
        let line_end = masked[call_end..]
            .find('\n')
            .map_or(masked.len(), |i| call_end + i);
        let rest = masked[call_end..line_end].trim();
        let word_len = rest
            .bytes()
            .position(|c| !is_ident_byte(c))
            .unwrap_or(rest.len());
        if !(rest.is_empty() || rest.starts_with(';') || MODIFIERS.contains(&&rest[..word_len])) {
            problem.get_or_insert_with(|| "code follows the call on its line".into());
        }
    }
    let args: Vec<Arg> = args
        .into_iter()
        .filter_map(|(comma, span)| span.map(|(s, e)| (comma, s, e)))
        .map(|(comma, s, e)| Arg {
            comma,
            start: s,
            end: e,
            kind: classify(&text[s..e], &masked[s..e]),
        })
        .collect();
    let args_end = args.last().map_or(close + 1, |arg| arg.end);
    let call = &masked[close + 1..call_end];
    if call.contains("<<") {
        problem.get_or_insert_with(|| "it takes a heredoc argument".into());
    }
    // A masked literal holds no quote, so its delimiters pair up; one left
    // over opens a string the line does not close.
    if ['"', '\'', '`']
        .iter()
        .any(|quote| call.matches(*quote).count() % 2 == 1)
    {
        problem.get_or_insert_with(|| "a string in it spans lines".into());
    }
    if nests_code_in_interpolation(&text[start..call_end], &masked[start..call_end]) {
        problem.get_or_insert_with(|| "a string in it interpolates quoted code".into());
    }
    Some(Call::Literal(Declaration {
        name: name.to_string(),
        start,
        end: call_end.max(args_end),
        args_end,
        args,
        problem,
    }))
}

/// Whether a literal of `text` (the `x` runs of `masked`) holds an
/// interpolation whose code carries a quote or a brace of its own
/// (`"#{ENV["V"]}"`) or opens a heredoc (`"#{<<~V}"`): the mask ends such a
/// literal at the inner quote, or misses the heredoc's body, so what
/// follows it was not read as it is.
fn nests_code_in_interpolation(text: &str, masked: &str) -> bool {
    let m = masked.as_bytes();
    text.match_indices("#{").any(|(at, _)| {
        m.get(at) == Some(&b'x') && {
            let body = &text[at + 2..];
            let body = &body[..body.find('}').unwrap_or(body.len())];
            body.contains(['"', '\'', '`', '{']) || body.contains("<<")
        }
    })
}

/// The length of a leading Ruby identifier of `s`.
fn ident_len(s: &str) -> usize {
    let bytes = s.as_bytes();
    if !bytes
        .first()
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
    {
        return 0;
    }
    bytes
        .iter()
        .position(|b| !(b.is_ascii_alphanumeric() || *b == b'_'))
        .unwrap_or(bytes.len())
}

/// A value that is one plain string literal (no escape, no interpolation):
/// its contents. `masked` is the code of `text`, offset for offset.
fn plain_string(text: &str, masked: &str) -> Option<String> {
    let lead = masked.len() - masked.trim_start().len();
    let code = masked.trim();
    let quote = code.chars().next().filter(|q| matches!(q, '"' | '\''))?;
    let close = code[1..].find(quote)? + 1;
    let value = text.get(lead + 1..lead + close)?;
    let plain =
        close + 1 == code.len() && !value.contains('\\') && !(quote == '"' && value.contains("#{"));
    plain.then(|| value.to_string())
}

/// One argument: `text` as written, `masked` its code.
fn classify(text: &str, masked: &str) -> ArgKind {
    let option = |key: &str, spelling: &str, value_at: usize| ArgKind::Option {
        key: key.to_string(),
        spelling: spelling.trim_end().to_string(),
        value: plain_string(&text[value_at..], &masked[value_at..]),
    };
    if let Some(quote) = masked.chars().next().filter(|q| matches!(q, '"' | '\'')) {
        let Some(close) = masked[1..].find(quote).map(|i| i + 1) else {
            return ArgKind::Opaque;
        };
        let rest = masked[close + 1..].trim_start();
        let at = masked.len() - rest.len();
        if rest.is_empty() {
            return ArgKind::Version;
        }
        // `"key" => v` or `"key": v` (a quoted-symbol key).
        if rest.starts_with("=>") {
            return option(&text[1..close], &text[..at + 2], at + 2);
        }
        if rest.starts_with(':') && !rest.starts_with("::") && at == close + 1 {
            return option(&text[1..close], &text[..at + 1], at + 1);
        }
        return ArgKind::Opaque;
    }
    // `:key => v`
    if let Some(sym) = masked.strip_prefix(':') {
        let n = ident_len(sym);
        let rest = sym[n..].trim_start();
        if n > 0 && rest.starts_with("=>") {
            let at = masked.len() - rest.len() + 2;
            return option(&text[1..1 + n], &text[..1 + n], at);
        }
        return ArgKind::Opaque;
    }
    // `key: v`
    let n = ident_len(masked);
    if n > 0 && masked[n..].starts_with(':') && !masked[n..].starts_with("::") {
        return option(&text[..n], &text[..n + 1], n + 1);
    }
    if masked.starts_with('*') || masked.starts_with('{') {
        return ArgKind::Dynamic;
    }
    // An array of requirements is no options hash either.
    if masked.starts_with('[') || masked.starts_with("%w") || masked.starts_with("%W") {
        return ArgKind::Version;
    }
    ArgKind::Opaque
}

/// `text` with `, source: "<url>"` appended to `decl`'s arguments.
pub(crate) fn with_source_option(text: &str, decl: &Declaration, url: &str) -> String {
    format!(
        "{}{}{}",
        &text[..decl.args_end],
        source_option(url),
        &text[decl.args_end..]
    )
}

/// The argument the hosted rewriter appends to a declaration.
pub(crate) fn source_option(url: &str) -> String {
    format!(", source: \"{url}\"")
}

/// `text` without the argument `arg` and the comma before it.
pub(crate) fn without_arg(text: &str, arg: &Arg) -> String {
    format!("{}{}", &text[..arg.comma], &text[arg.end..])
}

/// The line the hosted rewriter adds for a gem the manifest does not
/// declare (see [`ADDED_LINE_MARKER`]), without a line ending.
///
/// `require: false`: the gem was not in the manifest, so `Bundler.require`
/// (which a Rails app runs at boot) never loaded it by itself; the gems
/// that depend on it load it. A declaration without the option would have
/// `Bundler.require` load it at boot, which changes what the application
/// does for a gem whose main file has effects of its own.
pub(crate) fn added_line(name: &str, version: &str, url: &str) -> String {
    format!(
        "gem \"{name}\", \"{version}\"{}, require: false {ADDED_LINE_MARKER}",
        source_option(url)
    )
}

/// The byte range of the line holding byte `at`, its line ending included.
fn line_span(text: &str, at: usize) -> (usize, usize) {
    let start = text[..at].rfind('\n').map_or(0, |i| i + 1);
    let end = text[at..].find('\n').map_or(text.len(), |i| at + i + 1);
    (start, end)
}

/// Whether `decl` is a line the hosted rewriter added: a call alone on its
/// line, followed by [`ADDED_LINE_MARKER`].
pub(crate) fn is_added_line(text: &str, decl: &Declaration) -> bool {
    let (start, end) = line_span(text, decl.start);
    decl.end <= end
        && text[start..decl.start].trim().is_empty()
        && text[decl.end..end].trim() == ADDED_LINE_MARKER
}

/// Whether the line `content` (no line ending) carries the marker.
fn is_marked(content: &str) -> bool {
    content.trim_end().ends_with(ADDED_LINE_MARKER)
}

/// `text` with `line` added as its last line. The file keeps its line
/// ending and whether it ends on one, and one blank line separates the
/// added lines from what the user wrote (always written, so that removing
/// the last added line can take it back out).
pub(crate) fn append_line(text: &str, line: &str) -> String {
    let eol = line_endings::terminator(text);
    if text.is_empty() {
        return format!("{line}{eol}");
    }
    let terminated = text.ends_with('\n');
    // The file's last line: an added one takes the next right below it.
    let body = text.strip_suffix('\n').unwrap_or(text);
    let body = body.strip_suffix('\r').unwrap_or(body);
    let last = body.rsplit('\n').next().unwrap_or_default();
    let separator = if is_marked(last) { "" } else { eol };
    if terminated {
        format!("{text}{separator}{line}{eol}")
    } else {
        format!("{text}{eol}{separator}{line}")
    }
}

/// `text` without the added line `decl` ([`is_added_line`]): the line goes,
/// and with the last added line of its run the blank line
/// [`append_line`] wrote before it. A file that did not end on a line
/// ending still does not.
pub(crate) fn without_added_line(text: &str, decl: &Declaration) -> String {
    let mut lines: Vec<String> = text.split_inclusive('\n').map(str::to_string).collect();
    let mut offset = 0;
    let Some(k) = lines.iter().position(|line| {
        offset += line.len();
        decl.start < offset
    }) else {
        return text.to_string();
    };
    let content = |line: &str| line.trim_end_matches(['\r', '\n']).to_string();
    remove_line(&mut lines, k);
    let run_goes_on = lines.get(k).is_some_and(|next| is_marked(&content(next)));
    if k >= 1 && content(&lines[k - 1]).is_empty() && !run_goes_on {
        remove_line(&mut lines, k - 1);
    }
    lines.concat()
}

/// Remove line `k` of a file's `split_inclusive('\n')` lines. Removing a
/// last line that had no line ending leaves the line before it without one.
fn remove_line(lines: &mut Vec<String>, k: usize) {
    let removed = lines.remove(k);
    if k == lines.len() && !removed.ends_with('\n') {
        if let Some(last) = lines.last_mut() {
            if last.ends_with('\n') {
                last.pop();
                if last.ends_with('\r') {
                    last.pop();
                }
            }
        }
    }
}

/// The rubygems sources a manifest names, in the order Bundler < 2.2 lists
/// them as `remote:` lines of its one `GEM` section: each global `source
/// "<url>"` in file order, then each `source "<url>" do` block and `gem …,
/// source: "<url>"` option in the order bundler last meets it. A source
/// that is not a plain string literal is left out, so a caller must check
/// the answer against the lock bundler wrote before relying on it.
pub(crate) fn rubygems_sources(text: &str) -> Vec<String> {
    let masked = masked_source(text);
    let mut global: Vec<String> = Vec::new();
    // (byte offset, url) of each block or option source.
    let mut scoped: Vec<(usize, String)> = Vec::new();
    for (word, start, end) in ruby_words(&masked) {
        if word != "source" {
            continue;
        }
        let line_start = masked[..start].rfind('\n').map_or(0, |i| i + 1);
        let lead = masked[line_start..start].trim();
        let Some(paren) = source_call_args(&masked[end..]) else {
            continue;
        };
        if !(lead.is_empty() || lead.ends_with(';')) {
            continue;
        }
        let line_end = masked[end..].find('\n').map_or(masked.len(), |i| end + i);
        // Past the `(` or the blank that follows the word.
        let args = &masked[end + 1..line_end];
        let arg_at = end + 1 + (args.len() - args.trim_start().len());
        let Some(url) = masked[arg_at..line_end]
            .chars()
            .next()
            .filter(|q| matches!(q, '"' | '\''))
            .and_then(|q| masked[arg_at + 1..line_end].find(q))
            .map(|len| (arg_at + 1, arg_at + 1 + len))
        else {
            continue;
        };
        let value = &text[url.0..url.1];
        if value.contains('\\') || value.contains("#{") {
            continue;
        }
        let rest = masked[url.1 + 1..line_end].trim_start();
        let rest = if paren {
            rest.strip_prefix(')').unwrap_or(rest).trim_start()
        } else {
            rest
        };
        if rest.is_empty() || rest.starts_with(';') {
            global.push(value.to_string());
        } else if rest.starts_with("do") || rest.starts_with('{') {
            scoped.push((start, value.to_string()));
        }
    }
    for decl in declarations(text).literal {
        if let Some((arg, Some(url))) = decl.source() {
            scoped.push((arg.start, url.to_string()));
        }
    }
    scoped.sort_by_key(|(at, _)| *at);
    let mut out: Vec<String> = Vec::new();
    let same = super::same_remote;
    for url in global {
        if !out.iter().any(|seen| same(seen, &url)) {
            out.push(url);
        }
    }
    let globals = out.len();
    for (_, url) in scoped {
        if out[..globals].iter().any(|seen| same(seen, &url)) {
            continue;
        }
        // Bundler moves a source it meets again to the end.
        out.retain(|seen| !same(seen, &url));
        out.push(url);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://patch.test/patch-registry/gem/tok/uuid/";

    fn one(text: &str) -> Declaration {
        let mut all = declarations(text).literal;
        assert_eq!(all.len(), 1, "{text}: {all:?}");
        all.remove(0)
    }

    /// Every form a declaration is written in takes the option after its
    /// last argument, and taking the option off restores the file.
    #[test]
    fn source_option_goes_after_the_last_argument_and_comes_off_again() {
        let cases = [
            (
                "gem \"rack\", \"~> 2.2.3\"       # web server interface\n",
                "gem \"rack\", \"~> 2.2.3\", source: \"URL\"       # web server interface\n",
            ),
            ("gem 'rack'\n", "gem 'rack', source: \"URL\"\n"),
            ("gem 'rack'", "gem 'rack', source: \"URL\""),
            (
                "gem(\"jmespath\", \"1.4.0\")\n",
                "gem(\"jmespath\", \"1.4.0\", source: \"URL\")\n",
            ),
            ("gem( 'rack' ) # x\n", "gem( 'rack', source: \"URL\" ) # x\n"),
            (
                "gem(\"rack\",\n    \"2.2.3\",\n)\n",
                "gem(\"rack\",\n    \"2.2.3\", source: \"URL\",\n)\n",
            ),
            (
                "gem \"puma\",\n    \"4.3.5\",\n    require: false\n",
                "gem \"puma\",\n    \"4.3.5\",\n    require: false, source: \"URL\"\n",
            ),
            (
                "gem \"puma\", # app server\n    \"4.3.5\", # pinned\n    require: false # lazy\nx\n",
                "gem \"puma\", # app server\n    \"4.3.5\", # pinned\n    require: false, source: \"URL\" # lazy\nx\n",
            ),
            (
                "gem \"puma\", \\\n  \"4.3.5\"\n",
                "gem \"puma\", \\\n  \"4.3.5\", source: \"URL\"\n",
            ),
            (
                "gem \"rack\", \"~> 2.2\" \\\n\ngem \"puma\"\n",
                "gem \"rack\", \"~> 2.2\", source: \"URL\" \\\n\ngem \"puma\"\n",
            ),
            (
                "gem \"rack\", \"~> 2.2\" \\\r\n# note\r\ngem \"puma\"\r\n",
                "gem \"rack\", \"~> 2.2\", source: \"URL\" \\\r\n# note\r\ngem \"puma\"\r\n",
            ),
            (
                "gem 'rexml', '>= 3.2.4', '< 3.2.5', group: :test\r\n",
                "gem 'rexml', '>= 3.2.4', '< 3.2.5', group: :test, source: \"URL\"\r\n",
            ),
            (
                "group :development do\n  gem \"rack\", platforms: %i[mri windows], require: %w[rack rack/lint]\nend\n",
                "group :development do\n  gem \"rack\", platforms: %i[mri windows], require: %w[rack rack/lint], source: \"URL\"\nend\n",
            ),
            (
                "gem \"rack\", \"2.2.3\" if RUBY_VERSION >= \"3\"\n",
                "gem \"rack\", \"2.2.3\", source: \"URL\" if RUBY_VERSION >= \"3\"\n",
            ),
            (
                "gem \"rack\" unless ENV[\"SKIP\"] # why\n",
                "gem \"rack\", source: \"URL\" unless ENV[\"SKIP\"] # why\n",
            ),
            (
                "gem(\"rack\", \"2.2.3\") if x\n",
                "gem(\"rack\", \"2.2.3\", source: \"URL\") if x\n",
            ),
            (
                "gem \"rack\", \"2.2.3\"; gem \"puma\"\n",
                "gem \"rack\", \"2.2.3\", source: \"URL\"; gem \"puma\"\n",
            ),
            (
                "gem \"rack\", :require => false, \"group\" => :test\n",
                "gem \"rack\", :require => false, \"group\" => :test, source: \"URL\"\n",
            ),
            (
                "gem \"rack\", require: \"if x\", install_if: -> { RUBY_VERSION > \"3\" }\n",
                "gem \"rack\", require: \"if x\", install_if: -> { RUBY_VERSION > \"3\" }, source: \"URL\"\n",
            ),
            (
                "gem \"rack\", \"~> #{RACK}\", require: %w<rack rack/lint>\ngem \"puma\"\n",
                "gem \"rack\", \"~> #{RACK}\", require: %w<rack rack/lint>, source: \"URL\"\ngem \"puma\"\n",
            ),
            (
                "gem(\"rack\", require:\n  false)\n",
                "gem(\"rack\", require:\n  false, source: \"URL\")\n",
            ),
        ];
        for (before, after) in cases {
            let after = after.replace("URL", URL);
            let decls = declarations(before);
            let decl = &decls.literal[0];
            assert_eq!(decl.problem, None, "{before}");
            let edited = with_source_option(before, decl, URL);
            assert_eq!(edited, after, "{before}");
            // Read back, the option is the call's source and comes off.
            let again = declarations(&edited);
            let decl = again.literal.iter().find(|d| d.source().is_some()).unwrap();
            let (arg, url) = decl.source().unwrap();
            assert_eq!(url, Some(URL), "{edited}");
            assert_eq!(without_arg(&edited, arg), before, "{edited}");
        }
    }

    /// A `\` continues a call onto the next physical line only, so a blank
    /// or comment-only line after it ends the call and the next `gem` is
    /// its own declaration (Ruby reads these as two calls).
    #[test]
    fn a_backslash_continues_one_line_only() {
        for text in [
            "gem 'rack', '~> 2.2' \\\n\ngem 'puma'\n",
            "gem 'rack', '~> 2.2' \\\n# note\ngem 'puma'\n",
            "gem 'rack', '~> 2.2' \\\r\n\r\ngem 'puma'\r\n",
        ] {
            let decls = declarations(text).literal;
            assert_eq!(decls.len(), 2, "{text:?}: {decls:?}");
            assert_eq!(decls[0].positionals().count(), 1, "{text:?}");
            assert_eq!(decls[1].positionals().count(), 0, "{text:?}");
        }
        // A `\` straight onto the next argument still carries the call.
        assert_eq!(one("gem 'rack', \\\n  '~> 2.2'\n").positionals().count(), 1);
    }

    /// What is not code declares nothing, and neither does a local variable
    /// or another method of that name.
    #[test]
    fn only_code_declares() {
        for text in [
            "# gem \"rack\"\n",
            "=begin\ngem \"rack\"\n=end\n",
            "x = <<~EOS\n  gem \"rack\"\nEOS\n",
            "puts \"gem 'rack'\"\n",
            "__END__\ngem \"rack\"\n",
            "gem = \"rack\"\n",
            "gem.name\n",
            "spec.gem \"rack\"\n",
            "gemspec\n",
            "gem_group \"rack\"\n",
            "x = { gem: \"rack\" }\n",
            "gem\n",
        ] {
            let all = declarations(text);
            assert!(all.literal.is_empty() && !all.dynamic, "{text}: {all:?}");
        }
        // A name that is not a plain literal is a call nobody can attribute.
        for text in [
            "gem name\n",
            "gem *args\n",
            "gem \"#{prefix}-core\"\n",
            "gem(name, \"1.0\")\n",
            "%w[a b].each { |g| gem g }\n",
            "gem :rack\n",
        ] {
            let all = declarations(text);
            assert!(all.literal.is_empty() && all.dynamic, "{text}: {all:?}");
        }
    }

    /// The arguments are read in all of Ruby's option spellings, and a
    /// positional whose value is unknown is told from a version literal.
    #[test]
    fn arguments_are_classified() {
        let decl = one(
            "gem \"rack\", \"~> 2\", VERSION, require: false, :git => \"https://x/y.git\", \"branch\": \"main\", **opts\n",
        );
        let kinds: Vec<String> = decl
            .args
            .iter()
            .map(|a| match &a.kind {
                ArgKind::Version => "version".to_string(),
                ArgKind::Opaque => "opaque".to_string(),
                ArgKind::Dynamic => "dynamic".to_string(),
                ArgKind::Option {
                    key,
                    spelling,
                    value,
                } => {
                    format!("{key}|{spelling}|{}", value.as_deref().unwrap_or("-"))
                }
            })
            .collect();
        assert_eq!(
            kinds,
            [
                "version",
                "opaque",
                "require|require:|-",
                "git|:git|https://x/y.git",
                "branch|\"branch\":|main",
                "dynamic"
            ]
        );
        assert_eq!(decl.source_selecting(), Some(":git"));
        let text = "gem \"rack\", OPTS\n";
        assert_eq!(one(text).opaque_last(text), Some("OPTS"));
        let text = "gem \"rack\", VERSION, require: false\n";
        assert_eq!(one(text).opaque_last(text), None);
        let text = "gem \"rack\", \"1.0\", source: \"https://a.example/\"\n";
        let decl = one(text);
        assert_eq!(decl.source().unwrap().1, Some("https://a.example/"));
        assert_eq!(decl.source_selecting(), Some("source:"));
        // A value that is not one plain literal is not read as a URL.
        for text in [
            "gem \"rack\", source: SOCKET\n",
            "gem \"rack\", source: \"https://#{HOST}/\"\n",
            "gem \"rack\", source: \"https://a.example/\" + PATH\n",
        ] {
            assert_eq!(one(text).source().unwrap().1, None, "{text}");
        }
    }

    /// A call the reader cannot follow to its end is never edited.
    #[test]
    fn calls_it_cannot_follow_carry_a_problem() {
        for text in [
            "group(:test) { gem \"rack\" }\n",
            "group :test do gem \"rack\" end\n",
            "gem \"rack\" do\nend\n",
            "gem \"rack\", <<~V\n  1.0\nV\n",
            "gem \"rack\", \"~> #{ENV[\"V\"]}\"\n",
            "gem \"rack\" \"1.0\"\n",
            "gem \"rack\", \"1.0\" and x\n",
            "gem(\"rack\", \"1.0\"\n",
            "gem(\"rack\").tap { }\n",
            "gem \"rack\", if x then \"1\" else \"2\" end\n",
            "gem \"rack\",\n",
            "gem \"rack\", require:\n  false\n",
            "gem \"rack\", \"1.0\" +\n  SUFFIX\n",
            "gem \"rack\", \"group\" =>\n  :test\n",
        ] {
            let decl = one(text);
            assert!(decl.problem.is_some(), "{text}: {decl:?}");
        }
    }

    /// The added line is recognized by its marker, and removing it restores
    /// the file, whatever its line ending and final-newline state.
    #[test]
    fn added_lines_round_trip() {
        let line = |name: &str| added_line(name, "1.0.0", URL);
        for original in [
            "",
            "source \"https://rubygems.org\"\n\ngem \"sinatra\"\n",
            "source \"https://rubygems.org\"\n\ngem \"sinatra\"",
            "source \"https://rubygems.org\"\r\n\r\ngem \"sinatra\"\r\n",
            "source \"https://rubygems.org\"\r\n\r\ngem \"sinatra\"",
            "gem \"sinatra\"\n\n",
            "gem \"sinatra\"\n\n\n",
        ] {
            let eol = if original.contains("\r\n") {
                "\r\n"
            } else {
                "\n"
            };
            let one_added = append_line(original, &line("rack"));
            let two_added = append_line(&one_added, &line("tiny-dep"));
            if original.is_empty() {
                assert_eq!(one_added, format!("{}\n", line("rack")));
            } else if original.ends_with('\n') {
                assert_eq!(one_added, format!("{original}{eol}{}{eol}", line("rack")));
                assert_eq!(
                    two_added,
                    format!(
                        "{original}{eol}{}{eol}{}{eol}",
                        line("rack"),
                        line("tiny-dep")
                    )
                );
            } else {
                assert_eq!(one_added, format!("{original}{eol}{eol}{}", line("rack")));
                assert_eq!(
                    two_added,
                    format!(
                        "{original}{eol}{eol}{}{eol}{}",
                        line("rack"),
                        line("tiny-dep")
                    )
                );
            }
            let find = |text: &str, name: &str| {
                let decls = declarations(text);
                let decl = decls.of(name).next().unwrap().clone();
                assert!(is_added_line(text, &decl), "{text:?}");
                decl
            };
            // Either order of removal ends on the original bytes.
            for order in [["rack", "tiny-dep"], ["tiny-dep", "rack"]] {
                let mut text = two_added.clone();
                for name in order {
                    let decl = find(&text, name);
                    text = without_added_line(&text, &decl);
                }
                assert_eq!(text, original, "{original:?} {order:?}");
            }
            let decl = find(&one_added, "rack");
            assert_eq!(
                without_added_line(&one_added, &decl),
                original,
                "{original:?}"
            );
        }
        // The user's own declaration with the option appended is no added line.
        let text = format!("gem \"rack\", \"1.0.0\"{}\n", source_option(URL));
        assert!(!is_added_line(&text, &one(&text)));
    }

    /// Bundler < 2.2 lists the global sources first, then each block or
    /// option source in the order it last meets it.
    #[test]
    fn rubygems_sources_follow_bundlers_remote_order() {
        let text = "source \"https://rubygems.org\"\n\
                    gem \"b\", source: \"https://b.example/\"\n\
                    source \"https://block.example\" do\n  gem \"c\"\nend\n\
                    gem \"a\", source: \"https://a.example/\"\n\
                    gem \"b2\", source: \"https://b.example/\"\n\
                    source(\"https://second.example\")\n\
                    gem \"d\", source: COMPUTED\n";
        assert_eq!(
            rubygems_sources(text),
            [
                "https://rubygems.org",
                "https://second.example",
                "https://block.example",
                "https://a.example/",
                "https://b.example/",
            ]
        );
    }
}
