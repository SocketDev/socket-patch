//! Reader for the file a tracked `--downloader_config` names (design 2.6):
//! would Bazel's downloader still fetch a patch URL?
//!
//! Bazel decides in a fixed order, and so does [`DownloaderConfig::amend`]
//! (a port of `UrlRewriter.java`, which agrees with real Bazel on the 34
//! cases of probe T3): every `rewrite` whose pattern matches the whole URL
//! without its scheme contributes a URL, then on each resulting host an
//! `allow` entry (the host or a parent domain) wins over a `block` entry
//! (`*` = any host). So `block *` with `allow patch.socket.dev` fetches,
//! and a rewrite to a mirror is judged by the mirror's host.
//!
//! [`verdict`] applies that to the config files the tracked rc files
//! name. It fails closed: a file that is missing, unreadable or that
//! Bazel would reject, and a `rewrite` this file cannot evaluate, all
//! count as blocked.
//!
//! The `regex` crate cannot evaluate the patterns: they are Java regular
//! expressions, and the usual recipe needs a lookahead
//! (`rewrite ((?!127\.0\.0\.1[:/]).*) http://127.0.0.1:8080/$1`). A small
//! backtracking matcher covers the constructs such files use; any other
//! construct makes the rewrite, and with it the URL, unevaluable. Where
//! Bazel releases differ (how `$1` is substituted, host case), a result
//! is given only when every release agrees.

use std::cell::Cell;

use super::model::{FileText, FileView};
use super::rc::{root_relative, Chain, EffectiveFlags, Flag, Occurrence, PLAIN};
use super::version::{BazelLine, BazelVersion, Tri};

// ── Patterns ─────────────────────────────────────────────────────────

/// A `rewrite` pattern, in the subset of `java.util.regex` evaluated
/// here: literals, `.`, classes, `\d \w \s` and their negations, groups
/// (capturing and `(?:)`), `|`, the greedy and lazy quantifiers, `^`, `$`
/// and lookahead.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Text(Vec<char>),
    Any,
    /// Inclusive ranges, and whether the class is negated.
    Class(Vec<(char, char)>, bool),
    Start,
    End,
    /// `Some(n)`: capturing group `n`.
    Group(Option<usize>, Box<Node>),
    /// A lookahead; `true` when negative.
    Look(Box<Node>, bool),
    Seq(Vec<Node>),
    Alt(Vec<Node>),
    /// `min`, `max`, and whether it is greedy.
    Repeat(Box<Node>, u32, Option<u32>, bool),
}

const DIGIT: &[(char, char)] = &[('0', '9')];
const WORD: &[(char, char)] = &[('a', 'z'), ('A', 'Z'), ('0', '9'), ('_', '_')];
const BLANK: &[(char, char)] = &[(' ', ' '), ('\t', '\r')];

/// Patterns and URLs past these sizes are not evaluated. The matcher
/// recurses once per pattern element, and the Windows main thread has a
/// 1 MiB stack.
const MAX_PATTERN: usize = 512;
const MAX_URL: usize = 8192;
const MAX_DEPTH: u32 = 192;
const MAX_STEPS: u32 = 200_000;

struct Parser<'a> {
    chars: &'a [char],
    at: usize,
    groups: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.at).copied()
    }

    fn eat(&mut self, expected: char) -> bool {
        let hit = self.peek() == Some(expected);
        self.at += usize::from(hit);
        hit
    }

    /// `a|b|c`.
    fn alternation(&mut self) -> Option<Node> {
        let mut branches = vec![self.sequence()?];
        while self.eat('|') {
            branches.push(self.sequence()?);
        }
        Some(match branches.len() {
            1 => branches.remove(0),
            _ => Node::Alt(branches),
        })
    }

    fn sequence(&mut self) -> Option<Node> {
        let mut nodes: Vec<Node> = Vec::new();
        while self.peek().is_some_and(|c| c != '|' && c != ')') {
            let atom = self.atom()?;
            let node = self.quantified(atom)?;
            // Runs of literals are compared at once, so a long literal
            // prefix costs no recursion.
            match (nodes.last_mut(), node) {
                (Some(Node::Text(run)), Node::Text(more)) => run.extend(more),
                (_, node) => nodes.push(node),
            }
        }
        Some(Node::Seq(nodes))
    }

    fn quantified(&mut self, atom: Node) -> Option<Node> {
        let (min, max) = match self.peek() {
            Some('*') => (0, None),
            Some('+') => (1, None),
            Some('?') => (0, Some(1)),
            Some('{') => {
                let close = self.chars[self.at..].iter().position(|c| *c == '}')?;
                let body: String = self.chars[self.at + 1..self.at + close].iter().collect();
                self.at += close;
                let number = |text: &str| {
                    let digits = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
                    digits.then(|| text.parse::<u32>().ok())?
                };
                match body.split_once(',') {
                    None => (number(&body)?, Some(number(&body)?)),
                    Some((min, "")) => (number(min)?, None),
                    Some((min, max)) => (number(min)?, Some(number(max)?)),
                }
            }
            _ => return Some(atom),
        };
        self.at += 1;
        // Nothing to repeat, an inverted range, a possessive quantifier
        // and a second quantifier are errors in Java or outside the
        // subset.
        let repeatable = !matches!(atom, Node::Start | Node::End | Node::Look(..));
        if !repeatable || max.is_some_and(|max| max < min) {
            return None;
        }
        let greedy = !self.eat('?');
        let stacked = matches!(self.peek(), Some('*' | '+' | '?' | '{'));
        (!stacked).then(|| Node::Repeat(Box::new(atom), min, max, greedy))
    }

    fn atom(&mut self) -> Option<Node> {
        let c = self.peek()?;
        self.at += 1;
        Some(match c {
            '.' => Node::Any,
            '^' => Node::Start,
            '$' => Node::End,
            '[' => self.class()?,
            '(' => self.group()?,
            '\\' => self.escape()?,
            // A quantifier with nothing before it.
            '*' | '+' | '?' | '{' => return None,
            c => Node::Text(vec![c]),
        })
    }

    fn group(&mut self) -> Option<Node> {
        let node = if self.eat('?') {
            let kind = self.peek()?;
            self.at += 1;
            let inner = Box::new(self.alternation()?);
            match kind {
                ':' => Node::Group(None, inner),
                '=' => Node::Look(inner, false),
                '!' => Node::Look(inner, true),
                // Named groups, lookbehind, flags, atomic groups.
                _ => return None,
            }
        } else {
            self.groups += 1;
            let index = self.groups;
            Node::Group(Some(index), Box::new(self.alternation()?))
        };
        self.eat(')').then_some(node)
    }

    /// A backslash escape outside a class. Java reserves every escaped
    /// letter and digit; only the ones below are evaluated.
    fn escape(&mut self) -> Option<Node> {
        let c = self.peek()?;
        self.at += 1;
        Some(match c {
            'd' => Node::Class(DIGIT.to_vec(), false),
            'D' => Node::Class(DIGIT.to_vec(), true),
            'w' => Node::Class(WORD.to_vec(), false),
            'W' => Node::Class(WORD.to_vec(), true),
            's' => Node::Class(BLANK.to_vec(), false),
            'S' => Node::Class(BLANK.to_vec(), true),
            c if c.is_alphanumeric() => return None,
            c => Node::Text(vec![c]),
        })
    }

    /// `[...]`: literals, ranges and `\d \w \s`. A nested class, an
    /// intersection and a leading `]` are outside the subset.
    fn class(&mut self) -> Option<Node> {
        let negated = self.eat('^');
        let mut ranges: Vec<(char, char)> = Vec::new();
        if self.peek() == Some(']') {
            return None;
        }
        loop {
            let c = self.peek()?;
            self.at += 1;
            let low = match c {
                ']' => return Some(Node::Class(ranges, negated)),
                '[' => return None,
                '&' if self.peek() == Some('&') => return None,
                '\\' => match self.escape()? {
                    Node::Class(set, false) => {
                        ranges.extend(set);
                        continue;
                    }
                    Node::Text(text) => text[0],
                    _ => return None,
                },
                c => c,
            };
            let range = self.peek() == Some('-') && self.chars.get(self.at + 1) != Some(&']');
            let high = if range {
                self.at += 1;
                match self.peek()? {
                    '[' | '\\' => return None,
                    high => {
                        self.at += 1;
                        high
                    }
                }
            } else {
                low
            };
            if high < low {
                return None;
            }
            ranges.push((low, high));
        }
    }
}

/// The compiled form of `pattern` and its number of capturing groups, or
/// `None` when it is malformed or uses a construct outside the subset.
fn compile(pattern: &str) -> Option<(Node, usize)> {
    let chars: Vec<char> = pattern.chars().collect();
    if chars.len() > MAX_PATTERN {
        return None;
    }
    let mut parser = Parser {
        chars: &chars,
        at: 0,
        groups: 0,
    };
    let node = parser.alternation()?;
    (parser.at == chars.len()).then_some((node, parser.groups))
}

type Captures = Vec<Option<(usize, usize)>>;
type Then<'a> = &'a mut dyn FnMut(usize, &mut Captures) -> bool;

/// A backtracking matcher with Java's priorities: alternatives left to
/// right, greedy quantifiers longest first. It stops, and says so
/// (`exhausted`), when a match costs more than the budget or reaches a
/// case it does not decide.
struct Matcher<'a> {
    input: &'a [char],
    steps: Cell<u32>,
    depth: Cell<u32>,
    exhausted: Cell<bool>,
}

impl Matcher<'_> {
    /// Whether `node` matches exactly the one character `c`.
    fn one(node: &Node, c: char) -> bool {
        match node {
            Node::Any => true,
            Node::Class(ranges, negated) => {
                ranges.iter().any(|(low, high)| (*low..=*high).contains(&c)) != *negated
            }
            Node::Text(text) => text[..] == [c],
            _ => false,
        }
    }

    /// Whether `node` always consumes one character.
    fn single(node: &Node) -> bool {
        match node {
            Node::Any | Node::Class(..) => true,
            Node::Text(text) => text.len() == 1,
            _ => false,
        }
    }

    fn run(&self, node: &Node, at: usize, caps: &mut Captures, then: Then<'_>) -> bool {
        self.steps.set(self.steps.get() + 1);
        if self.steps.get() > MAX_STEPS || self.depth.get() > MAX_DEPTH {
            self.exhausted.set(true);
        }
        if self.exhausted.get() {
            return false;
        }
        self.depth.set(self.depth.get() + 1);
        let hit = self.step(node, at, caps, then);
        self.depth.set(self.depth.get() - 1);
        hit
    }

    fn step(&self, node: &Node, at: usize, caps: &mut Captures, then: Then<'_>) -> bool {
        match node {
            Node::Text(text) => self.input[at..].starts_with(text) && then(at + text.len(), caps),
            Node::Any | Node::Class(..) => {
                let hit = self.input.get(at).is_some_and(|c| Self::one(node, *c));
                hit && then(at + 1, caps)
            }
            Node::Start => at == 0 && then(at, caps),
            Node::End => at == self.input.len() && then(at, caps),
            Node::Group(None, inner) => self.run(inner, at, caps, then),
            Node::Group(Some(index), inner) => self.run(inner, at, caps, &mut |end, caps| {
                let before = caps[*index];
                caps[*index] = Some((at, end));
                let hit = then(end, caps);
                if !hit {
                    caps[*index] = before;
                }
                hit
            }),
            Node::Look(inner, negative) => {
                // A lookahead is atomic, and only a positive one keeps
                // the groups it captured.
                let mut inside = caps.clone();
                let mut kept = None;
                let found = self.run(inner, at, &mut inside, &mut |_, caps| {
                    kept = Some(caps.clone());
                    true
                });
                match (found, negative, kept) {
                    (false, true, _) => then(at, caps),
                    (true, false, Some(kept)) => {
                        let before = std::mem::replace(caps, kept);
                        let hit = then(at, caps);
                        if !hit {
                            *caps = before;
                        }
                        hit
                    }
                    _ => false,
                }
            }
            Node::Seq(nodes) => self.sequence(nodes, at, caps, then),
            Node::Alt(branches) => branches.iter().any(|b| self.run(b, at, caps, then)),
            Node::Repeat(inner, min, max, greedy) if Self::single(inner) => {
                // One character per iteration: counted in a loop, so a
                // long URL costs no recursion.
                let limit = max.map_or(usize::MAX, |max| max as usize);
                let rest = &self.input[at..];
                let run = rest
                    .iter()
                    .take(limit)
                    .take_while(|c| Self::one(inner, **c));
                let (min, most) = (*min as usize, run.count());
                if most < min {
                    false
                } else if *greedy {
                    (min..=most).rev().any(|n| then(at + n, caps))
                } else {
                    (min..=most).any(|n| then(at + n, caps))
                }
            }
            Node::Repeat(inner, min, max, greedy) => {
                self.repeat((inner, *min, *max, *greedy), 0, at, caps, then)
            }
        }
    }

    fn sequence(&self, nodes: &[Node], at: usize, caps: &mut Captures, then: Then<'_>) -> bool {
        match nodes.split_first() {
            None => then(at, caps),
            Some((first, rest)) => self.run(first, at, caps, &mut |next, caps| {
                self.sequence(rest, next, caps, then)
            }),
        }
    }

    /// One more iteration of a repeated group, then the rest of the loop.
    /// An iteration of a real loop that consumes nothing is where regex
    /// engines part ways on what the groups hold, so it is not evaluated;
    /// `(x)?` has no such case.
    fn again(
        &self,
        spec: (&Node, u32, Option<u32>, bool),
        count: u32,
        at: usize,
        caps: &mut Captures,
        then: Then<'_>,
    ) -> bool {
        self.run(spec.0, at, caps, &mut |next, caps| {
            if next == at && spec.2 != Some(1) {
                self.exhausted.set(true);
                return false;
            }
            self.repeat(spec, count + 1, next, caps, then)
        })
    }

    fn repeat(
        &self,
        spec: (&Node, u32, Option<u32>, bool),
        count: u32,
        at: usize,
        caps: &mut Captures,
        then: Then<'_>,
    ) -> bool {
        let (_, min, max, greedy) = spec;
        let more = max.is_none_or(|max| count < max);
        if count < min {
            self.again(spec, count, at, caps, then)
        } else if greedy {
            (more && self.again(spec, count, at, caps, then)) || then(at, caps)
        } else {
            then(at, caps) || (more && self.again(spec, count, at, caps, then))
        }
    }
}

/// How a pattern matches `input` from its first character: the end and
/// groups of the first match in priority order (what `Matcher.find`
/// reports), or of the first one that covers the whole input (what
/// `Matcher.matches` reports). `Err` when the budget ran out.
fn find(
    node: &Node,
    groups: usize,
    input: &[char],
    whole: bool,
) -> Result<Option<(usize, Captures)>, ()> {
    let matcher = Matcher {
        input,
        steps: Cell::new(0),
        depth: Cell::new(0),
        exhausted: Cell::new(false),
    };
    let mut caps: Captures = vec![None; groups + 1];
    let mut found = None;
    matcher.run(node, 0, &mut caps, &mut |end, caps| {
        let hit = !whole || end == input.len();
        if hit {
            found = Some((end, caps.clone()));
        }
        hit
    });
    if matcher.exhausted.get() {
        Err(())
    } else {
        Ok(found)
    }
}

/// One piece of a `rewrite` replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    Text(String),
    Group(usize),
}

/// A replacement in the grammar every Bazel release reads the same way:
/// text, `\c` for a literal `c`, and `$N` with every following digit part
/// of `N`. `${...}`, `urlencode(` (Bazel 10), a group the pattern does not
/// have and a bare `$` or trailing `\` are read differently by different
/// releases, or stop Bazel.
fn replacement(text: &str, groups: usize) -> Option<Vec<Piece>> {
    if text.contains("urlencode(") {
        return None;
    }
    let mut pieces = Vec::new();
    let mut literal = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => literal.push(chars.next()?),
            '$' => {
                let mut digits = String::new();
                while let Some(digit) = chars.next_if(char::is_ascii_digit) {
                    digits.push(digit);
                }
                let group: usize = digits.parse().ok()?;
                if group > groups {
                    return None;
                }
                pieces.push(Piece::Text(std::mem::take(&mut literal)));
                pieces.push(Piece::Group(group));
            }
            c => literal.push(c),
        }
    }
    pieces.push(Piece::Text(literal));
    Some(pieces)
}

// ── The config file ──────────────────────────────────────────────────

/// One `rewrite` line.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rewrite {
    pattern: String,
    /// `None`: the line cannot be evaluated statically.
    program: Option<(Node, usize, Vec<Piece>)>,
}

/// A line Bazel rejects. Bazel then stops every fetch, so the caller
/// treats the file as blocking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// 1-based line.
    pub line: usize,
    pub detail: String,
}

/// What a downloader config does to one URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Amended {
    /// The URLs Bazel tries, in order. Empty: every one is blocked.
    Urls(Vec<String>),
    /// The outcome cannot be decided statically; it counts as blocked.
    Unevaluable(String),
}

/// A parsed downloader config: one file, or on Bazel 10 the union of
/// several.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DownloaderConfig {
    pub allow: Vec<String>,
    pub block: Vec<String>,
    rewrites: Vec<Rewrite>,
    pub all_blocked_message: Option<String>,
}

impl DownloaderConfig {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let mut config = Self::default();
        config.add(text)?;
        Ok(config)
    }

    /// Adds the lines of one more file (`UrlRewriterConfig.parseConfig`).
    /// Lines end at LF, CR or CRLF; words are separated by whitespace; a
    /// line whose first word starts with `#` is a comment. A BOM is not
    /// skipped, so Bazel rejects the file's first line.
    pub fn add(&mut self, text: &str) -> Result<(), ConfigError> {
        let unified = text.replace("\r\n", "\n");
        for (index, line) in unified.split(['\n', '\r']).enumerate() {
            let blank = |c: char| matches!(c, ' ' | '\t' | '\x0b' | '\x0c');
            let words: Vec<&str> = line.split(blank).filter(|word| !word.is_empty()).collect();
            let error = |detail: &str| ConfigError {
                line: index + 1,
                detail: format!("{detail}: {line}"),
            };
            match words[..] {
                [] => {}
                [first, ..] if first.starts_with('#') => {}
                ["allow", host] => self.allow.push(host.to_string()),
                ["block", host] => self.block.push(host.to_string()),
                ["allow" | "block", ..] => return Err(error("one host name is expected")),
                ["rewrite", pattern, to] => {
                    let program = compile(pattern)
                        .and_then(|(node, groups)| Some((node, groups, replacement(to, groups)?)));
                    self.rewrites.push(Rewrite {
                        pattern: pattern.to_string(),
                        program,
                    });
                }
                ["rewrite", ..] => return Err(error("a pattern and a replacement are expected")),
                ["all_blocked_message", _, ..] if self.all_blocked_message.is_none() => {
                    // Bazel cuts the line at a fixed offset, indented or not.
                    let message = line.get("all_blocked_message".len() + 1..);
                    self.all_blocked_message = Some(message.unwrap_or_default().to_string());
                }
                ["all_blocked_message", ..] => {
                    return Err(error("one message is expected, once"));
                }
                _ => return Err(error("Bazel cannot parse this line")),
            }
        }
        Ok(())
    }

    /// What Bazel's downloader does with `url` (`UrlRewriter.rewrite`).
    /// A URL that is not `http` or `https` is neither rewritten nor
    /// checked.
    pub fn amend(&self, url: &str) -> Amended {
        let scheme = url
            .split_once(':')
            .map(|(scheme, _)| scheme)
            .filter(|scheme| {
                let legal = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.');
                scheme.starts_with(|c: char| c.is_ascii_alphabetic()) && scheme.bytes().all(legal)
            });
        let Some(scheme) = scheme else {
            return Amended::Unevaluable(format!("{url} is not a URL with a scheme"));
        };
        if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
            return Amended::Urls(vec![url.to_string()]);
        }
        let Some(rest) = url[scheme.len()..].strip_prefix("://") else {
            return Amended::Unevaluable(format!("{url} has no host"));
        };
        // Bazel 10 lower-cases the host before matching and older
        // releases do not.
        let lower = |host: String| {
            host.bytes()
                .all(|b| !b.is_ascii_uppercase())
                .then_some(host)
        };
        if host_of(url).and_then(lower).is_none() {
            return Amended::Unevaluable(format!("{url} has no lower-case host name"));
        }
        let mut candidates: Vec<String> = Vec::new();
        for rewrite in &self.rewrites {
            match rewrite.apply(rest) {
                Err(why) => return Amended::Unevaluable(why),
                Ok(None) => {}
                Ok(Some(rewritten)) => {
                    let absolute = ["http://", "https://"]
                        .iter()
                        .any(|s| rewritten.starts_with(s));
                    let full = match absolute {
                        true => rewritten,
                        false => format!("{scheme}://{rewritten}"),
                    };
                    if !candidates.contains(&full) {
                        candidates.push(full);
                    }
                }
            }
        }
        if candidates.is_empty() {
            candidates.push(url.to_string());
        }
        let mut urls = Vec::new();
        for candidate in candidates {
            let Some(host) = host_of(&candidate) else {
                let why = format!("the rewritten URL {candidate} has no host name to check");
                return Amended::Unevaluable(why);
            };
            // Bazel 10 compares hosts without regard to case and older
            // releases do not: an `allow` must match as written, a
            // `block` matches either way.
            let under = |entry: &str, host: &str| {
                host == entry
                    || host
                        .strip_suffix(entry)
                        .is_some_and(|sub| sub.ends_with('.'))
            };
            let allowed = self.allow.iter().any(|entry| under(entry, &host));
            let folded = host.to_ascii_lowercase();
            let blocked = self
                .block
                .iter()
                .any(|entry| entry == "*" || under(&entry.to_ascii_lowercase(), &folded));
            if allowed || !blocked {
                urls.push(candidate);
            }
        }
        Amended::Urls(urls)
    }
}

impl Rewrite {
    /// The URL `rest` (a URL without its scheme) is rewritten to, `None`
    /// when the pattern does not match all of it.
    fn apply(&self, rest: &str) -> Result<Option<String>, String> {
        let unevaluable = |why: &str| format!("`rewrite {}` {why}", self.pattern);
        let Some((node, groups, pieces)) = &self.program else {
            return Err(unevaluable("cannot be evaluated statically"));
        };
        let input: Vec<char> = rest.chars().collect();
        let terminator = |c: &char| matches!(c, '\n' | '\r' | '\u{85}' | '\u{2028}' | '\u{2029}');
        if input.len() > MAX_URL || input.iter().any(terminator) {
            return Err(unevaluable("is not evaluated on this URL"));
        }
        let costly = |()| unevaluable("costs too much to evaluate");
        let Some((end, caps)) = find(node, *groups, &input, false).map_err(costly)? else {
            return Ok(None);
        };
        if end != input.len() {
            // Bazel through 9 substitutes into the first match and keeps
            // the rest of the URL; Bazel 10 substitutes into the whole
            // match. They agree only when the two are one match.
            return match find(node, *groups, &input, true).map_err(costly)? {
                Some(_) => Err(unevaluable("matches this URL in more than one way")),
                None => Ok(None),
            };
        }
        let mut out = String::new();
        for piece in pieces {
            match piece {
                Piece::Text(text) => out.push_str(text),
                Piece::Group(0) => out.push_str(rest),
                Piece::Group(index) => {
                    let (start, end) = caps[*index].unwrap_or((0, 0));
                    out.extend(&input[start..end]);
                }
            }
        }
        Ok(Some(out))
    }
}

/// The host of an `http` or `https` URL, where every Java URL class Bazel
/// has used agrees on it: letters, digits, `-` and `.`, or a bracketed
/// IPv6 literal.
fn host_of(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = match host_port.strip_prefix('[') {
        Some(v6) => {
            let (inside, port) = v6.split_once(']')?;
            let legal = |b: u8| b.is_ascii_hexdigit() || b == b':' || b == b'.';
            let port_ok = port.is_empty() || port.starts_with(':');
            (port_ok && inside.bytes().all(legal)).then(|| format!("[{inside}]"))?
        }
        None => {
            let name = host_port.split(':').next()?;
            let legal = |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'.';
            (!name.is_empty() && name.bytes().all(legal)).then(|| name.to_string())?
        }
    };
    Some(host)
}

// ── The tracked configs ──────────────────────────────────────────────

/// Whether Bazel's downloader still fetches a URL, given the downloader
/// configs the tracked rc files name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No tracked rc file names a downloader config.
    NoConfig,
    /// Under every config a build may run with, the URL is fetched from
    /// one of these (the URL itself unless a `rewrite` moves it).
    Fetchable { urls: Vec<String> },
    /// Some config a build may run with blocks the URL, or cannot be
    /// read or evaluated.
    Blocked { config: String, why: String },
}

/// The verdict for `url` on the `build`, `test` and `fetch` chains.
///
/// Through Bazel 9 the last `--downloader_config` replaces the others; on
/// Bazel 10 (and on 9.1.0, by an accident 9.1.1 reverted) every one
/// applies together. Each set a reading of the rc files may select is
/// evaluated, and one blocked set blocks: a config that only a
/// `--config=ci` selects still breaks CI.
///
/// Only what was read is judged: a config named in an rc file that could
/// not be read is a gap of [`EffectiveFlags::gaps`], not `NoConfig`.
pub fn verdict(
    flags: &EffectiveFlags,
    line: &BazelLine,
    files: &dyn FileView,
    url: &str,
) -> Verdict {
    let candidate = BazelVersion {
        rc: Some(0),
        ..BazelVersion::new(10, 0, 0)
    };
    let stray = line.at_least(BazelVersion::new(9, 1, 0)) != Tri::No
        && line.at_least(BazelVersion::new(9, 1, 1)) != Tri::Yes;
    let union = line.at_least(candidate) != Tri::No || stray;
    let last_wins = line.at_least(candidate) != Tri::Yes;

    let mut sets: Vec<Vec<String>> = Vec::new();
    let mut add = |set: Vec<String>| {
        if !set.is_empty() && !sets.contains(&set) {
            sets.push(set);
        }
    };
    for chain in [Chain::Build, Chain::Test, Chain::Fetch] {
        if last_wins {
            let state = flags.state(Flag::DownloaderConfig, chain);
            state
                .values()
                .into_iter()
                .for_each(|path| add(vec![path.clone()]));
        }
        if union {
            let seen = flags.occurrences(Flag::DownloaderConfig, chain);
            let mut configs: Vec<&str> = seen.iter().map(|o| o.config.as_str()).collect();
            configs.dedup();
            for config in configs {
                let reached = |o: &&Occurrence| o.config == PLAIN || o.config == config;
                let paths = |certain: bool| -> Vec<String> {
                    let members = seen
                        .iter()
                        .filter(reached)
                        .filter(|o| o.certain || !certain);
                    members.map(|o| o.value.clone()).collect()
                };
                add(paths(false));
                add(paths(true));
            }
        }
    }
    if sets.is_empty() {
        return Verdict::NoConfig;
    }

    let mut fetched: Vec<String> = Vec::new();
    for set in sets {
        let name = set.join(", ");
        let blocked = |why: String| Verdict::Blocked {
            config: name.clone(),
            why,
        };
        // An empty value switches the downloader config off.
        if set.iter().any(|path| path.is_empty()) {
            fetched.push(url.to_string());
            continue;
        }
        let mut config = DownloaderConfig::default();
        for path in &set {
            // Bazel decodes the file as UTF-8 and replaces what is not.
            let Some(FileText::Bytes(bytes)) = root_relative(path).map(|rel| files.read(&rel))
            else {
                return blocked(format!("{path} cannot be read, and Bazel stops without it"));
            };
            let text = String::from_utf8_lossy(&bytes);
            if let Err(error) = config.add(&text) {
                return blocked(format!("{path}:{} {}", error.line, error.detail));
            }
        }
        match config.amend(url) {
            Amended::Unevaluable(why) => return blocked(why),
            Amended::Urls(urls) if urls.is_empty() => {
                return blocked(format!("every URL for {url} is blocked"));
            }
            Amended::Urls(urls) => fetched.extend(urls),
        }
    }
    fetched.sort();
    fetched.dedup();
    Verdict::Fetchable { urls: fetched }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::bazel::rc::read;
    use crate::bazel::rc::testing::Files;
    use crate::test_rng::Rng;

    const CASES: &str = include_str!("../../tests/fixtures/bazel/rc/url-rewriter-cases.json");
    const PATCH: &str = "https://patch.socket.dev/patch/npm/left-pad/1.3.0/abcd/left-pad-1.3.0.tgz";

    fn urls(config: &str, url: &str) -> Amended {
        DownloaderConfig::parse(config)
            .expect("a config Bazel accepts")
            .amend(url)
    }

    fn fetched(config: &str, url: &str) -> Vec<String> {
        match urls(config, url) {
            Amended::Urls(urls) => urls,
            Amended::Unevaluable(why) => panic!("{config:?} on {url}: {why}"),
        }
    }

    fn unevaluable(config: &str, url: &str) -> bool {
        matches!(urls(config, url), Amended::Unevaluable(_))
    }

    /// What one `rewrite` line makes of `rest`, a URL without its scheme.
    fn rewritten(pattern: &str, to: &str, rest: &str) -> Vec<String> {
        fetched(
            &format!("rewrite {pattern} {to}\n"),
            &format!("https://{rest}"),
        )
    }

    // ── Conformance with real Bazel (probe T3) ───────────────────────

    #[test]
    fn the_34_cases_bazel_ran_reproduce() {
        let fixture: Value = serde_json::from_str(CASES).expect("fixture");
        let cases = fixture["cases"].as_array().expect("cases");
        assert_eq!(cases.len(), 34);
        let (mut rewritten, mut blocked) = (0, 0);
        for case in cases {
            let name = case["name"].as_str().expect("name");
            let strings = |key: &str| -> Vec<&str> {
                let items = case[key].as_array().expect("an array").iter();
                items.map(|item| item.as_str().expect("a string")).collect()
            };
            let config = DownloaderConfig::parse(case["config"].as_str().expect("config"));
            let config = config.unwrap_or_else(|error| panic!("{name}: {error:?}"));
            let mut mine = Vec::new();
            for url in strings("urls") {
                match config.amend(url) {
                    Amended::Urls(urls) => mine.extend(urls),
                    Amended::Unevaluable(why) => panic!("{name}: {why}"),
                }
            }
            assert_eq!(mine, strings("expect_urls"), "{name}");
            rewritten += usize::from(mine.iter().any(|url| !strings("urls").contains(&&url[..])));
            if let Some(error) = case["expect_error"].as_str() {
                // Bazel's text ends with the config's own message.
                let message = config.all_blocked_message.as_deref().unwrap_or("");
                assert!(mine.is_empty() && error.ends_with(message), "{name}");
                assert!(
                    error.contains("Configured URL rewriter blocked all URLs"),
                    "{name}"
                );
                blocked += 1;
            }
        }
        // The fixture exercises the lookahead recipe and the block path.
        assert_eq!((rewritten, blocked), (29, 3));
    }

    // ── Bazel's order: rewrite, then allow over block ────────────────

    #[test]
    fn an_allow_entry_wins_over_a_block_entry_on_the_final_host() {
        let same = [PATCH.to_string()];
        assert_eq!(fetched("", PATCH), same);
        assert_eq!(fetched("block *\nallow patch.socket.dev\n", PATCH), same);
        assert_eq!(fetched("allow patch.socket.dev\nblock *\n", PATCH), same);
        // A parent domain covers its sub-domains; a look-alike does not.
        assert_eq!(fetched("block *\nallow socket.dev\n", PATCH), same);
        assert_eq!(fetched("block *\nallow dev\n", PATCH), same);
        for config in [
            "block *\n",
            "block patch.socket.dev\n",
            "block socket.dev\n",
            "block *\nallow ocket.dev\n",
            "block *\nallow notpatch.socket.dev\n",
            "block *\nallow https://patch.socket.dev\n",
        ] {
            assert!(fetched(config, PATCH).is_empty(), "{config:?}");
        }
        assert_eq!(
            fetched("block registry.npmjs.org\nblock ocket.dev\n", PATCH),
            same
        );

        // A rewrite moves the URL, and the mirror's host is what counts.
        let mirror = "rewrite patch\\.socket\\.dev/(.*) mirror.corp.example/socket/$1\n";
        let moved = [
            "https://mirror.corp.example/socket/patch/npm/left-pad/1.3.0/abcd/left-pad-1.3.0.tgz",
        ];
        assert_eq!(fetched(mirror, PATCH), moved);
        assert_eq!(
            fetched(&format!("{mirror}block *\nallow corp.example\n"), PATCH),
            moved
        );
        // The allowance of the original host no longer helps.
        assert!(fetched(&format!("{mirror}block *\nallow patch.socket.dev\n"), PATCH).is_empty());
        assert!(fetched(&format!("{mirror}block mirror.corp.example\n"), PATCH).is_empty());
        // Every matching rule adds a URL, once; a replacement may set the
        // scheme; a rule that does not match the whole URL adds none.
        let two = "rewrite patch\\.socket\\.dev/(.*) a.example/$1\n\
                   rewrite (patch\\.socket\\.dev)/(.*) http://b.example/$2?from=$1\n\
                   rewrite patch\\.socket\\.dev/(.*) a.example/$1\n\
                   rewrite patch\\.socket\\.dev b.example\n\
                   block a.example\n";
        assert_eq!(
            fetched(two, "https://patch.socket.dev/x.tgz"),
            ["http://b.example/x.tgz?from=patch.socket.dev"]
        );
        // Only http and https go through the config at all.
        assert_eq!(
            fetched("block *\n", "file:.socket/vendor/x.tgz"),
            ["file:.socket/vendor/x.tgz"]
        );
        assert_eq!(
            fetched("block *\n", "file:///abs/x.tgz"),
            ["file:///abs/x.tgz"]
        );
        assert_eq!(
            fetched("block *\n", "s3://bucket/x.tgz"),
            ["s3://bucket/x.tgz"]
        );
        assert!(fetched("block *\n", "HTTPS://patch.socket.dev/x").is_empty());
    }

    #[test]
    fn a_url_without_a_scheme_is_not_evaluated() {
        for url in [
            "patch.socket.dev/x",
            "//patch.socket.dev/x",
            "https:patch.socket.dev/x",
            "1http://a/x",
            "",
        ] {
            assert!(unevaluable("", url), "{url:?}");
        }
    }

    #[test]
    fn a_config_bazel_rejects_is_an_error() {
        let line = |config: &str| DownloaderConfig::parse(config).expect_err(config).line;
        assert_eq!(line("allow a.example\nfrobnicate x\n"), 2);
        assert_eq!(line("allow\n"), 1);
        assert_eq!(line("block a.example b.example\n"), 1);
        assert_eq!(line("rewrite (.*)\n"), 1);
        assert_eq!(line("rewrite (.*) a/$1 extra\n"), 1);
        assert_eq!(line("all_blocked_message\n"), 1);
        assert_eq!(
            line("all_blocked_message one\r\nall_blocked_message two\r\n"),
            2
        );
        // A BOM is part of the first word, which is then no directive,
        // and a comment sign must start a word.
        assert_eq!(line("\u{feff}# mirror rules\nblock *\n"), 1);
        assert_eq!(line("block * # everything\n"), 1);

        let config = "# comment\r\n\r\n  allow  a.example\t\r\n\x0c#x\rblock *\n\
                      all_blocked_message  see  go/bazel-mirror \n";
        let parsed = DownloaderConfig::parse(config).expect("accepted");
        assert_eq!(
            (parsed.allow, parsed.block),
            (vec!["a.example".to_string()], vec!["*".to_string()])
        );
        // Bazel cuts the line after the directive, spacing and all.
        assert_eq!(
            parsed.all_blocked_message.as_deref(),
            Some(" see  go/bazel-mirror ")
        );
        // Two files on Bazel 10: one config.
        let mut union = DownloaderConfig::parse("block *\n").expect("accepted");
        union.add("allow patch.socket.dev\n").expect("accepted");
        assert_eq!(union.amend(PATCH), Amended::Urls(vec![PATCH.to_string()]));
    }

    // ── The pattern subset ───────────────────────────────────────────

    #[test]
    fn rewrite_patterns_match_as_java_matches_them() {
        for (pattern, to, rest, expected) in [
            // The shapes of Bazel's own documentation.
            (
                "github\\.com/([^/]+)/([^/]+)/releases/download/([^/]+)/(.*)",
                "m.example/gh/$1/$2/$3/$4",
                "github.com/o/r/releases/download/v1/a.tgz",
                Some("m.example/gh/o/r/v1/a.tgz"),
            ),
            (
                "github.com/([^/]+)/([^/]+)/archive/(.+).(tar.gz|zip)",
                "m.example/$1/$2/$3?ext=$4",
                "github.com/o/r/archive/v1.2.tar.gz",
                Some("m.example/o/r/v1.2?ext=tar.gz"),
            ),
            (
                "(.*)",
                "m.example/$1",
                "a.example/x?y=1&z=2#f",
                Some("m.example/a.example/x?y=1&z=2#f"),
            ),
            // The whole URL must match.
            ("a\\.example", "m.example", "a.example/x", None),
            ("a\\.example/.*", "m.example", "b.a.example/x", None),
            // Alternation, classes, counted and lazy repeats.
            (
                "(?:a|b)\\.example/(\\d+)/(\\w+)\\.t(?:ar\\.)?gz",
                "m/$2-$1",
                "b.example/42/pkg_1.tgz",
                Some("m/pkg_1-42"),
            ),
            (
                "(?:a|b)\\.example/(\\d+)/(\\w+)\\.t(?:ar\\.)?gz",
                "m/$2-$1",
                "c.example/42/pkg_1.tgz",
                None,
            ),
            (
                "[a-c.]+example/([^?#&]*)[?]?.*",
                "m/$1",
                "a.b.example/p?q",
                Some("m/p"),
            ),
            (
                "([0-9a-f]{2})([0-9a-f]{2,})/(.{1,3}?)(.*)",
                "m/$1/$2/$3/$4",
                "abcdef/wxyz",
                Some("m/ab/cdef/w/xyz"),
            ),
            ("x{2}y{0,1}z{1,}", "m", "xxzz", Some("m")),
            (
                "a\\.example/+(x*)y?/*",
                "m/$1",
                "a.example///xxx",
                Some("m/xxx"),
            ),
            ("x{2}y{0,1}z{1,}", "m", "xyz", None),
            ("(a+?)(a*)/(\\S+)", "m/$1.$2.$3", "aaa/b", Some("m/a.aa.b")),
            // A group inside a repeat keeps its last iteration; one that
            // did not take part is empty.
            ("(?:(\\w)-)+(z)?end", "m/$1$2", "a-b-c-end", Some("m/c")),
            ("(a)|(b)", "m/[$1][$2]", "b", Some("m/[][b]")),
            // Lookahead, the recipe of the test harness included.
            (
                "((?!127\\.0\\.0\\.1[:/]).*)",
                "http://127.0.0.1:8080/$1",
                "a.example/x",
                Some("http://127.0.0.1:8080/a.example/x"),
            ),
            (
                "((?!127\\.0\\.0\\.1[:/]).*)",
                "http://127.0.0.1:8080/$1",
                "127.0.0.1:8080/x",
                None,
            ),
            ("(?=a\\.)(.*)/(.*)", "m/$2", "a.example/x", Some("m/x")),
            ("(?=b\\.)(.*)/(.*)", "m/$2", "a.example/x", None),
            ("^a\\.example/(.*)$", "m/$1", "a.example/x", Some("m/x")),
            // Escapes: a backslash before a non-letter is a literal, in a
            // class too; `$0` is the whole match; `\$` and `\\` are text.
            (
                "a\\.example/\\(x\\)\\[\\]\\{\\}\\*\\+\\?\\|\\^\\$\\\\",
                "m/$0",
                "a.example/(x)[]{}*+?|^$\\",
                Some("m/a.example/(x)[]{}*+?|^$\\"),
            ),
            ("h/a[\\].\\-/]+z", "m/\\$1\\\\", "h/a]./-z", Some("m/$1\\")),
            ("h/a[-x]b[x-]c[&]", "m", "h/a-bxc&", Some("m")),
            ("h/a\\s\\S\\D\\W", "m", "h/a ~~~", Some("m")),
            (
                "(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)",
                "$10$1",
                "abcdefghij",
                Some("ja"),
            ),
        ] {
            let expected: Vec<String> = vec![format!("https://{}", expected.unwrap_or(rest))
                .replace("https://http://", "http://")];
            assert_eq!(
                rewritten(pattern, to, rest),
                expected,
                "{pattern} on {rest}"
            );
        }
    }

    #[test]
    fn what_cannot_be_evaluated_statically_counts_as_blocked() {
        let url = "https://a.example/x";
        for pattern in [
            // Outside the subset.
            "(?<=a)(.*)",
            "(?<!a)(.*)",
            "(?<name>.*)",
            "(?i)(.*)",
            "(?>a)(.*)",
            "(.)\\1.*",
            "\\bx.*",
            "\\p{L}.*",
            "\\Qa.b\\E.*",
            "(.*)*+",
            "(.*)++",
            "a[b&&c].*",
            "a[b[c]].*",
            "\\x41.*",
            "\\t.*",
            // Errors in Java.
            "(.*",
            ".*)",
            "*a",
            "a{2",
            "a{,2}",
            "a{3,2}",
            "a**",
            "[]a].*",
            "[z-a].*",
            "a[b",
            "a\\",
            "(?",
            "^*",
            "(?!a)+b",
        ] {
            let config = format!("rewrite {pattern} m.example/x\n");
            assert!(unevaluable(&config, url), "{pattern}");
            // Even for a URL the rule would plainly not touch: Bazel may
            // read the pattern another way.
            assert!(unevaluable(&config, PATCH), "{pattern}");
        }
        for replacement in [
            "m/${1}",
            "m/$",
            "m/$x",
            "m/$2",
            "m/$10",
            "m\\",
            "m/urlencode($1)",
            "m/${urlencode($1)}",
        ] {
            let config = format!("rewrite (.*) {replacement}\n");
            assert!(unevaluable(&config, url), "{replacement}");
        }
        // The first match and the whole match differ: Bazel through 9
        // rewrites the first and keeps the tail, Bazel 10 the whole.
        assert!(unevaluable("rewrite (a\\.example|a\\.example/x) m\n", url));
        assert!(unevaluable("rewrite (.*?)/?(x?) m/$1\n", url));
        assert_eq!(
            rewritten("(a\\.example/x|a\\.example)", "m", "a.example/x"),
            ["https://m"]
        );
        // Too costly to decide.
        let slow = format!("https://{}!", "a".repeat(40));
        assert!(unevaluable("rewrite (a|aa)+b m\n", &slow));
        assert!(unevaluable(
            &format!("rewrite {} m\n", "(".repeat(300) + &")".repeat(300)),
            url
        ));
        assert!(unevaluable(
            &format!("rewrite {}.* m\n", "a".repeat(600)),
            url
        ));
        // A long literal prefix and a long URL cost nothing.
        let long = format!("{}/{}", "a.example/".repeat(40), "x".repeat(4000));
        let pattern = format!("{}/(.*)", "a\\.example/".repeat(40));
        assert_eq!(
            rewritten(&pattern, "m/$1", &long),
            [format!("https://m/{}", "x".repeat(4000))]
        );
        let pattern = format!("{}/(x+)", "a\\.example/".repeat(40));
        assert_eq!(
            rewritten(&pattern, "m/$1", &long),
            [format!("https://m/{}", "x".repeat(4000))]
        );
        assert!(unevaluable(
            "rewrite (.*) m/$1\n",
            &format!("https://a.example/{}", "x".repeat(9000))
        ));

        // Hosts Java's URL classes do not agree on, or that Bazel 10
        // would fold before matching.
        assert!(unevaluable("", "https://Patch.Socket.dev/x"));
        assert!(unevaluable("", "https://under_score.example/x"));
        assert!(unevaluable("", "https:///x"));
        assert!(unevaluable("rewrite (.*) m_irror.example/$1\n", url));
        assert!(unevaluable("rewrite (.*) /$1\n", url));
        assert_eq!(
            fetched("block *\nallow [::1]\n", "http://user:pw@[::1]:8080/x"),
            ["http://user:pw@[::1]:8080/x"]
        );
        assert_eq!(
            fetched("allow a.example\nblock *\n", "https://u@a.example:8443?q"),
            ["https://u@a.example:8443?q"]
        );
    }

    /// Bazel 10 compares hosts without regard to case and older releases
    /// do not, so an entry helps only where both agree.
    #[test]
    fn host_case_is_read_the_conservative_way() {
        let moved = "rewrite a\\.example/(.*) Mirror.Example/$1\n";
        let url = "https://a.example/x";
        assert_eq!(fetched(moved, url), ["https://Mirror.Example/x"]);
        assert!(fetched(&format!("{moved}block mirror.example\n"), url).is_empty());
        assert!(fetched(&format!("{moved}block *\nallow mirror.example\n"), url).is_empty());
        assert_eq!(
            fetched(&format!("{moved}block *\nallow Mirror.Example\n"), url),
            ["https://Mirror.Example/x"]
        );
        assert!(fetched("block PATCH.socket.dev\n", PATCH).is_empty());
        assert!(fetched("block *\nallow Patch.Socket.Dev\n", PATCH).is_empty());
    }

    // ── The tracked configs ──────────────────────────────────────────

    fn tracked(files: &[(&str, &str)], line: &BazelLine) -> Verdict {
        let files = Files::of(files);
        verdict(&read(&files).effective(line), line, &files, PATCH)
    }

    #[test]
    fn the_verdict_follows_the_configs_the_rc_files_name() {
        let nine = BazelLine::of(BazelVersion::new(9, 3, 2));
        let fetchable = Verdict::Fetchable {
            urls: vec![PATCH.to_string()],
        };
        let blocked_by = |verdict: Verdict| match verdict {
            Verdict::Blocked { config, why } => (config, why),
            other => panic!("{other:?}"),
        };
        assert_eq!(tracked(&[], &nine), Verdict::NoConfig);
        assert_eq!(
            tracked(&[(".bazelrc", "common --lockfile_mode=error\n")], &nine),
            Verdict::NoConfig
        );

        // Either spelling, a path relative to the root.
        for flag in ["downloader_config", "experimental_downloader_config"] {
            let rc = format!("common --{flag}=tools/./dl.cfg\n");
            let open = [
                (".bazelrc", &rc[..]),
                ("tools/dl.cfg", "block *\nallow patch.socket.dev\n"),
            ];
            assert_eq!(tracked(&open, &nine), fetchable, "{flag}");
            let shut = [
                (".bazelrc", &rc[..]),
                ("tools/dl.cfg", "block *\nallow registry.npmjs.org\n"),
            ];
            let (config, why) = blocked_by(tracked(&shut, &nine));
            assert_eq!(config, "tools/./dl.cfg");
            assert!(why.contains("is blocked"), "{why}");
        }
        // A rewrite to a mirror is where Bazel fetches from.
        let mirror = [
            (".bazelrc", "common --downloader_config=dl.cfg\n"),
            ("dl.cfg", "rewrite patch\\.socket\\.dev/(.*) mirror.example/$1\nblock *\nallow mirror.example\n"),
        ];
        let moved = PATCH.replace("patch.socket.dev", "mirror.example");
        assert_eq!(
            tracked(&mirror, &nine),
            Verdict::Fetchable { urls: vec![moved] }
        );

        // A file that is missing, outside the repository, rejected by
        // Bazel or not evaluable blocks: unreadable is not "no rules".
        let rc = (".bazelrc", "common --downloader_config=dl.cfg\n");
        assert!(blocked_by(tracked(&[rc], &nine))
            .1
            .contains("cannot be read"));
        let absolute = (".bazelrc", "common --downloader_config=/etc/bazel/dl.cfg\n");
        assert!(blocked_by(tracked(&[absolute], &nine))
            .1
            .contains("cannot be read"));
        assert!(blocked_by(tracked(&[rc, ("dl.cfg", "deny *\n")], &nine))
            .1
            .starts_with("dl.cfg:1 "));
        let lookbehind = ("dl.cfg", "rewrite (?<=x)(.*) m/$1\n");
        assert!(blocked_by(tracked(&[rc, lookbehind], &nine))
            .1
            .contains("cannot be evaluated"));

        // A config only `--config=ci` selects still breaks CI, and an
        // empty value switches the downloader config off.
        let ci = [
            (
                ".bazelrc",
                "common --downloader_config=open.cfg\ncommon:ci --downloader_config=shut.cfg\n",
            ),
            ("open.cfg", "allow patch.socket.dev\n"),
            ("shut.cfg", "block *\n"),
        ];
        assert_eq!(blocked_by(tracked(&ci, &nine)).0, "shut.cfg");
        let reset = [
            (
                ".bazelrc",
                "common --downloader_config=shut.cfg\ncommon --downloader_config=\n",
            ),
            ("shut.cfg", "block *\n"),
        ];
        assert_eq!(tracked(&reset, &nine), fetchable);
        // The `test` chain counts as much as `build`.
        let test_only = [
            (".bazelrc", "test --downloader_config=shut.cfg\n"),
            ("shut.cfg", "block *\n"),
        ];
        assert_eq!(blocked_by(tracked(&test_only, &nine)).0, "shut.cfg");
    }

    /// Probe S8: on Bazel 6.5.0 a second config replaced the first (a
    /// host the first blocked was fetched); on 10.0.0rc3 both applied.
    #[test]
    fn two_configs_are_last_wins_through_bazel_9_and_a_union_on_10() {
        let files = [
            (
                ".bazelrc",
                "common --downloader_config=a.cfg\ncommon --downloader_config=b.cfg\n",
            ),
            ("a.cfg", "block patch.socket.dev\n"),
            ("b.cfg", "block registry.npmjs.org\n"),
        ];
        let line = |text: &str| BazelLine::of(BazelVersion::parse(text).expect("a release"));
        let fetchable = Verdict::Fetchable {
            urls: vec![PATCH.to_string()],
        };
        for last_wins in ["6.6.0", "8.8.2", "9.0.2", "9.1.1", "9.3.2"] {
            assert_eq!(tracked(&files, &line(last_wins)), fetchable, "{last_wins}");
        }
        // 9.1.0 shipped the repeatable flag by accident.
        for union in ["10.0.0rc3", "10.0.0", "9.1.0"] {
            let verdict = tracked(&files, &line(union));
            assert!(
                matches!(&verdict, Verdict::Blocked { config, .. } if config == "a.cfg, b.cfg"),
                "{union}"
            );
        }
        // A line that may be either is held to both readings.
        assert!(matches!(
            tracked(&files, &BazelLine::unknown()),
            Verdict::Blocked { .. }
        ));
        // The union can also open what one file shuts.
        let opened = [
            (
                ".bazelrc",
                "common --downloader_config=a.cfg\ncommon:ci --downloader_config=b.cfg\n",
            ),
            ("a.cfg", "block *\n"),
            ("b.cfg", "allow patch.socket.dev\n"),
        ];
        // Without the config only `a.cfg` applies, on every release.
        assert!(
            matches!(tracked(&opened, &line("10.0.0")), Verdict::Blocked { config, .. } if config == "a.cfg")
        );
    }

    #[test]
    fn no_pattern_makes_the_matcher_panic_or_hang() {
        let seeds = [
            "((?!127\\.0\\.0\\.1[:/]).*)",
            "github\\.com/([^/]+)/(.+).(tar.gz|zip)",
            "(a|b)*c{2,3}?[x-z\\d]+$",
            "(?:(\\w)-)+(z)?(?=end)\\S*",
            "^(.*?)(a+)+[^&]{0,4}",
        ];
        let inputs = [
            "a.example/x",
            "127.0.0.1:8080/y",
            "github.com/o/r.tar.gz",
            "aaaaaaaaaaaaaaaaaaaaaaaa!",
            "",
        ];
        let mut rng = Rng::new(0xd1);
        for _ in 0..3000 {
            let mut pattern: Vec<char> = seeds[rng.below(seeds.len())].chars().collect();
            for _ in 0..rng.below(4) {
                let at = rng.below(pattern.len().max(1));
                let glyphs: Vec<char> = "()[]{}|*+?.\\^$-!=:,a1&<".chars().collect();
                match rng.below(3) {
                    0 if !pattern.is_empty() => drop(pattern.remove(at.min(pattern.len() - 1))),
                    1 => pattern.insert(at.min(pattern.len()), glyphs[rng.below(glyphs.len())]),
                    _ => pattern.truncate(at),
                }
            }
            let pattern: String = pattern.into_iter().collect();
            let config = format!("rewrite {pattern} m.example/$1\n");
            // A pattern with a blank in it is three words too many.
            let Ok(config) = DownloaderConfig::parse(&config) else {
                continue;
            };
            for input in inputs {
                let _ = config.amend(&format!("https://{input}"));
            }
        }
    }
}
