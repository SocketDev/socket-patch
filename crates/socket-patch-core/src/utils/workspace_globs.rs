//! The workspace glob grammar both workspace-membership checks read: npm,
//! yarn and Bun `package.json` `workspaces` (#884) and pnpm's
//! `pnpm-workspace.yaml` `packages:` (#1006). A pattern is a `/`-separated
//! glob in the grammar npm (minimatch), yarn, Bun and pnpm share: brace
//! sets (`{a,b}`, nested, and `{1..3}` / `{a..c}` sequences) expand first,
//! then `*`, `?` and character classes (`[abc]`, `[a-c]`, `[!a]`, `[^a]`)
//! match within one component and `**` matches any number of components
//! (#1071). A leading `./`, empty components and a trailing `/` are
//! ignored. A leading `!` negates; each caller applies negations the way
//! its package manager does. pnpm's globber also never lets a wildcard
//! match a component that starts with `.` ([`glob_matches_no_dot`]).
//! npm and yarn also match extglobs (`@(a|b)`, `?(..)`, `*(..)`, `+(..)`,
//! `!(..)`) within one component, and yarn classic ignores `!` patterns;
//! [`WorkspacesDialect`] names what each package manager reads (#1097).
//! yarn berry's picomatch further reads regex groups (`(a|b)`), POSIX
//! classes (`[[:alpha:]]`) and `..` segments (#1490).

use std::sync::LazyLock;

use regex::Regex;

/// How one package manager reads `package.json` (or `vlt.json`)
/// `workspaces`, probed on npm 10.9, yarn 1.22.22, yarn 4.10, Bun 1.2.23
/// and Bun 1.4.2 (#1097).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorkspacesDialect {
    /// What a pattern with a leading `!` does.
    pub(crate) negation: Negation,
    /// Extglob groups match (npm's minimatch, yarn's node-glob and
    /// micromatch). Off, they are literal characters (Bun fails its
    /// install on one, so its lock never lists such a member).
    pub(crate) extglob: bool,
    /// The pattern is read by globby / fast-glob / picomatch (yarn
    /// berry), which also take regex groups, POSIX classes and `..`
    /// segments ([`Picomatch`], #1490).
    pub(crate) picomatch: bool,
}

/// What a `workspaces` pattern with a leading `!` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Negation {
    /// It excludes what earlier patterns matched; a later pattern can
    /// list the directory again (npm, Bun 1.3+, vlt).
    LastMatchWins,
    /// It excludes the directory whatever the order (yarn berry's
    /// globby), and a leading `!(` is an extglob group, not a negation.
    Unordered,
    /// It is ignored: it neither excludes nor lists anything (yarn
    /// classic, Bun before 1.3).
    Ignored,
}

impl WorkspacesDialect {
    /// npm (`package-lock.json`, `npm-shrinkwrap.json`).
    pub(crate) const NPM: Self = Self {
        negation: Negation::LastMatchWins,
        extglob: true,
        picomatch: false,
    };
    /// yarn classic (a `yarn.lock` without berry's `__metadata`).
    pub(crate) const YARN_CLASSIC: Self = Self {
        negation: Negation::Ignored,
        extglob: true,
        picomatch: false,
    };
    /// yarn berry (a `yarn.lock` with `__metadata`).
    pub(crate) const YARN_BERRY: Self = Self {
        negation: Negation::Unordered,
        extglob: true,
        picomatch: true,
    };
    /// Bun 1.3 and later (a `bun.lock` with `configVersion`).
    pub(crate) const BUN: Self = Self {
        negation: Negation::LastMatchWins,
        extglob: false,
        picomatch: false,
    };
    /// Bun before 1.3: it lists `!`-negated directories anyway.
    pub(crate) const BUN_PRE_1_3: Self = Self {
        negation: Negation::Ignored,
        extglob: false,
        picomatch: false,
    };
    /// vlt, as #942 read it.
    pub(crate) const VLT: Self = Self {
        negation: Negation::LastMatchWins,
        extglob: false,
        picomatch: false,
    };
    /// Every dialect, for a root whose package manager is unknown: it lists
    /// a directory when any of them does.
    pub(crate) const ALL: [Self; 6] = [
        Self::NPM,
        Self::YARN_CLASSIC,
        Self::YARN_BERRY,
        Self::BUN,
        Self::BUN_PRE_1_3,
        Self::VLT,
    ];
}

/// Whether the member path (`rel`, relative to the workspace root, one
/// entry per component) matches a `workspaces` pattern and no later
/// `!`-negated one (npm and yarn: the last matching pattern wins), in vlt's
/// dialect.
pub(crate) fn workspaces_include(patterns: &[String], rel: &[String]) -> bool {
    workspaces_include_as(patterns, rel, WorkspacesDialect::VLT)
}

/// [`workspaces_include`] in a given package manager's dialect.
pub(crate) fn workspaces_include_as(
    patterns: &[String],
    rel: &[String],
    dialect: WorkspacesDialect,
) -> bool {
    if rel.is_empty() {
        return false;
    }
    let matches = |pattern: &str, negated: bool| {
        let picomatch = dialect.picomatch.then(|| Picomatch {
            // globby hands `!` patterns to micromatch as ignores, which
            // always read a group as one.
            every_group: negated || fast_glob_dynamic(pattern),
        });
        pattern_matches(pattern, rel, true, dialect.extglob, picomatch)
    };
    match dialect.negation {
        Negation::LastMatchWins => {
            let mut included = false;
            for pattern in patterns {
                let (negated, pattern) = split_negation(pattern);
                if matches(pattern, negated) {
                    included = !negated;
                }
            }
            included
        }
        Negation::Unordered => {
            let (mut listed, mut excluded) = (false, false);
            for pattern in patterns {
                match split_negation(pattern) {
                    (true, rest) if !(dialect.extglob && rest.starts_with('(')) => {
                        excluded |= matches(rest, true)
                    }
                    _ => listed |= matches(pattern, false),
                }
            }
            listed && !excluded
        }
        Negation::Ignored => patterns
            .iter()
            .any(|pattern| !pattern.starts_with('!') && matches(pattern, false)),
    }
}

/// `(true, rest)` for a `!`-negated pattern, `(false, pattern)` otherwise.
pub(crate) fn split_negation(pattern: &str) -> (bool, &str) {
    match pattern.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, pattern),
    }
}

/// Whether one (un-negated) pattern matches `rel`. A pattern with no
/// components left (`""`, `.`, `./`) matches nothing.
pub(crate) fn glob_matches(pattern: &str, rel: &[String]) -> bool {
    pattern_matches(pattern, rel, true, false, None)
}

/// [`glob_matches`] the way pnpm's globber reads `packages:` (`dot: false`,
/// probed on pnpm 12.10.1): `*`, `?` and `**` never match a component that
/// starts with `.`, so `**` does not list `.github/actions/demo` and
/// `packages/*` does not list `packages/.hidden`. A pattern component that
/// itself starts with `.` (`.github/**`) still matches it.
pub(crate) fn glob_matches_no_dot(pattern: &str, rel: &[String]) -> bool {
    pattern_matches(pattern, rel, false, false, None)
}

/// How yarn berry's globby / fast-glob / picomatch read a pattern beyond
/// the shared grammar (#1490, probed on yarn 4.0.2 and 4.18.1): a
/// parenthesised group not led by an extglob character is a regex group
/// (`packages/(a|b)`), a bracket class may hold POSIX classes
/// (`[[:alpha:]]`), and a `..` segment steps back over the one before it
/// (`packages/a/../b` lists `packages/b`).
#[derive(Debug, Clone, Copy)]
struct Picomatch {
    /// A group without `|` is a group too, not literal text. fast-glob
    /// reads a pattern it deems static as a plain path, so `(a)` there
    /// names a directory called `(a)`; picomatch reads it in a dynamic
    /// one ([`fast_glob_dynamic`]) and in an ignore.
    every_group: bool,
}

/// fast-glob's `isDynamicPattern`: whether it matches the pattern with
/// picomatch rather than reading it as a literal path.
fn fast_glob_dynamic(pattern: &str) -> bool {
    static DYNAMIC: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(concat!(
            r"[*?\\]|^!|\[[^\[]*\]",
            r"|(?:^|[^!*+?@])\([^(]*\|[^|]*\)",
            r"|[!*+?@]\([^(]*\)",
            r"|\{[^{}]*(?:,|\.\.)[^{}]*\}",
        ))
        .expect("static regex")
    });
    DYNAMIC.is_match(pattern)
}

fn pattern_matches(
    pattern: &str,
    rel: &[String],
    dot: bool,
    extglob: bool,
    picomatch: Option<Picomatch>,
) -> bool {
    let rel: Vec<Vec<char>> = rel.iter().map(|c| c.chars().collect()).collect();
    let mut alternatives = expand_braces(pattern.trim());
    if let Some(picomatch) = picomatch {
        let mut expanded = Vec::new();
        for alternative in &alternatives {
            expand_regex_groups(alternative, picomatch.every_group, &mut expanded);
        }
        alternatives = expanded;
    }
    alternatives.iter().any(|alternative| {
        let mut segments: Vec<Vec<char>> = Vec::new();
        for segment in alternative
            .split(['/', '\\'])
            .filter(|s| !s.is_empty() && *s != ".")
        {
            if picomatch.is_some() && segment == ".." {
                // A `..` above the workspace root lists nothing in it.
                if segments.pop().is_none() {
                    return false;
                }
                continue;
            }
            segments.push(segment.chars().collect());
        }
        !segments.is_empty()
            && path_glob_matches(&segments, &rel, dot, extglob, picomatch.is_some())
    })
}

/// The regex-group expansion of a picomatch pattern: the first group not
/// led by an extglob character (`@`, `?`, `*`, `+`, `!`) and holding a
/// top-level `|` (or any group, with `every_group`) is replaced by each
/// alternative, recursively. Extglob groups and classes are left whole,
/// and an unclosed `(` stays literal.
fn expand_regex_groups(pattern: &str, every_group: bool, out: &mut Vec<String>) {
    if out.len() >= MAX_BRACE_EXPANSIONS {
        return;
    }
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'[' => {
                // Skip a class, POSIX members included, to its `]`.
                let mut j = i + 1;
                if matches!(bytes.get(j), Some(b'!' | b'^')) {
                    j += 1;
                }
                if bytes.get(j) == Some(&b']') {
                    j += 1;
                }
                while j < bytes.len() && bytes[j] != b']' {
                    if bytes[j] == b'[' && bytes.get(j + 1) == Some(&b':') {
                        if let Some(end) = pattern[j + 2..].find(":]") {
                            j += end + 4;
                            continue;
                        }
                    }
                    j += 1;
                }
                i = if j < bytes.len() { j + 1 } else { i + 1 };
            }
            b'(' => {
                let Some(close) = matching_paren(bytes, i) else {
                    i += 1;
                    continue;
                };
                let extglob = i > 0 && matches!(bytes[i - 1], b'@' | b'?' | b'*' | b'+' | b'!');
                let alternatives = split_top_level_bars(&pattern[i + 1..close]);
                if extglob || (alternatives.len() < 2 && !every_group) {
                    i = if extglob { close + 1 } else { i + 1 };
                    continue;
                }
                let (prefix, suffix) = (&pattern[..i], &pattern[close + 1..]);
                for alternative in alternatives {
                    expand_regex_groups(
                        &format!("{prefix}{alternative}{suffix}"),
                        every_group,
                        out,
                    );
                    if out.len() >= MAX_BRACE_EXPANSIONS {
                        return;
                    }
                }
                return;
            }
            _ => i += 1,
        }
    }
    out.push(pattern.to_string());
}

/// The byte index of the `)` closing the `(` at `open`.
fn matching_paren(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (i, &c) in bytes.iter().enumerate().skip(open) {
        match c {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_top_level_bars(body: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut depth, mut start) = (0usize, 0usize);
    for (i, c) in body.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            '|' if depth == 0 => {
                parts.push(&body[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&body[start..]);
    parts
}

/// Cap on the alternatives one pattern expands to, so a pathological
/// sequence (`{1..1000000}`) cannot stall the run.
const MAX_BRACE_EXPANSIONS: usize = 4096;

/// The brace expansion of a glob, as minimatch's `brace-expansion` does it:
/// the first `{...}` group holding a top-level `,` or a `x..y[..step]`
/// sequence is replaced by each alternative, recursively. A group with
/// neither, and an unbalanced `{`, stay literal.
fn expand_braces(pattern: &str) -> Vec<String> {
    let mut out = Vec::new();
    expand_braces_into(pattern, &mut out);
    out
}

fn expand_braces_into(pattern: &str, out: &mut Vec<String>) {
    if out.len() >= MAX_BRACE_EXPANSIONS {
        return;
    }
    for (open, _) in pattern.match_indices('{') {
        let Some(close) = matching_brace(pattern, open) else {
            continue;
        };
        let body = &pattern[open + 1..close];
        let alternatives = split_top_level_commas(body);
        let alternatives = if alternatives.len() > 1 {
            alternatives
        } else if let Some(sequence) = brace_sequence(body) {
            sequence
        } else {
            continue;
        };
        let (prefix, suffix) = (&pattern[..open], &pattern[close + 1..]);
        for alternative in alternatives {
            expand_braces_into(&format!("{prefix}{alternative}{suffix}"), out);
            if out.len() >= MAX_BRACE_EXPANSIONS {
                return;
            }
        }
        return;
    }
    out.push(pattern.to_string());
}

/// The byte index of the `}` closing the `{` at `open`.
fn matching_brace(pattern: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (i, c) in pattern[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + i);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_top_level_commas(body: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let (mut depth, mut start) = (0usize, 0usize);
    for (i, c) in body.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(body[start..i].to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(body[start..].to_string());
    parts
}

/// A `{x..y}` or `{x..y..step}` sequence body: integers (zero-padded when
/// either end is) or single characters.
fn brace_sequence(body: &str) -> Option<Vec<String>> {
    let parts: Vec<&str> = body.split("..").collect();
    let (from, to, step) = match parts.as_slice() {
        [from, to] => (*from, *to, None),
        [from, to, step] => (*from, *to, Some(*step)),
        _ => return None,
    };
    let step = match step {
        Some(step) => step.parse::<i64>().ok()?.unsigned_abs().max(1),
        None => 1,
    };
    let (start, end, width, as_char) =
        if let (Ok(a), Ok(b)) = (from.parse::<i64>(), to.parse::<i64>()) {
            let padded = |s: &str| {
                s.trim_start_matches('-').len() > 1 && s.trim_start_matches('-').starts_with('0')
            };
            let width = if padded(from) || padded(to) {
                from.len().max(to.len())
            } else {
                0
            };
            (a, b, width, false)
        } else {
            let (mut a, mut b) = (from.chars(), to.chars());
            let (Some(a), None, Some(b), None) = (a.next(), a.next(), b.next(), b.next()) else {
                return None;
            };
            (a as i64, b as i64, 0, true)
        };
    let mut out = Vec::new();
    let mut n = start;
    loop {
        out.push(if as_char {
            char::from_u32(u32::try_from(n).ok()?)?.to_string()
        } else {
            format!("{n:0width$}")
        });
        if n == end || out.len() >= MAX_BRACE_EXPANSIONS {
            break;
        }
        let next = if start <= end {
            n.checked_add(step as i64)?
        } else {
            n.checked_sub(step as i64)?
        };
        if (start <= end && next > end) || (start > end && next < end) {
            break;
        }
        n = next;
    }
    Some(out)
}

/// `dot: false` keeps wildcards off components starting with `.`; `posix`
/// reads POSIX classes inside brackets.
fn path_glob_matches(
    pattern: &[Vec<char>],
    path: &[Vec<char>],
    dot: bool,
    ext: bool,
    posix: bool,
) -> bool {
    let hidden = |component: &Vec<char>| !dot && component.first() == Some(&'.');
    match pattern.split_first() {
        None => path.is_empty(),
        Some((first, rest)) if first.as_slice() == ['*', '*'] => (0..=path.len())
            .take_while(|&skip| skip == 0 || !hidden(&path[skip - 1]))
            .any(|skip| path_glob_matches(rest, &path[skip..], dot, ext, posix)),
        Some((first, rest)) => path.split_first().is_some_and(|(head, tail)| {
            (!hidden(head) || first.first() == Some(&'.'))
                && if ext || posix {
                    ExtglobMatcher {
                        extglob: ext,
                        posix,
                        ..ExtglobMatcher::default()
                    }
                    .segment(first, head)
                } else {
                    segment_glob_matches(first, head)
                }
                && path_glob_matches(rest, tail, dot, ext, posix)
        }),
    }
}

/// Whether one component matches a component pattern, without extglobs.
pub(crate) fn segment_glob_matches(pattern: &[char], name: &[char]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some(('*', rest)) => (0..=name.len()).any(|skip| segment_glob_matches(rest, &name[skip..])),
        Some(('?', rest)) => !name.is_empty() && segment_glob_matches(rest, &name[1..]),
        Some(('[', rest)) => match char_class(rest, false) {
            Some((class, after)) => name
                .split_first()
                .is_some_and(|(c, tail)| class.matches(*c) && segment_glob_matches(after, tail)),
            None => name.first() == Some(&'[') && segment_glob_matches(rest, &name[1..]),
        },
        Some((c, rest)) => name.first() == Some(c) && segment_glob_matches(rest, &name[1..]),
    }
}

/// One component matched against a pattern with extglob groups (`@(a|b)`,
/// `?(..)`, `*(..)`, `+(..)`, `!(..)`), as minimatch reads them. Every
/// (sub-pattern, name suffix) pair is decided once, so an ambiguous group
/// (`*(a|aa)`) costs polynomial time, not exponential.
#[derive(Default)]
struct ExtglobMatcher {
    /// Extglob groups match; off, they are literal.
    extglob: bool,
    /// Brackets read POSIX classes (picomatch, #1490).
    posix: bool,
    memo: std::collections::HashMap<(usize, usize, usize, usize), bool>,
}

impl ExtglobMatcher {
    fn segment(&mut self, pattern: &[char], name: &[char]) -> bool {
        let key = (
            pattern.as_ptr() as usize,
            pattern.len(),
            name.as_ptr() as usize,
            name.len(),
        );
        if let Some(&known) = self.memo.get(&key) {
            return known;
        }
        let matched = self.segment_uncached(pattern, name);
        self.memo.insert(key, matched);
        matched
    }

    fn segment_uncached(&mut self, pattern: &[char], name: &[char]) -> bool {
        if let Some(group) = extglob_group(pattern).filter(|_| self.extglob) {
            return self.group(&group, name);
        }
        match pattern.split_first() {
            None => name.is_empty(),
            Some(('*', rest)) => (0..=name.len()).any(|skip| self.segment(rest, &name[skip..])),
            Some(('?', rest)) => !name.is_empty() && self.segment(rest, &name[1..]),
            Some(('[', rest)) => match char_class(rest, self.posix) {
                Some((class, after)) => name
                    .split_first()
                    .is_some_and(|(c, tail)| class.matches(*c) && self.segment(after, tail)),
                None => name.first() == Some(&'[') && self.segment(rest, &name[1..]),
            },
            Some((c, rest)) => name.first() == Some(c) && self.segment(rest, &name[1..]),
        }
    }

    fn group(&mut self, group: &ExtglobGroup<'_>, name: &[char]) -> bool {
        let rest = group.rest;
        match group.kind {
            '@' => self.alternative_then(group, name, |m, tail| m.segment(rest, tail)),
            '?' => {
                self.segment(rest, name)
                    || self.alternative_then(group, name, |m, tail| m.segment(rest, tail))
            }
            '*' => self.repeat(group, name),
            '+' => self.alternative_then(group, name, |m, tail| m.repeat(group, tail)),
            // minimatch: `!(a|b)rest` matches when no alternative followed
            // by `rest` matches the whole name, and some prefix followed
            // by `rest` does.
            _ => {
                !self.alternative_then(group, name, |m, tail| m.segment(rest, tail))
                    && (0..=name.len()).any(|skip| self.segment(rest, &name[skip..]))
            }
        }
    }

    /// Some alternative matches a prefix of `name` and `then` the rest.
    fn alternative_then(
        &mut self,
        group: &ExtglobGroup<'_>,
        name: &[char],
        then: impl Fn(&mut Self, &[char]) -> bool,
    ) -> bool {
        (0..=name.len()).any(|split| {
            group
                .alternatives
                .iter()
                .any(|alt| self.segment(alt, &name[..split]))
                && then(self, &name[split..])
        })
    }

    /// Zero or more non-empty alternatives, then the group's `rest`.
    fn repeat(&mut self, group: &ExtglobGroup<'_>, name: &[char]) -> bool {
        // A group's `rest` starts right after its own `)`, so its address
        // names the group within the pattern.
        let key = (
            group.rest.as_ptr() as usize,
            usize::MAX,
            name.as_ptr() as usize,
            name.len(),
        );
        if let Some(&known) = self.memo.get(&key) {
            return known;
        }
        let matched = self.segment(group.rest, name)
            || (1..=name.len()).any(|split| {
                group
                    .alternatives
                    .iter()
                    .any(|alt| self.segment(alt, &name[..split]))
                    && self.repeat(group, &name[split..])
            });
        self.memo.insert(key, matched);
        matched
    }
}

/// An extglob group at the start of a component pattern: its kind
/// (`@`, `?`, `*`, `+`, `!`), its `|`-separated alternatives and the
/// pattern after its `)`.
struct ExtglobGroup<'a> {
    kind: char,
    alternatives: Vec<&'a [char]>,
    rest: &'a [char],
}

/// The group starting `pattern`, or `None` when it starts no group or the
/// group never closes (its characters are then read as usual, as in
/// minimatch).
fn extglob_group(pattern: &[char]) -> Option<ExtglobGroup<'_>> {
    let kind = *pattern.first()?;
    if !matches!(kind, '@' | '?' | '*' | '+' | '!') || pattern.get(1) != Some(&'(') {
        return None;
    }
    let body = &pattern[2..];
    let (mut depth, mut start) = (0usize, 0usize);
    let mut alternatives = Vec::new();
    for (i, &c) in body.iter().enumerate() {
        match c {
            '(' => depth += 1,
            ')' if depth == 0 => {
                alternatives.push(&body[start..i]);
                return Some(ExtglobGroup {
                    kind,
                    alternatives,
                    rest: &body[i + 1..],
                });
            }
            ')' => depth -= 1,
            '|' if depth == 0 => {
                alternatives.push(&body[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    None
}

/// A parsed `[...]` character class.
struct CharClass {
    negated: bool,
    ranges: Vec<(char, char)>,
}

impl CharClass {
    fn matches(&self, c: char) -> bool {
        self.ranges.iter().any(|&(lo, hi)| lo <= c && c <= hi) != self.negated
    }
}

/// The class after a `[`, and the pattern after its closing `]`. A `!` or
/// `^` first negates it; a `]` right after that is a member. With `posix`,
/// a `[:name:]` member adds that POSIX class, as picomatch reads it.
/// `None` when the class never closes (the `[` is then literal).
fn char_class(pattern: &[char], posix: bool) -> Option<(CharClass, &[char])> {
    let (negated, mut i) = match pattern.first() {
        Some('!' | '^') => (true, 1),
        _ => (false, 0),
    };
    let mut ranges = Vec::new();
    let first = i;
    while i < pattern.len() {
        let c = pattern[i];
        if c == ']' && i > first {
            return Some((CharClass { negated, ranges }, &pattern[i + 1..]));
        }
        if posix && c == '[' && pattern.get(i + 1) == Some(&':') {
            let name_end = (i + 2..pattern.len().saturating_sub(1))
                .find(|&j| pattern[j] == ':' && pattern[j + 1] == ']');
            if let Some(class) = name_end
                .and_then(|end| posix_class(&pattern[i + 2..end].iter().collect::<String>()))
            {
                ranges.extend_from_slice(class);
                i = name_end.unwrap_or(i) + 2;
                continue;
            }
        }
        if pattern.get(i + 1) == Some(&'-') && pattern.get(i + 2).is_some_and(|&h| h != ']') {
            ranges.push((c, pattern[i + 2]));
            i += 3;
        } else {
            ranges.push((c, c));
            i += 1;
        }
    }
    None
}

/// The members of a POSIX class, as picomatch defines them.
fn posix_class(name: &str) -> Option<&'static [(char, char)]> {
    Some(match name {
        "alnum" => &[('a', 'z'), ('A', 'Z'), ('0', '9')],
        "alpha" => &[('a', 'z'), ('A', 'Z')],
        "ascii" => &[('\0', '\x7f')],
        "blank" => &[(' ', ' '), ('\t', '\t')],
        "cntrl" => &[('\0', '\x1f'), ('\x7f', '\x7f')],
        "digit" => &[('0', '9')],
        "graph" => &[('!', '~')],
        "lower" => &[('a', 'z')],
        "print" => &[(' ', '~')],
        "punct" => &[('!', '/'), (':', '@'), ('[', '`'), ('{', '~')],
        "space" => &[(' ', ' '), ('\t', '\r')],
        "upper" => &[('A', 'Z')],
        "word" => &[('a', 'z'), ('A', 'Z'), ('0', '9'), ('_', '_')],
        "xdigit" => &[('a', 'f'), ('A', 'F'), ('0', '9')],
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspaces_patterns_match_like_npm_and_yarn() {
        let rel = |p: &str| p.split('/').map(str::to_string).collect::<Vec<_>>();
        let pats = |p: &[&str]| p.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(workspaces_include(
            &pats(&["packages/*"]),
            &rel("packages/a")
        ));
        assert!(!workspaces_include(
            &pats(&["packages/*"]),
            &rel("packages/a/b")
        ));
        assert!(workspaces_include(
            &pats(&["./packages/*/"]),
            &rel("packages/a")
        ));
        assert!(workspaces_include(
            &pats(&["packages/**"]),
            &rel("packages/a/b")
        ));
        assert!(workspaces_include(
            &pats(&["**/pkg-*"]),
            &rel("x/y/pkg-one")
        ));
        assert!(workspaces_include(&pats(&["app"]), &rel("app")));
        assert!(!workspaces_include(&pats(&["app"]), &rel("apps")));
        assert!(workspaces_include(&pats(&["app?"]), &rel("apps")));
        assert!(!workspaces_include(
            &pats(&["packages/*", "!packages/b"]),
            &rel("packages/b")
        ));
        assert!(!workspaces_include(&pats(&["*"]), &[]));
        assert!(!glob_matches("./", &rel("a")));
        // npm and yarn callers keep matching dot components.
        assert!(glob_matches("packages/*", &rel("packages/.hidden")));
    }

    /// #1071: npm (minimatch), yarn and Bun expand brace sets and match
    /// character classes in `workspaces`.
    #[test]
    fn workspaces_patterns_expand_braces_and_match_classes() {
        let rel = |p: &str| p.split('/').map(str::to_string).collect::<Vec<_>>();
        let pats = |p: &[&str]| p.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let yes = |p: &str, r: &str| assert!(workspaces_include(&pats(&[p]), &rel(r)), "{p} ~ {r}");
        let no =
            |p: &str, r: &str| assert!(!workspaces_include(&pats(&[p]), &rel(r)), "{p} !~ {r}");
        // Brace sets, nested, spanning separators, and sequences.
        yes("packages/{a,b}", "packages/a");
        yes("packages/{a,b}", "packages/b");
        no("packages/{a,b}", "packages/c");
        yes("{apps,packages}/*", "apps/web");
        yes("packages/{a,{b,c}x}", "packages/cx");
        no("packages/{a,{b,c}x}", "packages/c");
        yes("{packages/a,tools/*}", "tools/t");
        yes("packages/pkg-{1..3}", "packages/pkg-2");
        no("packages/pkg-{1..3}", "packages/pkg-4");
        yes("packages/{a..c}", "packages/b");
        yes("packages/v{01..10}", "packages/v07");
        yes("packages/{,x}a", "packages/a");
        // A brace group with no comma or range is literal, as in minimatch.
        yes("packages/{a}", "packages/{a}");
        no("packages/{a}", "packages/a");
        yes("packages/{a,b", "packages/{a,b");
        // Character classes: sets, ranges, negation, a literal `]` first.
        yes("packages/[a-c]", "packages/b");
        no("packages/[a-c]", "packages/d");
        yes("packages/[ab]x", "packages/bx");
        yes("packages/[!b]", "packages/a");
        no("packages/[!b]", "packages/b");
        yes("packages/[^b]", "packages/c");
        yes("packages/[]a]", "packages/]");
        yes("packages/[a-c]*", "packages/core");
        // An unclosed class is a literal `[`.
        yes("packages/[a", "packages/[a");
        no("packages/[a", "packages/a");
        // Non-ASCII names match one character per `?` and class.
        yes("packages/?", "packages/é");
        yes("packages/[é]", "packages/é");
        // Negation applies to the expanded alternatives too.
        assert!(!workspaces_include(
            &pats(&["packages/*", "!packages/{b,c}"]),
            &rel("packages/b")
        ));
    }

    /// #1097: npm (minimatch) and yarn (classic node-glob, berry
    /// micromatch) match extglobs in `workspaces`; probed on npm 10.9,
    /// yarn 1.22.22 and yarn 4.10.
    #[test]
    fn extglob_dialects_match_like_npm_and_yarn() {
        let rel = |p: &str| p.split('/').map(str::to_string).collect::<Vec<_>>();
        let pats = |p: &[&str]| p.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let npm = WorkspacesDialect::NPM;
        let yes = |p: &str, r: &str| {
            assert!(
                workspaces_include_as(&pats(&[p]), &rel(r), npm),
                "{p} ~ {r}"
            )
        };
        let no = |p: &str, r: &str| {
            assert!(
                !workspaces_include_as(&pats(&[p]), &rel(r), npm),
                "{p} !~ {r}"
            )
        };
        yes("packages/@(a|b)", "packages/a");
        yes("packages/@(a|b)", "packages/b");
        no("packages/@(a|b)", "packages/c");
        no("packages/@(a|b)", "packages/ab");
        yes("packages/+(a|c)", "packages/c");
        yes("packages/+(a|c)", "packages/aca");
        no("packages/+(a|c)", "packages/b");
        yes("packages/*(a|b)", "packages/ab");
        no("packages/*(a|b)", "packages/c");
        yes("packages/?(a)", "packages/a");
        no("packages/?(a)", "packages/aa");
        yes("packages/!(z)", "packages/a");
        yes("packages/!(z)", "packages/zz");
        no("packages/!(z)", "packages/z");
        yes("packages/!(z)-x", "packages/a-x");
        no("packages/!(z)-x", "packages/z-x");
        // Globs, classes and nesting inside the alternatives.
        yes("packages/@(pkg-*|[xy])", "packages/pkg-one");
        yes("packages/@(pkg-*|[xy])", "packages/y");
        yes("packages/@(a|@(b|c))d", "packages/cd");
        yes("packages/pre-@(a|b)-post", "packages/pre-b-post");
        // An unclosed group is literal; braces expand around a group.
        yes("packages/@(a", "packages/@(a");
        yes("{apps,packages}/@(a|b)", "apps/b");
        // Without extglobs (Bun, vlt, uv, pnpm) the group is literal.
        assert!(!workspaces_include(
            &pats(&["packages/@(a|b)"]),
            &rel("packages/a")
        ));
        assert!(!glob_matches("packages/@(a|b)", &rel("packages/a")));
        assert!(!workspaces_include_as(
            &pats(&["packages/@(a|b)"]),
            &rel("packages/a"),
            WorkspacesDialect::BUN
        ));
    }

    /// #1490: yarn berry reads `workspaces` with globby / fast-glob /
    /// picomatch, which also take regex groups, POSIX classes and `..`
    /// segments; probed on yarn 4.0.2 and 4.18.1.
    #[test]
    fn yarn_berry_reads_picomatch_syntax() {
        let rel = |p: &str| p.split('/').map(str::to_string).collect::<Vec<_>>();
        let pats = |p: &[&str]| p.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let berry = WorkspacesDialect::YARN_BERRY;
        let yes = |p: &[&str], r: &str| {
            assert!(
                workspaces_include_as(&pats(p), &rel(r), berry),
                "{p:?} ~ {r}"
            )
        };
        let no = |p: &[&str], r: &str| {
            assert!(
                !workspaces_include_as(&pats(p), &rel(r), berry),
                "{p:?} !~ {r}"
            )
        };
        // Regex groups with alternatives.
        yes(&["packages/(a|b)"], "packages/a");
        yes(&["packages/(a|b)"], "packages/b");
        no(&["packages/(a|b)"], "packages/c");
        no(&["packages/(a|b)"], "packages/(a|b)");
        yes(&["packages/pkg-(a|b)"], "packages/pkg-a");
        no(&["packages/pkg-(a|b)"], "packages/pkg-c");
        yes(&["(packages|apps)/x"], "apps/x");
        yes(&["packages/(a*|z)"], "packages/abc");
        yes(&["packages/((a|b)|c)"], "packages/b");
        // A group without `|` is literal in a static pattern (fast-glob
        // reads it as a path) and a group in a dynamic one.
        no(&["packages/(a)"], "packages/a");
        yes(&["packages/(a)"], "packages/(a)");
        yes(&["packages/*/(a)"], "packages/x/a");
        // A negated group excludes what it matches.
        no(&["packages/*", "!packages/(b|c)"], "packages/b");
        yes(&["packages/*", "!packages/(b|c)"], "packages/a");
        // Extglobs still read as before.
        yes(&["packages/@(a|b)"], "packages/a");
        yes(&["packages/!(z)"], "packages/a");
        no(&["packages/!(z)"], "packages/z");
        // POSIX classes, alone or beside other members.
        yes(&["packages/[[:alpha:]]"], "packages/a");
        no(&["packages/[[:alpha:]]"], "packages/1");
        yes(&["packages/[[:digit:]]x"], "packages/1x");
        no(&["packages/[[:digit:]]x"], "packages/ax");
        yes(&["packages/[[:upper:]0-9]"], "packages/7");
        yes(&["packages/[![:alpha:]]"], "packages/1");
        no(&["packages/[![:alpha:]]"], "packages/a");
        yes(&["packages/[[:alnum:]_]*"], "packages/_x");
        yes(&["packages/[[:punct:]]a"], "packages/-a");
        // `..` segments resolve against the segment before them.
        yes(&["packages/a/../b"], "packages/b");
        no(&["packages/a/../b"], "packages/a/b");
        no(&["packages/a/../b"], "packages/a");
        yes(&["packages/*/../b"], "packages/b");
        yes(&["packages/a/b/../../c"], "packages/c");
        no(&["../b"], "b");
        // The plain shapes keep matching.
        yes(&["packages/[a-c]"], "packages/b");
        yes(&["packages/./a"], "packages/a");
        // Other dialects keep their grammar.
        for dialect in [
            WorkspacesDialect::NPM,
            WorkspacesDialect::YARN_CLASSIC,
            WorkspacesDialect::BUN,
            WorkspacesDialect::VLT,
        ] {
            assert!(
                !workspaces_include_as(&pats(&["packages/(a|b)"]), &rel("packages/a"), dialect),
                "{dialect:?}"
            );
        }
        assert!(!glob_matches("packages/(a|b)", &rel("packages/a")));
    }

    /// #1097: yarn classic and Bun before 1.3 ignore `!` patterns, so a
    /// negated directory the positive patterns match stays a member; npm
    /// and Bun 1.3+ drop it unless a later pattern lists it again, and
    /// yarn berry drops it whatever the order. Probed on npm 10.9, yarn
    /// 1.22.22, yarn 4.10, Bun 1.2.23 and Bun 1.4.2.
    #[test]
    fn negation_is_per_dialect() {
        use WorkspacesDialect as D;
        let rel = |p: &str| p.split('/').map(str::to_string).collect::<Vec<_>>();
        let pats = |p: &[&str]| p.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let negated_last = pats(&["packages/*", "!packages/b"]);
        let negated_first = pats(&["!packages/b", "packages/*"]);
        let relisted = pats(&["packages/*", "!packages/b", "packages/b"]);
        for (dialect, last, first, again) in [
            (D::NPM, false, true, true),
            (D::BUN, false, true, true),
            (D::VLT, false, true, true),
            (D::YARN_BERRY, false, false, false),
            (D::YARN_CLASSIC, true, true, true),
            (D::BUN_PRE_1_3, true, true, true),
        ] {
            let b = rel("packages/b");
            assert_eq!(
                workspaces_include_as(&negated_last, &b, dialect),
                last,
                "{dialect:?}"
            );
            assert_eq!(
                workspaces_include_as(&negated_first, &b, dialect),
                first,
                "{dialect:?}"
            );
            assert_eq!(
                workspaces_include_as(&relisted, &b, dialect),
                again,
                "{dialect:?}"
            );
            assert!(workspaces_include_as(
                &negated_last,
                &rel("packages/a"),
                dialect
            ));
        }
        // A leading `!(` is an extglob to yarn berry (every top-level
        // directory but `internal`), a negation of `(internal)` to npm,
        // and lists nothing to yarn classic.
        let bang_group = pats(&["!(internal)"]);
        assert!(workspaces_include_as(
            &bang_group,
            &rel("tools"),
            D::YARN_BERRY
        ));
        assert!(!workspaces_include_as(
            &bang_group,
            &rel("internal"),
            D::YARN_BERRY
        ));
        assert!(!workspaces_include_as(&bang_group, &rel("tools"), D::NPM));
        assert!(!workspaces_include_as(
            &bang_group,
            &rel("tools"),
            D::YARN_CLASSIC
        ));
        // A lone negation lists nothing in any dialect.
        for dialect in D::ALL {
            assert!(
                !workspaces_include_as(&pats(&["!packages/b"]), &rel("packages/b"), dialect),
                "{dialect:?}"
            );
        }
    }

    /// An ambiguous extglob decides in polynomial time (a review finding
    /// on #1480: plain backtracking took ~2^40 steps here).
    #[test]
    fn ambiguous_extglobs_stay_fast() {
        let rel = |p: &str| p.split('/').map(str::to_string).collect::<Vec<_>>();
        let long = format!("packages/{}b", "a".repeat(60));
        for pattern in [
            "packages/*(a|aa)c",
            "packages/+(*)x",
            "packages/!(*(a|aa))b",
        ] {
            let started = std::time::Instant::now();
            assert!(!workspaces_include_as(
                &[pattern.to_string()],
                &rel(&long),
                WorkspacesDialect::NPM
            ));
            assert!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "{pattern}"
            );
        }
        assert!(workspaces_include_as(
            &["packages/*(a|aa)b".to_string()],
            &rel(&long),
            WorkspacesDialect::NPM
        ));
    }

    #[test]
    fn pnpm_wildcards_skip_dot_components() {
        let rel = |p: &str| p.split('/').map(str::to_string).collect::<Vec<_>>();
        assert!(!glob_matches_no_dot("**", &rel(".github/actions/demo")));
        assert!(!glob_matches_no_dot(
            "packages/**",
            &rel("packages/.x/demo")
        ));
        assert!(!glob_matches_no_dot("packages/*", &rel("packages/.hidden")));
        assert!(!glob_matches_no_dot(
            "packages/?hidden",
            &rel("packages/.hidden")
        ));
        assert!(!glob_matches_no_dot("**/demo", &rel("a/.b/demo")));
        // An explicit dot component still matches, and below it wildcards
        // match ordinary names.
        assert!(glob_matches_no_dot(
            ".github/**",
            &rel(".github/actions/demo")
        ));
        assert!(glob_matches_no_dot(
            "packages/.hidden",
            &rel("packages/.hidden")
        ));
        assert!(glob_matches_no_dot("packages/.*", &rel("packages/.hidden")));
        assert!(glob_matches_no_dot("**", &rel("examples/demo")));
        assert!(glob_matches_no_dot("packages/**", &rel("packages/x/demo")));
    }
}
