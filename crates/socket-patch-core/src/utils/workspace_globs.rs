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
//! match a component that starts with `.` ([`glob_matches_no_dot`]), and
//! neither do Bun's and vlt's (`WorkspacesDialect::dot`).
//! npm, yarn and vlt also match extglobs (`@(a|b)`, `?(..)`, `*(..)`, `+(..)`,
//! `!(..)`) within one component, and yarn classic ignores `!` patterns;
//! [`WorkspacesDialect`] names what each package manager reads (#1097).
//! yarn berry's picomatch further reads regex groups (`(a|b)`), POSIX
//! classes (`[[:alpha:]]`) and `..` segments (#1490).
//!
//! Matching is pure. The one disk question here is [`bazel_owned`]: a walk
//! that expands a pattern over a tree asks it for each entry, because a
//! Bazel output tree is never a workspace member, whatever the pattern.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use crate::bazel::output_tree::{self, Entry, PathClass, TreeFs};
use crate::vendor::lock_inventory::view::ProjectView;

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
    /// `*`, `?` and `**` match a component that starts with `.`. vlt's
    /// node-glob (#1542) and Bun's glob (#1631) do not.
    pub(crate) dot: bool,
}

/// What a `workspaces` pattern with a leading `!` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Negation {
    /// It excludes what earlier patterns matched; a later pattern can
    /// list the directory again (npm, Bun 1.3+).
    LastMatchWins,
    /// It excludes the directory whatever the order (yarn berry's
    /// globby), and a leading `!(` is an extglob group, not a negation.
    Unordered,
    /// It is ignored: it neither excludes nor lists anything (yarn
    /// classic, Bun before 1.3).
    Ignored,
    /// It excludes the directory whatever the order, until a later
    /// pattern whose own text it matches lists it again; an even run of
    /// leading `!` cancels out (vlt 1.3's `splitNegatedPatterns`, #1542).
    Relisted,
    /// A leading `!` is not special: `!x` lists only a directory literally
    /// named so, and `!(..)` is an extglob group (vlt before 1.3, which
    /// globs every pattern as given, #1542).
    Literal,
}

impl WorkspacesDialect {
    /// npm (`package-lock.json`, `npm-shrinkwrap.json`).
    pub(crate) const NPM: Self = Self {
        negation: Negation::LastMatchWins,
        extglob: true,
        picomatch: false,
        dot: true,
    };
    /// yarn classic (a `yarn.lock` without berry's `__metadata`).
    pub(crate) const YARN_CLASSIC: Self = Self {
        negation: Negation::Ignored,
        extglob: true,
        picomatch: false,
        dot: true,
    };
    /// yarn berry (a `yarn.lock` with `__metadata`).
    pub(crate) const YARN_BERRY: Self = Self {
        negation: Negation::Unordered,
        extglob: true,
        picomatch: true,
        dot: true,
    };
    /// Bun 1.3 and later (a `bun.lock` with `configVersion`, or an
    /// untagged 1.3.0/1.3.1 lock that leaves an excluded member out,
    /// #1521).
    pub(crate) const BUN: Self = Self {
        negation: Negation::LastMatchWins,
        extglob: false,
        picomatch: false,
        dot: false,
    };
    /// Bun before 1.3: it lists `!`-negated directories anyway. An
    /// untagged lock reads this way until its workspace list shows it
    /// is 1.3.0/1.3.1's (`hosted::governing_root`, #1521).
    pub(crate) const BUN_PRE_1_3: Self = Self {
        negation: Negation::Ignored,
        extglob: false,
        picomatch: false,
        dot: false,
    };
    /// vlt 1.3 and later, probed on 1.3.8 (#1542).
    pub(crate) const VLT: Self = Self {
        negation: Negation::Relisted,
        extglob: true,
        picomatch: false,
        dot: false,
    };
    /// vlt before 1.3, probed on 1.2.0 (#1542). Both write the same
    /// `vlt-lock.json`, so `hosted::governing_root` tells them apart by the
    /// members the lock records.
    pub(crate) const VLT_PRE_1_3: Self = Self {
        negation: Negation::Literal,
        extglob: true,
        picomatch: false,
        dot: false,
    };
    /// Every dialect, for a root whose package manager is unknown: it lists
    /// a directory when any of them does.
    pub(crate) const ALL: [Self; 7] = [
        Self::NPM,
        Self::YARN_CLASSIC,
        Self::YARN_BERRY,
        Self::BUN,
        Self::BUN_PRE_1_3,
        Self::VLT,
        Self::VLT_PRE_1_3,
    ];
}

/// Whether the member path (`rel`, relative to the workspace root, one
/// entry per component) matches a `workspaces` pattern and no later
/// `!`-negated one, in npm's dialect.
#[cfg(test)]
pub(crate) fn workspaces_include(patterns: &[String], rel: &[String]) -> bool {
    workspaces_include_as(patterns, rel, WorkspacesDialect::NPM)
}

/// Whether the member path (`rel`, relative to the workspace root, one
/// entry per component) is listed by the `workspaces` `patterns`, read in
/// `dialect` (see [`Negation`] for what a `!` pattern does).
pub(crate) fn workspaces_include_as(
    patterns: &[String],
    rel: &[String],
    dialect: WorkspacesDialect,
) -> bool {
    if rel.is_empty() {
        return false;
    }
    // A pattern past the matcher's bounds ([`pattern_matches`]) lists every
    // directory and, as a `!` pattern, excludes none.
    let matches = |pattern: &str, negated: bool| {
        let picomatch = dialect.picomatch.then_some(Picomatch { negated });
        pattern_matches(
            pattern,
            rel,
            dialect.dot,
            dialect.extglob,
            picomatch,
            !negated,
        )
    };
    match dialect.negation {
        Negation::LastMatchWins => {
            let mut included = false;
            for pattern in patterns {
                let (negated, pattern) = split_negation(pattern);
                // Bun's walker skips dot components, but it filters the
                // walked directories through its `!` patterns with a plain
                // match that has no dot rule (as node-glob's ignore below).
                let hit = if negated {
                    pattern_matches(pattern, rel, true, dialect.extglob, None, false)
                } else {
                    matches(pattern, false)
                };
                if hit {
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
        Negation::Relisted => {
            let mut listed = false;
            let mut ignore: Vec<&str> = Vec::new();
            for pattern in patterns {
                let bangs = pattern.len() - pattern.trim_start_matches('!').len();
                let pattern = &pattern[bangs..];
                if bangs % 2 == 1 {
                    ignore.push(pattern);
                    continue;
                }
                // minimatch(pattern, ignore): the pattern's own text, read
                // as a path, against each earlier `!` glob.
                let text: Vec<String> = pattern
                    .split(['/', '\\'])
                    .filter(|s| !s.is_empty() && *s != ".")
                    .map(str::to_string)
                    .collect();
                // An ignore past the matcher's bounds is dropped here, as
                // one the pattern relists is: it excludes nothing.
                ignore.retain(|ign| !pattern_matches(ign, &text, false, true, None, true));
                listed |= matches(pattern, false);
            }
            // node-glob's ignore matches dot components.
            listed
                && !ignore
                    .iter()
                    .any(|ign| pattern_matches(ign, rel, true, dialect.extglob, None, false))
        }
        Negation::Literal => patterns.iter().any(|pattern| matches(pattern, false)),
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
    // Without groups every pattern is read whole ([`pattern_matches`]), so
    // the answer for one that is not never applies.
    pattern_matches(pattern, rel, true, false, None, true)
}

/// [`glob_matches`] the way pnpm's globber reads `packages:` (`dot: false`,
/// probed on pnpm 12.10.1): `*`, `?` and `**` never match a component that
/// starts with `.`, so `**` does not list `.github/actions/demo` and
/// `packages/*` does not list `packages/.hidden`. A pattern component that
/// itself starts with `.` (`.github/**`) still matches it.
pub(crate) fn glob_matches_no_dot(pattern: &str, rel: &[String]) -> bool {
    pattern_matches(pattern, rel, false, false, None, true)
}

/// How yarn berry's fast-glob / picomatch read a pattern beyond the shared
/// grammar (#1490, probed on yarn 4.0.2 and 4.18.1 and fast-glob 3.3.3):
/// a parenthesised group not led by an extglob character is a regex group
/// (`packages/(a|b)`), `?` and `+` after a group, `+` after a class and
/// `+` inside a group are regex quantifiers, a bracket class may hold
/// POSIX classes (`[[:alpha:]]`), and a `..` segment after a static
/// prefix steps back over the segment before it (`packages/a/../b` lists
/// `packages/b`).
#[derive(Debug, Clone, Copy)]
struct Picomatch {
    /// The pattern is a `!` one, which fast-glob matches as an ignore:
    /// every group is one, and a `..` segment is literal (so it excludes
    /// nothing).
    negated: bool,
}

/// fast-glob's `isDynamicPattern`: whether it matches a (brace-expanded)
/// pattern with picomatch rather than reading it as a literal path.
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

/// Longest brace alternative holding a group (or, read by picomatch, any
/// alternative) that is matched, in characters: group matching recurses
/// and rescans in proportion to it. minimatch and picomatch themselves
/// refuse a pattern past 65,536.
const MAX_GROUPED_CHARS: usize = 4096;

/// Most `(` in a brace alternative that is matched: each may open a group,
/// and the picomatch rewrite nests a call per group.
const MAX_GROUPS: usize = 64;

/// Most group-matcher steps ([`ExtglobMatcher`]) one pattern may take
/// against one path. An ambiguous group costs the cube of the component's
/// length, which a 255-character directory name turns into seconds per
/// brace alternative; the patterns package managers are given take a few
/// thousand.
const MAX_GROUP_STEPS: usize = 1 << 20;

/// Whether `pattern` matches `rel`. `unreadable` is the answer for a
/// brace alternative with groups that is past the bounds above (its
/// length, its groups, the steps or depth matching it takes): fail closed,
/// so `true` where the pattern lists a directory and `false` where it
/// excludes one. Without `extglob` and `picomatch` there are no groups,
/// every alternative is read in pattern length × name length, and
/// `unreadable` never applies.
fn pattern_matches(
    pattern: &str,
    rel: &[String],
    dot: bool,
    extglob: bool,
    picomatch: Option<Picomatch>,
    unreadable: bool,
) -> bool {
    let rel: Vec<Vec<char>> = rel.iter().map(|c| c.chars().collect()).collect();
    let steps = std::cell::Cell::new(MAX_GROUP_STEPS);
    let matches = |alternative: &[char], static_path: bool| {
        let alternative: String = alternative.iter().collect();
        let mut segments: Vec<Vec<char>> = Vec::new();
        for segment in alternative
            .split(['/', '\\'])
            .filter(|s| !s.is_empty() && *s != ".")
        {
            if picomatch.is_some_and(|p| !p.negated) && segment == ".." {
                // fast-glob resolves `..` in a static pattern (a literal
                // path) and otherwise only through a static prefix; a `..`
                // above the workspace root lists nothing in it.
                let globbed = |s: &Vec<char>| s.iter().any(|c| "*?[(".contains(*c));
                if (!static_path && segments.iter().any(globbed)) || segments.pop().is_none() {
                    return false;
                }
                continue;
            }
            segments.push(segment.chars().collect());
        }
        !segments.is_empty()
            && path_glob_matches(&segments, &rel, dot, extglob, picomatch.is_some(), &steps)
                .unwrap_or(unreadable)
    };
    expand_braces(pattern.trim()).iter().any(|alternative| {
        let chars: Vec<char> = alternative.chars().collect();
        let count = |open: char| chars.iter().filter(|c| **c == open).count();
        let Some(p) = picomatch else {
            let groups = if extglob { count('(') } else { 0 };
            if groups > MAX_GROUPS || (groups > 0 && chars.len() > MAX_GROUPED_CHARS) {
                return unreadable;
            }
            return matches(&chars, false);
        };
        // The rewrite below reads the alternative once per group and per
        // class, and writes it once per spelling.
        if chars.len() > MAX_GROUPED_CHARS
            || count('(') > MAX_GROUPS
            || count('[') > MAX_GROUPS
            || steps.get() < chars.len()
        {
            return unreadable;
        }
        // fast-glob reads a static pattern as a literal path, where a
        // group without `|` is plain text.
        let static_path = !p.negated && !fast_glob_dynamic(alternative);
        let mut spelled = Vec::new();
        if !expand_slash_groups(&chars, !static_path, &mut spelled) {
            // A shape this matcher cannot read fails closed: it lists
            // every directory and, as a `!` pattern, excludes none.
            return !p.negated;
        }
        let written: usize = spelled.iter().map(Vec::len).sum();
        steps.set(steps.get().saturating_sub(written));
        spelled.iter().any(|spelling| {
            picomatch_as_extglob(spelling, !static_path, false)
                .is_some_and(|rewritten| matches(&rewritten, static_path))
        })
    })
}

/// The spellings of a picomatch pattern with every group whose
/// alternatives hold a `/` (`(packages/ui|apps/web)`) expanded in place,
/// as brace sets are, so each alternative is matched across its path
/// components, each read as inside a group (`x+` repeats `x`). Groups
/// without a `/` are left for [`picomatch_as_extglob`]. `false` when a
/// `?` or `+` quantifies such a group: the repeated or skipped `/` cannot
/// be read component by component, so the caller fails closed.
fn expand_slash_groups(p: &[char], every_group: bool, out: &mut Vec<Vec<char>>) -> bool {
    if out.len() >= MAX_BRACE_EXPANSIONS {
        return true;
    }
    let mut i = 0;
    while i < p.len() {
        if p[i] == '[' {
            if let Some((_, after)) = char_class(&p[i + 1..], true) {
                i = p.len() - after.len();
                continue;
            }
        }
        let led = i > 0 && matches!(p[i - 1], '@' | '?' | '*' | '+' | '!');
        if p[i] == '(' && !led {
            if let Some((close, alternatives)) = group_alternatives(p, i) {
                if (alternatives.len() > 1 || every_group)
                    && alternatives.iter().any(|a| a.contains(&'/'))
                {
                    let rest = close + 1;
                    if matches!(p.get(rest), Some('?' | '+')) && p.get(rest + 1) != Some(&'(') {
                        return false;
                    }
                    let mut fills: Vec<Vec<char>> = Vec::new();
                    for alternative in alternatives {
                        let mut inner = Vec::new();
                        if !expand_slash_groups(alternative, every_group, &mut inner) {
                            return false;
                        }
                        fills.extend(
                            inner
                                .iter()
                                .filter_map(|a| picomatch_as_extglob(a, every_group, true)),
                        );
                    }
                    for fill in fills {
                        let mut spelling = p[..i].to_vec();
                        spelling.extend(fill);
                        spelling.extend_from_slice(&p[rest..]);
                        if !expand_slash_groups(&spelling, every_group, out) {
                            return false;
                        }
                        if out.len() >= MAX_BRACE_EXPANSIONS {
                            return true;
                        }
                    }
                    return true;
                }
            }
        }
        i += 1;
    }
    out.push(p.to_vec());
    true
}

/// A picomatch pattern rewritten into the extglob grammar
/// [`ExtglobMatcher`] reads: a regex group (`(a|b)`, or any group with
/// `every_group`) becomes `@(a|b)`, `?(a|b)` when a `?` follows it and
/// `+(a|b)` when a `+` does; `[ab]+` becomes `+([ab])`, and inside a
/// group (`in_group`) `x+` becomes `+(x)`. [`expand_slash_groups`] has
/// already spelled out regex groups holding a `/`; one left inside an
/// extglob group can never match one component, so it is dropped, and
/// `None` when a group has no alternative left (the pattern lists
/// nothing).
fn picomatch_as_extglob(p: &[char], every_group: bool, in_group: bool) -> Option<Vec<char>> {
    let mut out: Vec<char> = Vec::with_capacity(p.len());
    let mut i = 0;
    while i < p.len() {
        match p[i] {
            '[' => {
                let Some((_, after)) = char_class(&p[i + 1..], true) else {
                    out.push('[');
                    i += 1;
                    continue;
                };
                let end = p.len() - after.len();
                // `+(` after a class opens an extglob, not a quantifier.
                if after.first() == Some(&'+') && after.get(1) != Some(&'(') {
                    out.extend(['+', '(']);
                    out.extend_from_slice(&p[i..end]);
                    out.push(')');
                    i = end + 1;
                } else {
                    out.extend_from_slice(&p[i..end]);
                    i = end;
                }
            }
            '(' => {
                let led = i > 0 && matches!(p[i - 1], '@' | '?' | '*' | '+' | '!');
                let Some((close, alternatives)) = group_alternatives(p, i) else {
                    out.push('(');
                    i += 1;
                    continue;
                };
                if !led && alternatives.len() < 2 && !every_group {
                    out.push('(');
                    i += 1;
                    continue;
                }
                let mut rewritten = Vec::new();
                for alternative in alternatives {
                    if !alternative.contains(&'/') {
                        rewritten.push(picomatch_as_extglob(alternative, every_group, true)?);
                    }
                }
                if rewritten.is_empty() {
                    return None;
                }
                let mut next = close + 1;
                if !led {
                    // `?(` / `+(` after the group opens an extglob instead.
                    let kind = match p.get(next) {
                        Some(&q @ ('?' | '+')) if p.get(next + 1) != Some(&'(') => {
                            next += 1;
                            q
                        }
                        _ => '@',
                    };
                    out.push(kind);
                }
                out.push('(');
                for (n, alternative) in rewritten.into_iter().enumerate() {
                    if n > 0 {
                        out.push('|');
                    }
                    out.extend(alternative);
                }
                out.push(')');
                i = next;
            }
            '+' if in_group
                && p.get(i + 1) != Some(&'(')
                && out.last().is_some_and(|c| !"*?)]/|+".contains(*c)) =>
            {
                let repeated = out.pop().expect("checked above");
                out.extend(['+', '(', repeated, ')']);
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Some(out)
}

/// The `)` closing the `(` at `open`, and the group's top-level
/// `|`-separated alternatives. Classes are skipped whole, so a `)` or `|`
/// inside `[...]` is a member, as picomatch reads it.
fn group_alternatives(p: &[char], open: usize) -> Option<(usize, Vec<&[char]>)> {
    let (mut depth, mut start, mut i) = (0usize, open + 1, open);
    let mut alternatives = Vec::new();
    while i < p.len() {
        match p[i] {
            '[' => {
                if let Some((_, after)) = char_class(&p[i + 1..], true) {
                    i = p.len() - after.len();
                    continue;
                }
            }
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    alternatives.push(&p[start..i]);
                    return Some((i, alternatives));
                }
            }
            '|' if depth == 1 => {
                alternatives.push(&p[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Cap on the alternatives one pattern expands to, so a pathological
/// sequence (`{1..1000000}`) cannot stall the run.
const MAX_BRACE_EXPANSIONS: usize = 4096;

/// Cap on the text one pattern's expansion builds, the partly expanded
/// patterns on the way to an alternative included. Every group expanded
/// copies the rest of the pattern, so a long pattern of many groups
/// (`{a,b}` a hundred thousand times over) would otherwise build gigabytes
/// before its first alternative, and every alternative is then matched
/// against each path. 4,096 alternatives of 250 bytes fit.
const MAX_BRACE_BYTES: usize = 1 << 20;

/// The brace expansion of a glob, as minimatch's `brace-expansion` does it:
/// the first `{...}` group holding a top-level `,` or a `x..y[..step]`
/// sequence is replaced by each alternative, and each result expanded the
/// same way. A group with neither, and an unbalanced `{`, stay literal.
/// Past [`MAX_BRACE_EXPANSIONS`] alternatives or [`MAX_BRACE_BYTES`] of
/// text the expansion stops with the alternatives it has.
pub(crate) fn expand_braces(pattern: &str) -> Vec<String> {
    brace_expansion(pattern).0
}

/// [`expand_braces`] for a caller that walks each alternative itself:
/// `None` when the pattern has more alternatives than the matcher expands,
/// so a walk over the ones it returned would miss some.
pub(crate) fn brace_alternatives(pattern: &str) -> Option<Vec<String>> {
    let (alternatives, whole) = brace_expansion(pattern.trim());
    (whole && alternatives.len() < MAX_BRACE_EXPANSIONS).then_some(alternatives)
}

/// [`expand_braces`], and whether the expansion is whole (it stopped at
/// neither cap).
fn brace_expansion(pattern: &str) -> (Vec<String>, bool) {
    let mut out = Vec::new();
    let mut bytes = MAX_BRACE_BYTES;
    // Depth first with the next alternative on top, so the alternatives
    // come out in the order expanding the first group first gives them.
    // A stack of patterns rather than a call per group: the groups of one
    // pattern have no bound a call stack could be sized for.
    let mut pending = vec![pattern.to_string()];
    while let Some(pattern) = pending.pop() {
        if out.len() >= MAX_BRACE_EXPANSIONS {
            return (out, false);
        }
        let Some((open, close, alternatives)) = first_brace_group(&pattern) else {
            out.push(pattern);
            continue;
        };
        let (prefix, suffix) = (&pattern[..open], &pattern[close + 1..]);
        for alternative in alternatives.iter().rev() {
            let expanded = format!("{prefix}{alternative}{suffix}");
            let Some(left) = bytes.checked_sub(expanded.len()) else {
                return (out, false);
            };
            bytes = left;
            pending.push(expanded);
        }
    }
    (out, true)
}

/// The first `{...}` group of `pattern` that expands: the byte offsets of
/// its braces and its alternatives. Every `{` is paired with its `}` in
/// one pass (a scan per `{` is quadratic in a pattern of unclosed ones),
/// which also notes whether a `,` or another `{` sits directly inside.
fn first_brace_group(pattern: &str) -> Option<(usize, usize, Vec<String>)> {
    struct Group {
        open: usize,
        close: Option<usize>,
        comma: bool,
        nests: bool,
    }
    let mut groups: Vec<Group> = Vec::new();
    // The groups still open, innermost last, as indices into `groups`.
    let mut open: Vec<usize> = Vec::new();
    for (at, c) in pattern.char_indices() {
        match c {
            '{' => {
                if let Some(&outer) = open.last() {
                    groups[outer].nests = true;
                }
                open.push(groups.len());
                groups.push(Group {
                    open: at,
                    close: None,
                    comma: false,
                    nests: false,
                });
            }
            '}' => {
                if let Some(closed) = open.pop() {
                    groups[closed].close = Some(at);
                }
            }
            ',' => {
                if let Some(&inner) = open.last() {
                    groups[inner].comma = true;
                }
            }
            _ => {}
        }
    }
    groups.into_iter().find_map(|group| {
        let close = group.close?;
        let body = &pattern[group.open + 1..close];
        let alternatives = if group.comma {
            split_top_level_commas(body)
        } else if group.nests && body != "{..}" && !body.starts_with("{..}..") {
            // The one sequence that holds a brace runs from the character
            // `{` to `}`. Any other body with a group inside is not read:
            // a pattern of nested groups would be read once per group.
            return None;
        } else {
            brace_sequence(body)?
        };
        Some((group.open, close, alternatives))
    })
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
    // A fourth part is one too many, and all that needs finding out.
    let parts: Vec<&str> = body.splitn(4, "..").collect();
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
    // The zero padding is as wide as the body is long, so the items are
    // held to the expansion's text bound as well as its count.
    let mut bytes = 0;
    loop {
        out.push(if as_char {
            char::from_u32(u32::try_from(n).ok()?)?.to_string()
        } else {
            // `{n:0width$}` by hand: the width is the pattern's to choose,
            // and `format!` panics on one past 65,535.
            let (sign, digits) = (if n < 0 { "-" } else { "" }, n.unsigned_abs().to_string());
            let zeros = width.saturating_sub(sign.len() + digits.len());
            format!("{sign}{}{digits}", "0".repeat(zeros))
        });
        bytes += out.last().map_or(0, String::len);
        if n == end || out.len() >= MAX_BRACE_EXPANSIONS || bytes > MAX_BRACE_BYTES {
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
///
/// A `**` segment takes any number of components, and a pattern may hold
/// many, so the answer is filled in from the last segment back rather than
/// by trying each number of components every `**` could take (which is
/// exponential in the `**` count): at most one component match per
/// (segment, component) pair. `None` when matching a group ran out of
/// `steps` or nested too deep ([`component_matches`]).
fn path_glob_matches(
    pattern: &[Vec<char>],
    path: &[Vec<char>],
    dot: bool,
    ext: bool,
    posix: bool,
    steps: &std::cell::Cell<usize>,
) -> Option<bool> {
    let hidden = |component: &Vec<char>| !dot && component.first() == Some(&'.');
    // `tail[at]`: the segments after the one being read match `path[at..]`.
    // No segments match only the end of the path.
    let mut tail = vec![false; path.len() + 1];
    tail[path.len()] = true;
    for segment in pattern.iter().rev() {
        if segment.as_slice() == ['*', '*'] {
            // No component, or one that is not hidden and then `**` again.
            for at in (0..path.len()).rev() {
                tail[at] = tail[at] || (!hidden(&path[at]) && tail[at + 1]);
            }
        } else {
            for at in 0..path.len() {
                tail[at] = tail[at + 1]
                    && (!hidden(&path[at]) || segment.first() == Some(&'.'))
                    && component_matches(segment, &path[at], ext, posix, steps)?;
            }
            tail[path.len()] = false;
        }
    }
    Some(tail[0])
}

/// Whether one path component matches one pattern segment. `None` when the
/// segment holds a group and matching it took the last of `steps` or
/// nested past [`MAX_GROUP_DEPTH`].
fn component_matches(
    pattern: &[char],
    name: &[char],
    ext: bool,
    posix: bool,
    steps: &std::cell::Cell<usize>,
) -> Option<bool> {
    // An extglob group opens with a `(`. A segment without one is
    // wildcards, classes and literals in every dialect, read without a
    // call per character or a table.
    if !(ext && pattern.contains(&'(')) {
        return Some(wildcard_matches(pattern, name, posix));
    }
    let mut matcher = ExtglobMatcher::new(true, posix, steps.get());
    let matched = matcher.segment(pattern, name);
    steps.set(matcher.steps);
    (!matcher.gave_up).then_some(matched)
}

/// Whether one component matches a component pattern, without extglobs.
pub(crate) fn segment_glob_matches(pattern: &[char], name: &[char]) -> bool {
    wildcard_matches(pattern, name, false)
}

/// One step of a component pattern that holds no extglob group.
enum Wildcard {
    /// `*`: any run of characters, the empty one included.
    Run,
    /// `?`: any one character.
    One,
    /// `[...]`: one character of the class.
    Class(CharClass),
    /// The character itself (a `[` that opens no class included).
    Literal(char),
}

/// `pattern` as the steps it reads as, left to right.
fn wildcards(pattern: &[char], posix: bool) -> Vec<Wildcard> {
    let mut steps = Vec::with_capacity(pattern.len());
    let mut rest = pattern;
    // Without POSIX names a `[` stays open only when no `]` follows its
    // first member, so none follows a later `[` either: looking again for
    // each would read a pattern of unclosed `[` once per `[`. (A POSIX
    // name's own `]` can close a later class, so those are all read; only
    // picomatch reads them, and it is held to `MAX_GROUPED_CHARS`.)
    let mut unclosed = false;
    while let Some((&c, after)) = rest.split_first() {
        rest = after;
        steps.push(match c {
            '*' => Wildcard::Run,
            '?' => Wildcard::One,
            '[' if !unclosed => match char_class(after, posix) {
                Some((class, after_class)) => {
                    rest = after_class;
                    Wildcard::Class(class)
                }
                None => {
                    unclosed = !posix;
                    Wildcard::Literal('[')
                }
            },
            c => Wildcard::Literal(c),
        });
    }
    steps
}

/// Whether `name` matches a component pattern of `*`, `?`, classes and
/// literals (`posix`: the classes read POSIX names).
///
/// The steps are matched in order with one place to go back to, the last
/// `*` passed: when a later step fails, that `*` takes one more character
/// and the steps after it are tried again. An earlier `*` never has to
/// give anything back, because whatever it could give up the later one can
/// take. So the cost is at most pattern length × name length, where trying
/// every way each `*` can end is exponential in the number of `*`
/// (`*a*a*a*a*a*a*a*a*a*a*b` against sixty `a` never finished).
fn wildcard_matches(pattern: &[char], name: &[char], posix: bool) -> bool {
    let steps = wildcards(pattern, posix);
    let (mut step, mut at) = (0, 0);
    // The step after the last `*` passed, and where in `name` it resumes.
    let mut retry: Option<(usize, usize)> = None;
    while at < name.len() {
        let matched = match steps.get(step) {
            Some(Wildcard::Run) => {
                step += 1;
                retry = Some((step, at));
                continue;
            }
            Some(Wildcard::One) => true,
            Some(Wildcard::Class(class)) => class.matches(name[at]),
            Some(Wildcard::Literal(c)) => *c == name[at],
            None => false,
        };
        if matched {
            step += 1;
            at += 1;
        } else if let Some((after_run, resume)) = retry {
            step = after_run;
            at = resume + 1;
            retry = Some((after_run, resume + 1));
        } else {
            return false;
        }
    }
    steps[step..].iter().all(|s| matches!(s, Wildcard::Run))
}

/// One component matched against a pattern with extglob groups (`@(a|b)`,
/// `?(..)`, `*(..)`, `+(..)`, `!(..)`), as minimatch reads them. Every
/// (sub-pattern, name suffix) pair is decided once, so an ambiguous group
/// (`*(a|aa)`) costs polynomial time, not exponential.
///
/// Polynomial is still the cube of the name's length times the pattern's,
/// and the matcher calls itself once per pattern character, so its work
/// is bounded: past `steps` or [`MAX_GROUP_DEPTH`] it stops and sets
/// `gave_up`, and the answer it returned means nothing.
struct ExtglobMatcher {
    /// Extglob groups match; off, they are literal.
    extglob: bool,
    /// Brackets read POSIX classes (picomatch, #1490).
    posix: bool,
    memo: std::collections::HashMap<(usize, usize, usize, usize), bool>,
    /// Steps left ([`MAX_GROUP_STEPS`], shared by the brace alternatives
    /// and components of one pattern).
    steps: usize,
    /// How many of its own calls the matcher is inside.
    depth: usize,
    /// The matcher ran out of steps or depth.
    gave_up: bool,
}

/// Deepest the group matcher calls itself: a call per character matched
/// since the last group, and one per repetition of a `*(..)` or `+(..)`.
/// Twice the longest directory name a filesystem holds.
const MAX_GROUP_DEPTH: usize = 512;

impl ExtglobMatcher {
    fn new(extglob: bool, posix: bool, steps: usize) -> Self {
        ExtglobMatcher {
            extglob,
            posix,
            memo: std::collections::HashMap::new(),
            steps,
            depth: 0,
            gave_up: false,
        }
    }

    /// One more call, `cost` steps, if the bounds allow it.
    fn enter(&mut self, cost: usize) -> bool {
        if self.gave_up || self.depth >= MAX_GROUP_DEPTH || self.steps < cost {
            self.gave_up = true;
            return false;
        }
        self.steps -= cost;
        self.depth += 1;
        true
    }

    fn segment(&mut self, pattern: &[char], name: &[char]) -> bool {
        let key = (
            pattern.as_ptr() as usize,
            pattern.len(),
            name.as_ptr() as usize,
            name.len(),
        );
        // A lookup is a step too: a group's loops make one per split.
        // Finding where a group or a class closes reads the pattern after
        // it, to the end when it never does.
        let scans = pattern.first() == Some(&'[') || pattern.get(1) == Some(&'(');
        let cost = 1 + if scans { pattern.len() / 8 } else { 0 };
        if !self.enter(cost) {
            return false;
        }
        let matched = match self.memo.get(&key) {
            Some(&known) => known,
            None => {
                let matched = self.segment_uncached(pattern, name);
                self.memo.insert(key, matched);
                matched
            }
        };
        self.depth -= 1;
        matched
    }

    fn segment_uncached(&mut self, pattern: &[char], name: &[char]) -> bool {
        if let Some(group) = extglob_group(pattern, self.posix).filter(|_| self.extglob) {
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
        if !self.enter(1) {
            return false;
        }
        let matched = self.segment(group.rest, name)
            || (1..=name.len()).any(|split| {
                group
                    .alternatives
                    .iter()
                    .any(|alt| self.segment(alt, &name[..split]))
                    && self.repeat(group, &name[split..])
            });
        self.depth -= 1;
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
/// minimatch). A class is skipped whole, so a `)` or `|` inside `[...]`
/// is a member.
fn extglob_group(pattern: &[char], posix: bool) -> Option<ExtglobGroup<'_>> {
    let kind = *pattern.first()?;
    if !matches!(kind, '@' | '?' | '*' | '+' | '!') || pattern.get(1) != Some(&'(') {
        return None;
    }
    let body = &pattern[2..];
    let (mut depth, mut start) = (0usize, 0usize);
    let mut alternatives = Vec::new();
    let mut i = 0;
    // As in `wildcards`: once a `[` stays open, so does every later one.
    let mut unclosed = false;
    while i < body.len() {
        let c = body[i];
        if c == '[' && !unclosed {
            if let Some((_, after)) = char_class(&body[i + 1..], posix) {
                i = body.len() - after.len();
                continue;
            }
            unclosed = !posix;
        }
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
        i += 1;
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
            if let Some(end) = name_end {
                if let Some(class) = posix_class(&pattern[i + 2..end].iter().collect::<String>()) {
                    ranges.extend_from_slice(class);
                    i = end + 2;
                    continue;
                }
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

/// Whether the entry at `rel` (a path as `view` reads it) is Bazel's and
/// not the project's, so that a glob expansion leaves it out: it is never
/// a workspace member and is never entered (hazard HZ-17).
///
/// Bazel puts its trees where a wide pattern reaches them (`*`, `**`, and
/// the `.` of the `pnpm-workspace.yaml` hosted and vendored mode write):
/// four convenience links in the workspace root, under any
/// `--symlink_prefix`, and sometimes an output base or a vendor directory
/// inside the checkout. The execution root mirrors every top-level entry of
/// the workspace, `package.json` included. A walk that does not follow
/// links takes such a link for a member it cannot inspect, and one that
/// enters an output base reads thousands of fetched and mirrored manifests
/// as the project's own; either way every npm package ends up withheld.
///
/// `true` only on proof, by the markers Bazel writes and never by a name
/// (`bazel::output_tree`):
///
/// - a directory that is the root of an output base, of a contents-cache or
///   repository-cache entry, or of a vendor directory;
/// - a link to such a root;
/// - a link outside every such tree that leads into one
///   ([`PathClass::Link`]).
///
/// Anything else is left to the caller, which handles it as it did before:
/// a marker the disk would not show, a link in an in-memory project (it
/// has no target to judge), and an entry *inside* a tree whose root lies
/// above the walk. In the last case the whole walk runs inside Bazel's
/// tree, which is for the caller's scope check to refuse, not for a member
/// walk to hide.
pub(crate) fn bazel_owned(view: &ProjectView<'_>, rel: &str) -> bool {
    // Read through a link as well: a link to a tree's root shows the
    // markers of that root. No rc file is read here, so a `--vendor_dir`
    // is known by the marker `bazel vendor` writes into it; before that
    // run the directory holds nothing to take for a member.
    let own = output_tree::tree_at(&ViewTree(view), Path::new(rel), &[]);
    if own.tree.is_some() {
        return true;
    }
    if !view.is_symlink(rel) {
        return false;
    }
    // Where a link leads only the disk knows. The link is fingerprinted
    // (entry and target), the markers of the tree it leads into are not:
    // Bazel writes them when a server first starts in an output base and
    // removes them only with the base, which takes the link's target along.
    let Some(root) = view.disk_root_reading([rel]) else {
        return false;
    };
    crate::crawlers::bazel_output::classify(&root.join(rel)).class == PathClass::Link
}

/// What is behind a [`ProjectView`], as the marker rules ask for it. Only
/// [`output_tree::tree_at`] is put to it, which asks for no link target.
struct ViewTree<'a, 'v>(&'a ProjectView<'v>);

impl TreeFs for ViewTree<'_, '_> {
    fn stat(&self, path: &Path) -> Entry {
        // `/`-separated, the way a view (and an in-memory key) spells it.
        let rel = if path.is_absolute() {
            path.to_string_lossy().into_owned()
        } else {
            let names = path.components().map(|c| c.as_os_str().to_string_lossy());
            names.collect::<Vec<_>>().join("/")
        };
        // Named to the view first, so a recording snapshot fingerprints
        // each marker the answer rests on.
        let Some(root) = self.0.disk_root_reading([&rel]) else {
            return if self.0.is_file(&rel) {
                Entry::File
            } else if self.0.is_dir(&rel) {
                Entry::Dir
            } else {
                Entry::Neither
            };
        };
        // One `stat` per marker (`is_file` then `is_dir` would be two),
        // and an error that is not "absent" stays unknown.
        use std::io::ErrorKind::{InvalidFilename, NotADirectory, NotFound};
        match std::fs::metadata(root.join(&rel)) {
            Ok(meta) if meta.is_file() => Entry::File,
            Ok(meta) if meta.is_dir() => Entry::Dir,
            Ok(_) => Entry::Neither,
            Err(err) => match err.kind() {
                NotFound | NotADirectory | InvalidFilename => Entry::Neither,
                _ => Entry::Unknown,
            },
        }
    }

    fn read_link(&self, _path: &Path) -> Option<PathBuf> {
        None
    }
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
        // A `)` or `|` inside a class is a member, not the group's end.
        yes("packages/@(a|[)|])", "packages/a");
        yes("packages/@(a|[)|])", "packages/)");
        no("packages/@(a|[)|])", "packages/b");
        // An unclosed group is literal; braces expand around a group.
        yes("packages/@(a", "packages/@(a");
        yes("{apps,packages}/@(a|b)", "apps/b");
        // Without extglobs (Bun, uv, pnpm) the group is literal.
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
        yes(&["packages/(a|[)])"], "packages/a");
        yes(&["packages/(a|)"], "packages/a");
        no(&["packages/(a|)"], "packages");
        // An alternative holding `/` matches across components (Bugbot on
        // #1493: listing it fails closed).
        yes(&["packages/(a/b|c)"], "packages/c");
        yes(&["packages/(a/b|c)"], "packages/a/b");
        yes(&["(packages/ui|packages/core)"], "packages/core");
        no(&["(packages/ui|packages/core)"], "packages/web");
        // An in-group `+` still reads as picomatch's; a quantified one
        // fails closed (Bugbot on #1493): it lists every directory, and
        // as a `!` pattern excludes none.
        yes(&["(packages/a|apps/b)?x"], "x");
        yes(&["(packages/a|apps/b)?x"], "elsewhere");
        yes(&["(a|b/c)+"], "a/a");
        yes(&["packages/*", "!(packages/a|apps/b)?"], "packages/a");
        yes(&["(packages/a+|apps/b)"], "packages/aaa");
        no(&["(packages/a+|apps/b)"], "packages/a+");
        yes(&["(packages/(x|y)|apps/b)"], "packages/y");
        // Regex quantifiers after a group or class, and inside a group.
        yes(&["packages/(a|b)?"], "packages/a");
        no(&["packages/(a|b)?"], "packages/ab");
        yes(&["packages/(a|b)+"], "packages/ab");
        yes(&["packages/[ab]+"], "packages/abba");
        no(&["packages/[ab]+"], "packages/abc");
        yes(&["packages/(a+|c)"], "packages/aaa");
        no(&["packages/(a+|c)"], "packages/a+");
        // `?(` / `+(` right after a group or class opens an extglob.
        yes(&["packages/(a|b)?(c|d)"], "packages/a");
        yes(&["packages/(a|b)?(c|d)"], "packages/ac");
        yes(&["packages/(a|b)?(c|d)"], "packages/bd");
        yes(&["packages/(a|b)+(c)"], "packages/acc");
        yes(&["packages/[ab]+(c)"], "packages/bc");
        no(&["packages/[ab]+(c)"], "packages/b");
        no(&["packages/*", "!packages/(a|b)?(c)"], "packages/ac");
        // A group without `|` in a static pattern (fast-glob reads it as
        // a path) never lists the directory its group names; listing the
        // literal `(a)` fails closed. In a dynamic one it is a group.
        no(&["packages/(a)"], "packages/a");
        yes(&["packages/(a)"], "packages/(a)");
        yes(&["packages/*/(a)"], "packages/x/a");
        // fast-glob decides that per brace alternative.
        no(&["packages/{(a),c}"], "packages/a");
        yes(&["packages/{(a),c}"], "packages/c");
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
        yes(&["packages/a/b/../../c"], "packages/c");
        no(&["../b"], "b");
        // A static pattern is a literal path, `(a)` included.
        yes(&["packages/(a)/../b"], "packages/b");
        // Only through a static prefix, and never in an ignore.
        no(&["packages/*/../b"], "packages/b");
        yes(&["packages/*", "!packages/a/../b"], "packages/b");
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
            (D::VLT, false, false, true),
            (D::VLT_PRE_1_3, true, true, true),
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

    /// #1631: Bun's workspace glob never lets `*`, `?` or `**` match a
    /// component that starts with `.`, probed on Bun 1.1.39, 1.2.23, 1.3.9
    /// and 1.4.3 (`packages/*` does not list `packages/.hidden`,
    /// `packages/**` does not list `packages/.cache/x`); a pattern
    /// component that spells the dot still matches it.
    #[test]
    fn bun_wildcards_skip_dot_components() {
        use WorkspacesDialect as D;
        let rel = |p: &str| p.split('/').map(str::to_string).collect::<Vec<_>>();
        let pats = |p: &[&str]| p.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for dialect in [D::BUN, D::BUN_PRE_1_3] {
            for (patterns, dir, listed) in [
                (&["packages/*"][..], "packages/.hidden", false),
                (&["packages/*"], "packages/a", true),
                (&["packages/**"], "packages/.cache/x", false),
                (&["packages/**"], "packages/x/y", true),
                (&["packages/?hidden"], "packages/.hidden", false),
                (&["**"], ".github/x", false),
                (&["packages/.hidden"], "packages/.hidden", true),
                (&["packages/.*"], "packages/.hidden", true),
                (&["packages/.cache/*"], "packages/.cache/x", true),
                // A `!` pattern still excludes a dot directory an explicit
                // pattern listed.
                (
                    &["packages/.hidden", "!packages/*"],
                    "packages/.hidden",
                    dialect == D::BUN_PRE_1_3,
                ),
                (
                    &["packages/.*", "!packages/**"],
                    "packages/.hidden",
                    dialect == D::BUN_PRE_1_3,
                ),
            ] {
                assert_eq!(
                    workspaces_include_as(&pats(patterns), &rel(dir), dialect),
                    listed,
                    "{dialect:?}: {patterns:?} ~ {dir}"
                );
            }
        }
    }

    /// #1542: vlt reads `workspaces` with node-glob / minimatch, probed on
    /// vlt 1.2.0 and 1.3.8 (`vlt install` then `vlt query ':workspace'`
    /// over `packages/{a,b,ab,c,.h}`): extglobs match, and wildcards skip a
    /// component that starts with `.`. vlt 1.3 drops a `!` pattern's
    /// directories wherever the pattern sits, until a later pattern whose
    /// own text it matches lists them again (`splitNegatedPatterns`); vlt
    /// before 1.3 reads a leading `!` literally, so `!x` lists nothing and
    /// `!(..)` is an extglob.
    #[test]
    fn vlt_dialects_list_what_vlt_lists() {
        use WorkspacesDialect as D;
        let rel = |p: &str| p.split('/').map(str::to_string).collect::<Vec<_>>();
        let pats = |p: &[&str]| p.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // (patterns, directory, vlt 1.3 lists it, vlt 1.2 lists it)
        for (patterns, dir, current, pre_1_3) in [
            (&["packages/+(a|b)"][..], "packages/a", true, true),
            (&["packages/+(a|b)"], "packages/ab", true, true),
            (&["packages/+(a|b)"], "packages/c", false, false),
            (&["packages/@(a|b)"], "packages/b", true, true),
            (&["packages/@(a|b)"], "packages/ab", false, false),
            (&["packages/?(a)b"], "packages/ab", true, true),
            (&["packages/*(a)"], "packages/a", true, true),
            (&["packages/*(a)"], "packages/b", false, false),
            (&["packages/!(a)"], "packages/b", true, true),
            (&["packages/!(a)"], "packages/a", false, false),
            (&["packages/(a|b)"], "packages/a", false, false),
            (&["packages/{a,b}"], "packages/a", true, true),
            (&["packages/[ab]"], "packages/b", true, true),
            (&["packages/*"], "packages/.h", false, false),
            (&["**"], ".gh/x", false, false),
            (&["packages/.h"], "packages/.h", true, true),
            (&["!packages/a", "packages/*"], "packages/a", false, true),
            (&["!packages/a", "packages/*"], "packages/b", true, true),
            (&["packages/*", "!packages/a"], "packages/a", false, true),
            (
                &["packages/*", "!packages/a", "packages/a"],
                "packages/a",
                true,
                true,
            ),
            (
                &["packages/*", "!packages/a", "packages/[a]"],
                "packages/a",
                false,
                true,
            ),
            (&["!packages/*", "packages/a"], "packages/a", true, true),
            (&["packages/a", "!packages/*"], "packages/a", false, true),
            (
                &["!packages/a", "packages/@(a|b)"],
                "packages/a",
                false,
                true,
            ),
            (
                &["!packages/@(a|b)", "packages/a"],
                "packages/a",
                true,
                true,
            ),
            (&["!!packages/a"], "packages/a", true, false),
            (&["!(apps)/a"], "packages/a", false, true),
            (&["packages/*", "!(apps)/a"], "packages/a", true, true),
        ] {
            let patterns = pats(patterns);
            let dir = rel(dir);
            assert_eq!(
                workspaces_include_as(&patterns, &dir, D::VLT),
                current,
                "vlt 1.3: {patterns:?} ~ {dir:?}"
            );
            assert_eq!(
                workspaces_include_as(&patterns, &dir, D::VLT_PRE_1_3),
                pre_1_3,
                "vlt 1.2: {patterns:?} ~ {dir:?}"
            );
        }
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

    /// `decide`'s answer, or a failure when it has not answered in a
    /// minute. It runs on its own thread: a matcher that backtracks
    /// exponentially never returns, and a test waiting on it would hang
    /// the suite instead of failing.
    fn decided<T: Send + 'static>(decide: impl FnOnce() -> T + Send + 'static) -> T {
        let (answer, wait) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = answer.send(decide());
        });
        wait.recv_timeout(std::time::Duration::from_secs(60))
            .expect("the glob matcher did not decide within a minute")
    }

    /// A component pattern of many `*` against a long name that almost
    /// matches is decided at once in every dialect: `*a*a*a*a*a*a*a*a*a*a*b`
    /// against sixty `a` took plain backtracking about 10^11 steps, so one
    /// such directory hung `scan`.
    #[test]
    fn many_stars_against_a_long_name_decide_at_once() {
        let stars = format!("build/{}b", "*a".repeat(10));
        let near_miss = vec!["build".to_string(), "a".repeat(60)];
        let hit = vec!["build".to_string(), format!("{}b", "a".repeat(60))];
        let answers = decided(move || {
            let mut answers = Vec::new();
            for rel in [&near_miss, &hit] {
                for dialect in WorkspacesDialect::ALL {
                    answers.push(workspaces_include_as(
                        std::slice::from_ref(&stars),
                        rel,
                        dialect,
                    ));
                }
                answers.push(glob_matches(&stars, rel));
                answers.push(glob_matches_no_dot(&stars, rel));
                let pattern: Vec<char> = stars["build/".len()..].chars().collect();
                let name: Vec<char> = rel[1].chars().collect();
                answers.push(segment_glob_matches(&pattern, &name));
            }
            answers
        });
        let (missed, matched) = answers.split_at(answers.len() / 2);
        assert!(missed.iter().all(|listed| !listed), "{missed:?}");
        assert!(matched.iter().all(|listed| *listed), "{matched:?}");

        // The cost is pattern length × name length, whatever the pattern:
        // a thousand stars against a name as long as a file name gets.
        let pattern: Vec<char> = format!("{}b", "*a".repeat(1000)).chars().collect();
        let name: Vec<char> = "a".repeat(255).chars().collect();
        assert!(!decided(move || segment_glob_matches(&pattern, &name)));
    }

    /// `**` segments are decided in pattern segments × path components:
    /// twenty of them against a forty-deep path that does not end in the
    /// name they lead to took the recursive matcher about 10^15 steps.
    #[test]
    fn repeated_globstars_decide_at_once() {
        let globstars = format!("build/{}zz", "**/".repeat(20));
        let interleaved = format!("build/{}zz", "**/a/".repeat(20));
        let deep = |last: &str| {
            let mut rel = vec!["build".to_string()];
            rel.extend(std::iter::repeat_n("a".to_string(), 40));
            rel.push(last.to_string());
            rel
        };
        let (near_miss, hit) = (deep("a"), deep("zz"));
        let answers = decided(move || {
            let mut answers = Vec::new();
            for rel in [&near_miss, &hit] {
                for pattern in [&globstars, &interleaved] {
                    for dialect in WorkspacesDialect::ALL {
                        answers.push(workspaces_include_as(
                            std::slice::from_ref(pattern),
                            rel,
                            dialect,
                        ));
                    }
                    answers.push(glob_matches(pattern, rel));
                    answers.push(glob_matches_no_dot(pattern, rel));
                }
            }
            answers
        });
        let (missed, matched) = answers.split_at(answers.len() / 2);
        assert!(missed.iter().all(|listed| !listed), "{missed:?}");
        assert!(matched.iter().all(|listed| *listed), "{matched:?}");
    }

    /// A group pattern whose matching would take hours is not worked out:
    /// it reads as unreadable, which lists every directory and, as a `!`
    /// pattern, excludes none. Sixty `*(a|aa)` groups against one
    /// 255-character directory name take the matcher seconds, and twelve
    /// two-way brace sets in front make that 4,096 times over.
    #[test]
    fn a_group_pattern_past_the_step_bound_fails_closed() {
        let costly = format!("build/{}{}x", "{a,b}".repeat(12), "*(a|aa)".repeat(60));
        let rel = vec!["build".to_string(), "a".repeat(255)];
        let extglob_dialects = WorkspacesDialect::ALL
            .into_iter()
            .filter(|dialect| dialect.extglob);
        let answers = decided(move || {
            let mut answers = Vec::new();
            for dialect in extglob_dialects {
                let listed = workspaces_include_as(std::slice::from_ref(&costly), &rel, dialect);
                let excluding = ["build/*".to_string(), format!("!{costly}")];
                let kept = workspaces_include_as(&excluding, &rel, dialect);
                answers.push((dialect, listed, kept));
            }
            answers
        });
        assert_eq!(answers.len(), 5);
        for (dialect, listed, kept) in answers {
            assert!(listed, "{dialect:?}: an unreadable pattern lists");
            assert!(kept, "{dialect:?}: an unreadable `!` pattern excludes none");
        }
        // The dialects without groups read the same text as literals.
        let rel = vec!["build".to_string(), "a".repeat(255)];
        let costly = format!("build/{}x", "*(a|aa)".repeat(60));
        assert!(!workspaces_include_as(
            std::slice::from_ref(&costly),
            &rel,
            WorkspacesDialect::BUN
        ));
    }

    /// The group matcher calls itself per pattern character, and the
    /// picomatch rewrite per group: a pattern long or nested enough to
    /// overflow the stack (a hundred kilobytes of `*` after a group, fifty
    /// thousand nested parentheses) is unreadable instead, so it lists
    /// every directory and excludes none.
    #[test]
    fn a_group_pattern_past_the_size_bounds_fails_closed() {
        let rel = vec!["build".to_string(), "a".repeat(10)];
        let cases = [
            format!("build/@(a){}", "*".repeat(100_000)),
            format!("build/{}a|b{}", "(".repeat(50_000), ")".repeat(50_000)),
            format!("build/{}", "@(a|b)".repeat(MAX_GROUPS + 1)),
            format!("build/@(a|b){}", "?".repeat(MAX_GROUPED_CHARS)),
            // Within the size bounds, past the depth one.
            format!("build/@(a){}", "*".repeat(2_000)),
        ];
        let answers = decided(move || {
            let mut answers = Vec::new();
            for pattern in &cases {
                for dialect in WorkspacesDialect::ALL {
                    if !dialect.extglob {
                        continue;
                    }
                    let listed =
                        workspaces_include_as(std::slice::from_ref(pattern), &rel, dialect);
                    let excluding = ["build/*".to_string(), format!("!{pattern}")];
                    let kept = workspaces_include_as(&excluding, &rel, dialect);
                    answers.push((pattern.len(), dialect, listed, kept));
                }
            }
            answers
        });
        for (len, dialect, listed, kept) in answers {
            assert!(listed, "{dialect:?}: a {len}-byte pattern lists");
            assert!(kept, "{dialect:?}: a {len}-byte `!` pattern excludes none");
        }
        // A group-free pattern of any length is still read, in every
        // dialect: it needs no call per character.
        let long = format!("build/{}", "?".repeat(100_000));
        let name = vec!["build".to_string(), "a".repeat(100_000)];
        let answers = decided(move || {
            WorkspacesDialect::ALL
                .into_iter()
                .filter(|dialect| !dialect.picomatch)
                .map(|dialect| workspaces_include_as(std::slice::from_ref(&long), &name, dialect))
                .collect::<Vec<_>>()
        });
        assert_eq!(answers, [true; 6]);
    }

    /// The patterns package managers are given stay far inside the step
    /// bound: the costliest shapes here, against names of fifty to 240
    /// characters, use under a twentieth of it.
    #[test]
    fn ordinary_group_patterns_stay_inside_the_step_bound() {
        let long = format!("{}b", "a".repeat(60));
        for (pattern, name, want) in [
            ("*(a|aa)c", long.as_str(), false),
            ("+(*)x", &long, false),
            ("!(*(a|aa))b", &long, false),
            ("*(a|aa)b", &long, true),
            ("@(pkg-*|[xy])", "pkg-one", true),
            ("!(node_modules|dist|build)", "some-package-name-here", true),
            (
                "@(alpha|beta|gamma|delta|epsilon|zeta|eta|theta)-*",
                "theta-service-with-a-long-name",
                true,
            ),
            (
                "!(*-internal|*-private)",
                "a-fairly-long-package-directory-name-of-fifty-chars",
                true,
            ),
            (
                "+(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|-)",
                "a-fairly-long-package-directory-name-of-fifty-chars",
                true,
            ),
            ("+(a|b)", &"ab".repeat(120), true),
        ] {
            let p: Vec<char> = pattern.chars().collect();
            let n: Vec<char> = name.chars().collect();
            let steps = std::cell::Cell::new(MAX_GROUP_STEPS);
            assert_eq!(
                component_matches(&p, &n, true, false, &steps),
                Some(want),
                "{pattern} ~ {name}"
            );
            let used = MAX_GROUP_STEPS - steps.get();
            assert!(used < MAX_GROUP_STEPS / 20, "{pattern} ~ {name}: {used}");
        }
    }

    /// The brace expansion this module had before the one that keeps its
    /// own stack: a call per group, a scan per `{`. Kept as the oracle.
    fn recursive_brace_expansion(pattern: &str, out: &mut Vec<String>) {
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
                recursive_brace_expansion(&format!("{prefix}{alternative}{suffix}"), out);
                if out.len() >= MAX_BRACE_EXPANSIONS {
                    return;
                }
            }
            return;
        }
        out.push(pattern.to_string());
    }

    /// The expansion that keeps its own stack gives the alternatives the
    /// recursive one gave, in its order, on 20,000 seeded patterns of
    /// nested, unbalanced, empty and sequence groups (the `{..}` character
    /// sequence included), and says the same of whether they are all of
    /// them.
    #[test]
    fn brace_expansion_agrees_with_the_recursive_one() {
        const ALPHABET: &[&str] = &[
            "a",
            "b",
            "/",
            "*",
            "{",
            "{",
            "}",
            "}",
            ",",
            ",",
            "..",
            "1",
            "3",
            "{a,b}",
            "{1..3}",
            "{a..c}",
            "{..}",
            "{{..}..2}",
            "{,x}",
            "{a}",
            "{3..1..2}",
            "{01..3}",
            "é",
        ];
        let mut rng = crate::test_rng::Rng::new(0x53);
        let (mut expanded, mut capped) = (0, 0);
        // Patterns at and past the cap on alternatives first.
        let mut patterns = vec![
            "{a,b}".repeat(12),
            "{a,b}".repeat(13),
            "x{1..4095}".to_string(),
            "x{1..5000}y".to_string(),
            "{1..70}/{1..70}".to_string(),
            " packages/{a,b} ".to_string(),
        ];
        patterns
            .extend((0..20_000).map(|_| random_text(&mut rng, ALPHABET, 12).into_iter().collect()));
        for (case, pattern) in patterns.into_iter().enumerate() {
            let mut want = Vec::new();
            recursive_brace_expansion(&pattern, &mut want);
            assert_eq!(expand_braces(&pattern), want, "case {case}: {pattern:?}");
            assert_eq!(
                brace_alternatives(&pattern),
                (want.len() < MAX_BRACE_EXPANSIONS).then(|| {
                    let mut trimmed = Vec::new();
                    recursive_brace_expansion(pattern.trim(), &mut trimmed);
                    trimmed
                }),
                "case {case}: {pattern:?}"
            );
            expanded += usize::from(want.len() > 1);
            capped += usize::from(want.len() >= MAX_BRACE_EXPANSIONS);
        }
        assert!(expanded > 5_000, "{expanded}");
        assert!(capped > 0, "{capped}");
    }

    /// A pattern of very many brace groups is expanded within a megabyte
    /// of text and no call stack: `{a,b}` four thousand times over
    /// overflowed the stack, a hundred thousand times would have built
    /// gigabytes on the way to its first alternative.
    #[test]
    fn brace_expansion_is_bounded_in_text_and_stack() {
        let cases = [
            "{a,b}".repeat(100_000),
            "{1..1}".repeat(50_000),
            // Unclosed and nested groups: nothing expands, in one pass.
            "{".repeat(300_000),
            format!("{}{}", "{".repeat(150_000), "}".repeat(150_000)),
            format!("{}{}", "{{..}x".repeat(50_000), "}".repeat(50_000)),
            // A zero padding as wide as the pattern is long.
            format!("{{{}1..9999}}", "0".repeat(300_000)),
        ];
        let answers = decided(move || {
            cases
                .iter()
                .map(|pattern| {
                    let alternatives = expand_braces(pattern);
                    let text: usize = alternatives.iter().map(String::len).sum();
                    (
                        alternatives.len(),
                        text,
                        brace_alternatives(pattern).map(|whole| whole.len()),
                        // The matcher reads what was expanded and no more.
                        glob_matches(pattern, &["a".to_string()]),
                    )
                })
                .collect::<Vec<_>>()
        });
        let within = |(count, text, ..): &(usize, usize, Option<usize>, bool)| {
            *count <= MAX_BRACE_EXPANSIONS && *text <= MAX_BRACE_BYTES + 300_010
        };
        assert!(answers.iter().all(within), "{answers:?}");
        let whole: Vec<Option<usize>> = answers.iter().map(|a| a.2).collect();
        assert_eq!(whole, [None, None, Some(1), Some(1), Some(1), None]);
        assert!(answers.iter().all(|a| !a.3), "{answers:?}");
    }

    /// A zero-padded sequence pads to the width of its longer end,
    /// whatever that is: `{0…01..2}` with seventy thousand zeros is two
    /// long names, where `format!`'s own width (65,535 at most) panicked.
    #[test]
    fn zero_padded_sequences_pad_to_any_width() {
        assert_eq!(expand_braces("{08..10}"), ["08", "09", "10"]);
        assert_eq!(expand_braces("{-01..1}"), ["-01", "000", "001"]);
        assert_eq!(expand_braces("{1..-02}"), ["001", "000", "-01", "-02"]);
        assert_eq!(expand_braces("{007..9..2}"), ["007", "009"]);
        let wide = expand_braces(&format!("v{{{}1..2}}", "0".repeat(70_000)));
        assert_eq!(wide.len(), 2);
        for (alternative, last) in wide.iter().zip(["1", "2"]) {
            assert_eq!(alternative.len(), 70_002);
            assert_eq!(
                alternative.trim_start_matches('v').trim_start_matches('0'),
                last
            );
        }
    }

    /// A component pattern of unclosed `[` is read in one pass: looking
    /// for the `]` of each would read it once per `[`.
    #[test]
    fn unclosed_classes_are_read_in_one_pass() {
        let pattern: Vec<char> = "[".repeat(300_000).chars().collect();
        let name: Vec<char> = "[".repeat(255).chars().collect();
        let whole: Vec<char> = "[".repeat(300_000).chars().collect();
        // The same run inside a group, whose end is looked for past it.
        let grouped: Vec<char> = format!("@({}|a)", "[".repeat(100_000)).chars().collect();
        let answers = decided(move || {
            [
                segment_glob_matches(&pattern, &name),
                segment_glob_matches(&pattern, &whole),
                component_matches(&grouped, &['a'], true, false, &unbounded()) == Some(true),
            ]
        });
        assert_eq!(answers, [false, true, true]);
    }

    /// The component matcher this module had before the linear one: one
    /// recursive call per way a `*` can end, so the plainest statement of
    /// what a pattern matches and, on a crafted pattern, exponential. Kept
    /// as the oracle the linear matcher is compared against.
    fn backtracking_segment_matches(pattern: &[char], name: &[char], posix: bool) -> bool {
        let rec = |pattern, name| backtracking_segment_matches(pattern, name, posix);
        match pattern.split_first() {
            None => name.is_empty(),
            Some(('*', rest)) => (0..=name.len()).any(|skip| rec(rest, &name[skip..])),
            Some(('?', rest)) => !name.is_empty() && rec(rest, &name[1..]),
            Some(('[', rest)) => match char_class(rest, posix) {
                Some((class, after)) => name
                    .split_first()
                    .is_some_and(|(c, tail)| class.matches(*c) && rec(after, tail)),
                None => name.first() == Some(&'[') && rec(rest, &name[1..]),
            },
            Some((c, rest)) => name.first() == Some(c) && rec(rest, &name[1..]),
        }
    }

    /// The path matcher this module had before the table-filling one, over
    /// any component matcher: it tries every number of components each
    /// `**` can take, one recursive call each.
    fn backtracking_path_matches(
        pattern: &[Vec<char>],
        path: &[Vec<char>],
        dot: bool,
        component: &dyn Fn(&[char], &[char]) -> bool,
    ) -> bool {
        let hidden = |component: &Vec<char>| !dot && component.first() == Some(&'.');
        match pattern.split_first() {
            None => path.is_empty(),
            Some((first, rest)) if first.as_slice() == ['*', '*'] => (0..=path.len())
                .take_while(|&skip| skip == 0 || !hidden(&path[skip - 1]))
                .any(|skip| backtracking_path_matches(rest, &path[skip..], dot, component)),
            Some((first, rest)) => path.split_first().is_some_and(|(head, tail)| {
                (!hidden(head) || first.first() == Some(&'.'))
                    && component(first, head)
                    && backtracking_path_matches(rest, tail, dot, component)
            }),
        }
    }

    /// A step budget no test pattern reaches.
    fn unbounded() -> std::cell::Cell<usize> {
        std::cell::Cell::new(usize::MAX)
    }

    /// A short random string over `alphabet` (whole fragments, so a class
    /// or a group shows up closed more often than chance would close it).
    fn random_text(rng: &mut crate::test_rng::Rng, alphabet: &[&str], max: usize) -> Vec<char> {
        (0..rng.below(max + 1))
            .flat_map(|_| rng.pick(alphabet).chars())
            .collect()
    }

    const NAME_ALPHABET: &[&str] = &["a", "a", "b", "b", "c", ".", "-", "[", "]", "!", "é"];

    /// The linear component matcher answers as the backtracking one did,
    /// on 40,000 seeded pattern/name pairs over the whole grammar (`*`,
    /// `?`, classes with ranges, negation, a leading `]` and POSIX names,
    /// unclosed classes), short enough for the oracle to finish.
    #[test]
    fn linear_component_matcher_agrees_with_backtracking() {
        const PATTERN_ALPHABET: &[&str] = &[
            "a",
            "a",
            "b",
            "c",
            ".",
            "-",
            "*",
            "*",
            "*",
            "?",
            "?",
            "[",
            "]",
            "!",
            "^",
            "[ab]",
            "[!a]",
            "[^b]",
            "[a-c]",
            "[]a]",
            "[!]]",
            "[[:alpha:]]",
            "[![:punct:]b]",
            "[:",
            ":]",
            "é",
        ];
        let mut rng = crate::test_rng::Rng::new(0x51);
        let (mut matched, mut classes) = (0, 0);
        for case in 0..40_000 {
            let pattern = random_text(&mut rng, PATTERN_ALPHABET, 9);
            let name = if rng.chance(30) {
                // A name the pattern is likely to match: its literals, with
                // each wildcard and bracket turned into a character.
                pattern
                    .iter()
                    .filter(|c| !rng.chance(10) && **c != '*')
                    .map(|c| if "?[]!^:".contains(*c) { 'a' } else { *c })
                    .collect()
            } else {
                random_text(&mut rng, NAME_ALPHABET, 7)
            };
            for posix in [false, true] {
                let want = backtracking_segment_matches(&pattern, &name, posix);
                assert_eq!(
                    wildcard_matches(&pattern, &name, posix),
                    want,
                    "case {case}: {pattern:?} ~ {name:?} (posix: {posix})"
                );
                // The extglob matcher reads a pattern without a group the
                // same way, which is what lets `component_matches` send
                // one to the linear matcher.
                for extglob in [false, true] {
                    let mut general = ExtglobMatcher::new(extglob, posix, usize::MAX);
                    assert_eq!(
                        general.segment(&pattern, &name),
                        want,
                        "case {case}: {pattern:?} ~ {name:?} (posix: {posix}, extglob: {extglob})"
                    );
                    assert_eq!(
                        component_matches(&pattern, &name, extglob, posix, &unbounded()),
                        Some(want),
                        "case {case}: {pattern:?} ~ {name:?} (posix: {posix}, extglob: {extglob})"
                    );
                }
                matched += usize::from(want);
            }
            assert_eq!(
                segment_glob_matches(&pattern, &name),
                backtracking_segment_matches(&pattern, &name, false),
                "case {case}: {pattern:?} ~ {name:?}"
            );
            classes += usize::from(char_class(&pattern, true).is_some());
        }
        // The sweep is not vacuous: thousands of pairs match, thousands do
        // not, and thousands of patterns hold a class that closes.
        assert!((4_000..76_000).contains(&matched), "{matched}");
        assert!(classes > 2_000, "{classes}");
    }

    /// The path matcher answers as the recursive one did, on 40,000 seeded
    /// pattern/path pairs with `**` segments, hidden components and every
    /// `dot` / extglob / POSIX reading.
    #[test]
    fn table_path_matcher_agrees_with_backtracking() {
        const SEGMENTS: &[&str] = &[
            "**",
            "**",
            "**",
            "*",
            "*",
            "a",
            "a",
            "b",
            ".a",
            ".*",
            "?",
            "a*",
            "*a",
            "[ab]",
            "@(a|b)",
            "!(a)",
            "+(a|.a)",
            "*(b)",
            "[[:alpha:]]",
            "a?",
        ];
        const COMPONENTS: &[&str] = &["a", "a", "a", "b", "b", ".a", ".b", "ab", "aa", "c"];
        let mut rng = crate::test_rng::Rng::new(0x52);
        let mut matched = 0;
        for case in 0..40_000 {
            let pattern: Vec<Vec<char>> = (0..rng.below(7))
                .map(|_| rng.pick(SEGMENTS).chars().collect())
                .collect();
            let path: Vec<Vec<char>> = (0..rng.below(7))
                .map(|_| rng.pick(COMPONENTS).chars().collect())
                .collect();
            for (dot, ext, posix) in [
                (true, false, false),
                (false, false, false),
                (true, true, false),
                (false, true, false),
                (true, true, true),
                (false, false, true),
            ] {
                // Each component as the recursive matcher decided it: the
                // extglob matcher when either flag is on, else the plain
                // one.
                let component = |segment: &[char], name: &[char]| {
                    if ext || posix {
                        ExtglobMatcher::new(ext, posix, usize::MAX).segment(segment, name)
                    } else {
                        backtracking_segment_matches(segment, name, false)
                    }
                };
                let want = backtracking_path_matches(&pattern, &path, dot, &component);
                assert_eq!(
                    path_glob_matches(&pattern, &path, dot, ext, posix, &unbounded()),
                    Some(want),
                    "case {case}: {pattern:?} ~ {path:?} (dot: {dot}, ext: {ext}, posix: {posix})"
                );
                matched += usize::from(want);
            }
        }
        assert!((10_000..230_000).contains(&matched), "{matched}");
    }

    fn put(root: &Path, rel: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "{}").unwrap();
    }

    /// HZ-17: a Bazel tree inside the checkout is known by the marker Bazel
    /// wrote at its root, on disk, under a snapshot and in memory alike. A
    /// name proves nothing, a marker name on the wrong kind of entry
    /// proves nothing, and a directory inside a tree is not a root.
    #[test]
    fn bazel_trees_are_known_by_their_markers_in_every_view() {
        use crate::vendor::lock_inventory::{DiskSnapshot, MemoryEntry, MemoryProject};

        const FILES: [&str; 12] = [
            // An output base (probe C8: `--output_base=<ws>/out`).
            "out/DO_NOT_BUILD_HERE",
            "out/execroot/_main/package.json",
            "out/external/npm__left-pad/package.json",
            // Vendor directories: 7.3 and later, and 7.1.2 to 7.2.1.
            "third_party/bazel/VENDOR.bazel",
            "third_party/bazel/npm__left-pad/package.json",
            "old_vendor/.vendorignore",
            // A contents-cache entry.
            "cache/contents/7f/0.recorded_inputs",
            "cache/contents/7f/0/package.json",
            // Named like Bazel's, or holding a marker's name, and plain.
            "bazel-bin/package.json",
            "notes/DO_NOT_BUILD_HERE",
            "docs/VENDOR.bazel/readme.md",
            "packages/a/package.json",
        ];
        let tmp = tempfile::tempdir().unwrap();
        let mut memory = MemoryProject::new();
        for rel in FILES {
            put(tmp.path(), rel);
            memory.insert(rel, MemoryEntry::Present);
        }
        let snapshot = DiskSnapshot::new(tmp.path());
        let views = [
            ProjectView::Disk(tmp.path()),
            ProjectView::Snapshot(&snapshot),
            ProjectView::Memory(&memory),
        ];
        for (rel, owned) in [
            ("out", true),
            ("third_party/bazel", true),
            ("old_vendor", true),
            ("cache/contents/7f/0", true),
            ("out/external/npm__left-pad", false),
            ("third_party", false),
            ("bazel-bin", false),
            ("notes", false),
            ("docs", false),
            ("packages/a", false),
            ("absent", false),
        ] {
            for view in &views {
                assert_eq!(bazel_owned(view, rel), owned, "{rel} in {view:?}");
            }
        }
        // An absolute path is read as it is, as a walk spells an ancestor.
        let out = tmp.path().join("out");
        assert!(bazel_owned(&views[0], &out.to_string_lossy()));
    }

    /// HZ-17: a link is Bazel's when it leads into one of Bazel's trees,
    /// whatever it is called and whether or not its target still exists
    /// (probe B4: `--symlink_prefix=dist/` moves the links, and a `clean`
    /// leaves them stale). An ordinary link, a link whose output base is
    /// gone, and a link met by a walk that itself runs inside a tree are
    /// the caller's, as before.
    #[cfg(unix)]
    #[test]
    fn links_are_bazels_by_where_they_lead() {
        use crate::vendor::lock_inventory::{DiskSnapshot, MemoryEntry, MemoryProject};
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let (ws, base) = (tmp.path().join("ws"), tmp.path().join("user_root/0a1b"));
        let execroot = base.join("execroot/_main");
        put(&base, "DO_NOT_BUILD_HERE");
        put(&execroot, "bazel-out/k8-fastbuild/bin/package.json");
        put(&base, "external/repo/pkg/package.json");
        put(&ws, "packages/a/package.json");
        std::fs::create_dir_all(ws.join("dist")).unwrap();
        let out = execroot.join("bazel-out");
        for (link, target) in [
            ("bazel-bin", out.join("k8-fastbuild/bin")),
            ("bazel-ws", execroot.clone()),
            ("dist/bin", out.join("k8-fastbuild/bin")),
            // Never built: the link is stale and its base is live.
            ("bazel-testlogs", out.join("k8-fastbuild/testlogs")),
            ("base", base.clone()),
            ("member", ws.join("packages/a")),
            (
                "bazel-out",
                tmp.path().join("expunged/execroot/_main/bazel-out"),
            ),
        ] {
            symlink(target, ws.join(link)).unwrap();
        }
        let snapshot = DiskSnapshot::tracked(&ws);
        snapshot.begin_recording();
        for (link, owned) in [
            ("bazel-bin", true),
            ("bazel-ws", true),
            ("dist/bin", true),
            ("bazel-testlogs", true),
            ("base", true),
            ("member", false),
            ("bazel-out", false),
        ] {
            for view in [ProjectView::Disk(&ws), ProjectView::Snapshot(&snapshot)] {
                assert_eq!(bazel_owned(&view, link), owned, "{link} in {view:?}");
            }
        }
        assert!(
            snapshot.end_recording().is_some(),
            "judging a link must not cost the snapshot its recording"
        );

        // A listed link has no target: not judged.
        let mut memory = MemoryProject::new();
        memory.insert("bazel-bin", MemoryEntry::Symlink);
        assert!(!bazel_owned(&ProjectView::Memory(&memory), "bazel-bin"));

        // A project inside the output base (a repository rule's hook runs
        // there): its entries are in a tree, and none is a tree or a link
        // into one.
        let repo = base.join("external/repo");
        symlink(repo.join("pkg"), repo.join("link")).unwrap();
        for entry in ["pkg", "link"] {
            assert!(!bazel_owned(&ProjectView::Disk(&repo), entry), "{entry}");
        }
    }

    /// The markers an answer rested on are in the snapshot's read set, so a
    /// cached discovery is not reused once a directory has become a tree.
    #[test]
    fn a_recording_snapshot_fingerprints_the_markers() {
        use crate::vendor::lock_inventory::DiskSnapshot;

        let tmp = tempfile::tempdir().unwrap();
        put(tmp.path(), "third_party/npm__left-pad/package.json");
        let snapshot = DiskSnapshot::tracked(tmp.path());
        snapshot.begin_recording();
        assert!(!bazel_owned(
            &ProjectView::Snapshot(&snapshot),
            "third_party"
        ));
        let reads = snapshot.end_recording().expect("every probe is recorded");
        assert!(reads.unchanged());
        put(tmp.path(), "third_party/VENDOR.bazel");
        assert!(!reads.unchanged(), "a new marker must invalidate the reads");
        assert!(bazel_owned(&ProjectView::Disk(tmp.path()), "third_party"));
    }
}
