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

/// Whether the member path (`rel`, relative to the workspace root, one
/// entry per component) matches a `workspaces` pattern and no later
/// `!`-negated one (npm and yarn: the last matching pattern wins).
pub(crate) fn workspaces_include(patterns: &[String], rel: &[String]) -> bool {
    if rel.is_empty() {
        return false;
    }
    let mut included = false;
    for pattern in patterns {
        let (negated, pattern) = split_negation(pattern);
        if glob_matches(pattern, rel) {
            included = !negated;
        }
    }
    included
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
    pattern_matches(pattern, rel, true)
}

/// [`glob_matches`] the way pnpm's globber reads `packages:` (`dot: false`,
/// probed on pnpm 12.10.1): `*`, `?` and `**` never match a component that
/// starts with `.`, so `**` does not list `.github/actions/demo` and
/// `packages/*` does not list `packages/.hidden`. A pattern component that
/// itself starts with `.` (`.github/**`) still matches it.
pub(crate) fn glob_matches_no_dot(pattern: &str, rel: &[String]) -> bool {
    pattern_matches(pattern, rel, false)
}

fn pattern_matches(pattern: &str, rel: &[String], dot: bool) -> bool {
    let rel: Vec<Vec<char>> = rel.iter().map(|c| c.chars().collect()).collect();
    expand_braces(pattern.trim()).iter().any(|alternative| {
        let segments: Vec<Vec<char>> = alternative
            .split(['/', '\\'])
            .filter(|s| !s.is_empty() && *s != ".")
            .map(|s| s.chars().collect())
            .collect();
        !segments.is_empty() && path_glob_matches(&segments, &rel, dot)
    })
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

/// `dot: false` keeps wildcards off components starting with `.`.
fn path_glob_matches(pattern: &[Vec<char>], path: &[Vec<char>], dot: bool) -> bool {
    let hidden = |component: &Vec<char>| !dot && component.first() == Some(&'.');
    match pattern.split_first() {
        None => path.is_empty(),
        Some((first, rest)) if first.as_slice() == ['*', '*'] => (0..=path.len())
            .take_while(|&skip| skip == 0 || !hidden(&path[skip - 1]))
            .any(|skip| path_glob_matches(rest, &path[skip..], dot)),
        Some((first, rest)) => path.split_first().is_some_and(|(head, tail)| {
            (!hidden(head) || first.first() == Some(&'.'))
                && segment_glob_matches(first, head)
                && path_glob_matches(rest, tail, dot)
        }),
    }
}

pub(crate) fn segment_glob_matches(pattern: &[char], name: &[char]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some(('*', rest)) => (0..=name.len()).any(|skip| segment_glob_matches(rest, &name[skip..])),
        Some(('?', rest)) => !name.is_empty() && segment_glob_matches(rest, &name[1..]),
        Some(('[', rest)) => match char_class(rest) {
            Some((class, after)) => name
                .split_first()
                .is_some_and(|(c, tail)| class.matches(*c) && segment_glob_matches(after, tail)),
            None => name.first() == Some(&'[') && segment_glob_matches(rest, &name[1..]),
        },
        Some((c, rest)) => name.first() == Some(c) && segment_glob_matches(rest, &name[1..]),
    }
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
/// `^` first negates it; a `]` right after that is a member. `None` when
/// the class never closes (the `[` is then literal).
fn char_class(pattern: &[char]) -> Option<(CharClass, &[char])> {
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
