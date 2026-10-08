//! yarn.lock key and locator patterns: how a block's key splits into its
//! descriptors (classic and berry quote them differently), how a
//! descriptor splits into name and range, and the berry `resolution:`
//! locator and `resolutions` selector forms. Shared by every yarn reader
//! and writer (see [`super::blocks`]).

/// Split a comma-joined key into its patterns, honoring quoting; the
/// surrounding quotes are dropped from each pattern.
pub(crate) fn split_key_patterns(key: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for ch in key.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                let p = cur.trim();
                if !p.is_empty() {
                    out.push(p.to_string());
                }
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    let p = cur.trim();
    if !p.is_empty() {
        out.push(p.to_string());
    }
    out
}

/// Split a berry lock key into its comma-joined descriptor patterns. yarn
/// wraps a multi-descriptor key in ONE outer quote pair (`"a@npm:^1,
/// a@npm:^2"`), so strip a single wrapping pair first, THEN split on `, ` —
/// that surfaces every descriptor (letting a genuinely mixed-name key be
/// detected as ambiguous) while a single quoted descriptor stays intact.
/// Twin of the TS `splitKeyPatterns`. The ONE berry key splitter: the
/// vendored and hosted berry backends and the lock inventory's
/// `berry_entries` (lockfile discovery's entry model) all read berry keys
/// with it — [`split_key_patterns`] is the classic grammar's, and treats
/// the outer pair as one quoted pattern.
pub(crate) fn split_berry_key_patterns(key: &str) -> Vec<String> {
    let trimmed = key.trim();
    let inner = if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };
    inner
        .split(", ")
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect()
}

/// Split `name@range` at the first `@` past a leading `@scope/` marker.
pub(crate) fn split_pattern(pattern: &str) -> Option<(&str, &str)> {
    let from = usize::from(pattern.starts_with('@'));
    let at = pattern[from..].find('@')? + from;
    let (name, range) = (&pattern[..at], &pattern[at + 1..]);
    if name.is_empty() || range.is_empty() {
        return None;
    }
    Some((name, range))
}

/// The real package a key pattern stands for: its name, unless the range is
/// an `npm:` alias — then the aliased target's name.
pub(crate) fn pattern_real_name(pattern: &str) -> Option<&str> {
    let (name, range) = split_pattern(pattern)?;
    if let Some(aliased) = range.strip_prefix("npm:") {
        return match split_pattern(aliased) {
            Some((real, _)) => Some(real),
            None => Some(aliased), // `npm:left-pad` with no range
        };
    }
    Some(name)
}

/// The one real package EVERY pattern of a classic key stands for
/// ([`pattern_real_name`]): `None` when there is no pattern, one does not
/// parse, or they name different packages.
pub(crate) fn classic_key_real_name(patterns: &[String]) -> Option<&str> {
    let mut names = patterns.iter().map(|p| pattern_real_name(p));
    let first = names.next()??;
    names.all(|n| n == Some(first)).then_some(first)
}

/// A classic `resolved` value split at its first `#`: the url before it,
/// and the fragment as a lowercase sha1 when it is 40 hex digits (either
/// case) — the legacy tarball verifier yarn v1 enforces when no
/// `integrity` line is present.
pub(crate) fn split_resolved_sha1(raw: &str) -> (&str, Option<String>) {
    match raw.split_once('#') {
        Some((url, frag)) => (url, crate::utils::digest::sha1_hex(frag)),
        None => (raw, None),
    }
}

/// A berry `resolution:` locator `name@<reference>`, split at the first `@`
/// past a leading `@scope/` marker ([`split_pattern`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BerryLocator<'a> {
    pub(crate) name: &'a str,
    pub(crate) reference: &'a str,
}

impl<'a> BerryLocator<'a> {
    /// `(version, bindings)` of a registry locator `npm:<version>[::<bindings>]`
    /// (`bindings` is `""` without a `::`); `None` for any other protocol.
    pub(crate) fn npm(&self) -> Option<(&'a str, &'a str)> {
        let npm = self.reference.strip_prefix("npm:")?;
        Some(npm.split_once("::").unwrap_or((npm, "")))
    }

    /// The `__archiveUrl=` binding of a registry locator (bindings are
    /// `&`-joined), still percent-encoded — what hosted redirects up to 5.0
    /// wrote (and what yarn itself writes for a custom registry).
    pub(crate) fn archive_url(&self) -> Option<&'a str> {
        self.npm()?
            .1
            .split('&')
            .find_map(|b| b.strip_prefix("__archiveUrl="))
    }
}

/// Parse a berry `resolution:` value into its locator.
pub(crate) fn parse_berry_locator(resolution: &str) -> Option<BerryLocator<'_>> {
    split_pattern(resolution).map(|(name, reference)| BerryLocator { name, reference })
}

/// The package a berry `resolutions` selector overrides: its LAST
/// descriptor's ident (`name`, `name@range`, `**/name`, `parent/name`,
/// `@scope/name`, `parent/@scope/name@range`), or `None` when it has none.
pub(crate) fn resolution_selector_target(selector: &str) -> Option<&str> {
    let s = selector.trim();
    // The last descriptor starts after the last `/` that is not a scope's
    // own separator (the segment before it starts with `@`).
    let mut start = 0;
    let bytes = s.as_bytes();
    let mut seg_start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'/' {
            if !s[seg_start..i].starts_with('@') {
                start = i + 1;
            }
            seg_start = i + 1;
        }
    }
    let last = &s[start..];
    let name = split_pattern(last).map(|(n, _)| n).unwrap_or(last);
    (!name.is_empty() && name != "**").then_some(name)
}

/// The package a berry `npm:<name>@<range>` alias range installs: `None`
/// for a plain `npm:<range>` (no alias, the descriptor's own package) or
/// any other protocol. Unlike [`pattern_real_name`], which answers for a
/// whole classic key pattern and reads a bare `npm:<name>` with no range as
/// an alias of `<name>`, this reads only the range, so a plain berry
/// `npm:^1` registry range is never mistaken for an alias target.
pub(crate) fn berry_npm_alias_target(range: &str) -> Option<&str> {
    let body = range.strip_prefix("npm:")?;
    split_pattern(body).map(|(real, _)| real)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolution_selector_targets() {
        for (sel, want) in [
            ("left-pad", Some("left-pad")),
            ("left-pad@npm:1.3.0", Some("left-pad")),
            ("**/left-pad", Some("left-pad")),
            ("parent/left-pad", Some("left-pad")),
            ("@scope/pkg", Some("@scope/pkg")),
            ("@p/parent/@scope/pkg@^2", Some("@scope/pkg")),
            ("@scope/parent/left-pad", Some("left-pad")),
            ("**", None),
            ("", None),
        ] {
            assert_eq!(resolution_selector_target(sel), want, "{sel}");
        }
    }
}
