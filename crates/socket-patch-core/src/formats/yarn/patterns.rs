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

/// Split a classic key pattern `name@range` like [`split_pattern`], but
/// keep an EMPTY range (#1271): `""` is valid npm semver (the same as `*`),
/// and yarn 1 locks `"left-pad": ""` under `left-pad@:` — merged with other
/// ranges as `left-pad@, left-pad@^1.3.0:`. Berry never writes a rangeless
/// descriptor (its ranges carry a protocol), so the berry readers keep the
/// strict [`split_pattern`] and treat `name@` as malformed.
pub(crate) fn split_classic_pattern(pattern: &str) -> Option<(&str, &str)> {
    let from = usize::from(pattern.starts_with('@'));
    let at = pattern[from..].find('@')? + from;
    let (name, range) = (&pattern[..at], &pattern[at + 1..]);
    if name.is_empty() {
        return None;
    }
    Some((name, range))
}

/// The real package a key pattern stands for: its name, unless the range is
/// an `npm:` alias — then the aliased target's name.
pub(crate) fn pattern_real_name(pattern: &str) -> Option<&str> {
    real_name_with(pattern, split_pattern)
}

/// [`pattern_real_name`] over the classic grammar ([`split_classic_pattern`]):
/// a rangeless `left-pad@` stands for `left-pad`.
pub(crate) fn classic_pattern_real_name(pattern: &str) -> Option<&str> {
    real_name_with(pattern, split_classic_pattern)
}

fn real_name_with(pattern: &str, split: fn(&str) -> Option<(&str, &str)>) -> Option<&str> {
    let (name, range) = split(pattern)?;
    if let Some(aliased) = range.strip_prefix("npm:") {
        return match split(aliased) {
            Some((real, _)) => Some(real),
            None => Some(aliased), // `npm:left-pad` with no range
        };
    }
    Some(name)
}

/// The one real package EVERY pattern of a classic key stands for
/// ([`classic_pattern_real_name`]): `None` when there is no pattern, one
/// does not parse, or they name different packages.
pub(crate) fn classic_key_real_name(patterns: &[String]) -> Option<&str> {
    let mut names = patterns.iter().map(|p| classic_pattern_real_name(p));
    let first = names.next()??;
    names.all(|n| n == Some(first)).then_some(first)
}

/// What a berry `patch:` reference wraps, every layer peeled.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PatchLayers {
    /// The innermost source, percent-decoded (`left-pad@npm:1.3.0`,
    /// `left-pad@http://host/x.tgz`).
    pub source: String,
    /// Some layer applies a patch outside yarn's builtin compatibility
    /// namespace (`yarn patch`, or a plugin's own builtin).
    pub user_patch: bool,
}

/// Peel a berry `patch:` reference (`patch:…` or `name@patch:…`) layer by
/// layer: a compatibility patch can wrap a user patch, or vice versa, and
/// both still belong to the original package. `Ok(None)` when `spec` is no
/// patch reference; `Err` names a reference too odd to read.
pub(crate) fn patch_layers(spec: &str) -> Result<Option<PatchLayers>, &'static str> {
    use crate::utils::purl::percent_decode_purl_component;

    if !spec.starts_with("patch:") && !spec.contains("@patch:") {
        return Ok(None);
    }
    let mut source = spec.to_owned();
    let mut user_patch = false;
    for _ in 0..16 {
        let Some(inner) = source
            .strip_prefix("patch:")
            .or_else(|| source.split_once("@patch:").map(|(_, rest)| rest))
        else {
            return Ok(Some(PatchLayers { source, user_patch }));
        };
        let Some((original, patches)) = inner.split_once('#') else {
            return Err("unrecognized patch: reference");
        };
        // Only Yarn's compatibility namespace is exempt. Plugins can
        // supply their own builtin patches through getBuiltinPatch.
        let patches = percent_decode_purl_component(patches);
        user_patch |= !patches
            .split("::")
            .next()
            .unwrap_or(&patches)
            .split('&')
            .all(|p| {
                let p = p.rsplit('!').next().unwrap_or(p).trim_start_matches('~');
                p.starts_with("builtin<compat/") && p.ends_with('>')
            });
        source = percent_decode_purl_component(original).into_owned();
    }
    Err("patch locator nesting exceeds inspection limit")
}

/// The sources every user `patch:` reference in `text` (a berry lock or a
/// `package.json`) wraps, innermost layer first decoded
/// ([`patch_layers`]): `patch:left-pad@http%3A//h/x.tgz#~/.yarn/patches/
/// x.patch` wraps `left-pad@http://h/x.tgz`. Yarn's builtin compatibility
/// wrappers are not the user's and are left out.
pub(crate) fn user_patch_sources(text: &str) -> Vec<String> {
    text.match_indices("patch:")
        // The protocol opens a value (`"patch:`) or a range (`name@patch:`),
        // never the middle of a word: `x.patch::version=…` is no reference.
        .filter(|&(at, _)| {
            text[..at]
                .chars()
                .next_back()
                .is_none_or(|c| matches!(c, '@' | '"' | '\'') || c.is_whitespace())
        })
        .filter_map(|(at, _)| {
            let rest = &text[at..];
            let end = rest
                .find(|c: char| matches!(c, '"' | '\'' | ',') || c.is_whitespace())
                .unwrap_or(rest.len());
            match patch_layers(&rest[..end]) {
                Ok(Some(layers)) if layers.user_patch => Some(layers.source),
                _ => None,
            }
        })
        .collect()
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

    /// #962: the source a user `patch:` wraps, as `yarn patch-commit`
    /// spells it in a lock key, a `resolution:` and a `package.json` value;
    /// builtin compatibility wrappers are not the user's.
    #[test]
    fn user_patch_sources_peel_what_yarn_patch_wraps() {
        let lock = "\"left-pad@patch:left-pad@http%3A//h%3A1/x.tgz#~/.yarn/patches/a.patch\":\n  \
                    resolution: \"left-pad@patch:left-pad@npm%3A1.3.0#~/.yarn/patches/a.patch\
                    ::version=1.3.0&hash=0d6d28\"\n";
        assert_eq!(
            user_patch_sources(lock),
            vec!["left-pad@http://h:1/x.tgz", "left-pad@npm:1.3.0"]
        );
        let pkg = r#"{ "dependencies": { "a": "patch:a@file%3A./v/a.tgz#./p.patch" } }"#;
        assert_eq!(user_patch_sources(pkg), vec!["a@file:./v/a.tgz"]);
        // A user patch over yarn's own compat wrapper: both layers peeled.
        let nested = "\"typescript@patch:typescript@patch%3Atypescript@http%253A//h/t.tgz\
                      %23optional!builtin%3Ccompat/typescript%3E#~/.yarn/patches/t.patch\":";
        assert_eq!(
            user_patch_sources(nested),
            vec!["typescript@http://h/t.tgz"]
        );
        // The compat wrapper alone is not a user patch.
        let builtin =
            "\"resolve@patch:resolve@http%3A//h/r.tgz#optional!builtin<compat/resolve>\":";
        assert!(user_patch_sources(builtin).is_empty());
        assert!(user_patch_sources("\"left-pad@npm:1.3.0\":\n").is_empty());
    }

    /// #1271: the classic grammar keeps an empty range (`left-pad@` from
    /// `"left-pad": ""`); the strict berry grammar still rejects it.
    #[test]
    fn classic_patterns_keep_an_empty_range() {
        assert_eq!(split_classic_pattern("left-pad@"), Some(("left-pad", "")));
        assert_eq!(
            split_classic_pattern("@scope/pkg@"),
            Some(("@scope/pkg", ""))
        );
        assert_eq!(
            split_classic_pattern("left-pad@^1.3.0"),
            Some(("left-pad", "^1.3.0"))
        );
        assert_eq!(split_classic_pattern("@scope/pkg"), None);
        assert_eq!(split_classic_pattern("left-pad"), None);
        assert_eq!(split_classic_pattern("@"), None);
        assert_eq!(split_pattern("left-pad@"), None);

        assert_eq!(classic_pattern_real_name("left-pad@"), Some("left-pad"));
        assert_eq!(
            classic_pattern_real_name("lp@npm:left-pad@"),
            Some("left-pad")
        );
        let merged = split_key_patterns("left-pad@, left-pad@^1.3.0");
        assert_eq!(merged, ["left-pad@", "left-pad@^1.3.0"]);
        assert_eq!(classic_key_real_name(&merged), Some("left-pad"));
        let quoted = split_key_patterns("\"@scope/pkg@\", \"@scope/pkg@^1.0.0\"");
        assert_eq!(classic_key_real_name(&quoted), Some("@scope/pkg"));
    }

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
