//! PEP 440 version equality — the comparison pip, uv and Hatch apply to a
//! hand-written `name==X` pin.
//!
//! Only equality is implemented: the writers that rewrite a pin need to know
//! whether `==X` selects exactly the release being patched, and under PEP 440
//! that ignores case, leading zeros, trailing `.0` release segments and the
//! alternate pre/post/dev spellings (`1.16` == `1.16.0` == `01.16.0.0`,
//! `1.0RC1` == `1.0rc1` == `1.0-c1`). Arbitrary equality (`===`) is plain
//! string equality and is not handled here.

use once_cell::sync::Lazy;
use regex::Regex;

/// The `packaging` reference grammar (`packaging.version.VERSION_PATTERN`).
static VERSION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?ix)^\s*
        v?
        (?:(?P<epoch>[0-9]+)!)?
        (?P<release>[0-9]+(?:\.[0-9]+)*)
        (?:[-_.]?(?P<pre_l>alpha|beta|preview|pre|a|b|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?
        (?:-(?P<post_n1>[0-9]+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?)?
        (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
        (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
        \s*$",
    )
    .expect("static PEP 440 regex is valid")
});

/// A numeric component with leading zeros stripped, so arbitrarily long
/// digit runs compare exactly without overflowing an integer.
fn number(digits: &str) -> String {
    let trimmed = digits.trim_start_matches('0');
    if trimmed.is_empty() { "0" } else { trimmed }.to_owned()
}

#[derive(Debug, PartialEq, Eq)]
enum LocalPart {
    Number(String),
    Text(String),
}

/// A parsed version in the form PEP 440 equality compares.
#[derive(Debug, PartialEq, Eq)]
struct Version {
    epoch: String,
    /// Release segments with trailing zeros removed (`1.16.0` → `[1, 16]`).
    release: Vec<String>,
    pre: Option<(&'static str, String)>,
    post: Option<String>,
    dev: Option<String>,
    local: Vec<LocalPart>,
}

fn parse(text: &str) -> Option<Version> {
    let captures = VERSION.captures(text)?;
    let digits = |name: &str| captures.name(name).map(|m| number(m.as_str()));
    let mut release: Vec<String> = captures["release"].split('.').map(number).collect();
    while release.len() > 1 && release.last().is_some_and(|segment| segment == "0") {
        release.pop();
    }
    let pre = captures.name("pre_l").map(|label| {
        let label = match label.as_str().to_ascii_lowercase().as_str() {
            "a" | "alpha" => "a",
            "b" | "beta" => "b",
            _ => "rc",
        };
        (label, digits("pre_n").unwrap_or_else(|| "0".into()))
    });
    let post = if captures.name("post_n1").is_some() {
        digits("post_n1")
    } else {
        captures
            .name("post_l")
            .map(|_| digits("post_n2").unwrap_or_else(|| "0".into()))
    };
    let dev = captures
        .name("dev_l")
        .map(|_| digits("dev_n").unwrap_or_else(|| "0".into()));
    let local = captures.name("local").map_or_else(Vec::new, |local| {
        local
            .as_str()
            .split(['-', '_', '.'])
            .map(|part| {
                if part.bytes().all(|byte| byte.is_ascii_digit()) {
                    LocalPart::Number(number(part))
                } else {
                    LocalPart::Text(part.to_ascii_lowercase())
                }
            })
            .collect()
    });
    Some(Version {
        epoch: digits("epoch").unwrap_or_else(|| "0".into()),
        release,
        pre,
        post,
        dev,
        local,
    })
}

/// Whether `a` and `b` are the same version under PEP 440 (what `==a`
/// selects when `b` is the candidate, local labels included). An invalid
/// version on either side is never equal to anything: callers fail closed.
pub(crate) fn versions_equal(a: &str, b: &str) -> bool {
    match (parse(a), parse(b)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// Whether a whitespace-free specifier is an exact `==X` pin of `version`
/// under PEP 440. Wildcards (`==1.*`), arbitrary equality (`===`) and every
/// other operator are not.
pub(crate) fn is_exact_pin_of(specifier: &str, version: &str) -> bool {
    specifier
        .strip_prefix("==")
        .filter(|pinned| !pinned.starts_with('=') && !pinned.contains('*'))
        .is_some_and(|pinned| versions_equal(pinned, version))
}

/// Whether `specifier` (whitespace already stripped) is an exact `==` pin
/// of SOME valid release — the shape [`is_exact_pin_of`] accepts, for any
/// version. Arbitrary equality (`===`) and wildcards are not exact pins.
pub(crate) fn is_exact_pin(specifier: &str) -> bool {
    specifier
        .strip_prefix("==")
        .filter(|pinned| !pinned.starts_with('=') && !pinned.contains('*'))
        .is_some_and(|pinned| parse(pinned).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_spellings_of_one_release() {
        for (a, b) in [
            ("1.16", "1.16.0"),
            ("1.16.0.0", "1.16.0"),
            ("01.16.0", "1.16.0"),
            ("v1.16.0", "1.16.0"),
            (" 1.16.0 ", "1.16.0"),
            ("0!1.16", "1.16.0"),
            ("1.0RC1", "1.0rc1"),
            ("1.0-c1", "1.0rc1"),
            ("1.0.preview2", "1.0rc2"),
            ("1.0alpha", "1.0a0"),
            ("1.0-beta.3", "1.0b3"),
            ("1.0-1", "1.0.post1"),
            ("1.0rev", "1.0.post0"),
            ("1.0_r2", "1.0.post2"),
            ("1.0DEV", "1.0.dev0"),
            ("1.0+Ubuntu-01", "1.0+ubuntu.1"),
            ("2026.00010.0", "2026.10"),
            ("99999999999999999999999.0", "99999999999999999999999"),
        ] {
            assert!(versions_equal(a, b), "{a} == {b}");
            assert!(versions_equal(b, a), "{b} == {a}");
        }
    }

    #[test]
    fn different_releases_and_invalid_versions_are_not_equal() {
        for (a, b) in [
            ("1.16.1", "1.16.0"),
            ("1.16", "1.1.6"),
            ("1.0", "1.0rc1"),
            ("1.0a1", "1.0b1"),
            ("1.0.post1", "1.0"),
            ("1.0.dev1", "1.0"),
            ("1!1.0", "1.0"),
            ("1.0+local", "1.0"),
            ("1.0", "1.0+local"),
            ("1.*", "1.0"),
            ("", ""),
            ("not-a-version", "not-a-version"),
            ("1.0 extra", "1.0"),
        ] {
            assert!(!versions_equal(a, b), "{a} != {b}");
        }
    }

    #[test]
    fn exact_pin_spellings() {
        assert!(is_exact_pin_of("==1.16", "1.16.0"));
        assert!(is_exact_pin_of("==1.16.0.0", "1.16.0"));
        assert!(is_exact_pin_of("==01.16.0", "1.16.0"));
        assert!(!is_exact_pin_of("===1.16.0", "1.16.0"));
        assert!(!is_exact_pin_of("==1.16.*", "1.16.0"));
        assert!(!is_exact_pin_of(">=1.16.0", "1.16.0"));
        assert!(!is_exact_pin_of("~=1.16.0", "1.16.0"));
        assert!(!is_exact_pin_of("==1.15", "1.16.0"));
        assert!(!is_exact_pin_of("1.16.0", "1.16.0"));
        assert!(is_exact_pin("==1.17.0"));
        assert!(is_exact_pin("==1.16"));
        assert!(!is_exact_pin("===1.17.0"));
        assert!(!is_exact_pin("==1.17.*"));
        assert!(!is_exact_pin(">=1.17"));
        assert!(!is_exact_pin("==not a version"));
    }
}
