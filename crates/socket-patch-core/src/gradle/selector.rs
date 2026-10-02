//! Gradle's version ordering and version selectors, ported from Gradle's
//! `VersionParser`, `StaticVersionComparator`, `VersionRangeSelector` and
//! `DefaultVersionSelectorScheme`.
//!
//! The ordering matters for hosted mode: a suffixed patched version
//! `1.10.0-socket.4d5e6f70` sorts BELOW its base `1.10.0` (an extra
//! non-numeric part makes a version lower) and above every earlier
//! release. The hosted settings script carries a Groovy port of this
//! module; the `GOLDEN_*` tables are the shared cases both ports are tested
//! against, and `tests/gradle_selector_golden.rs` checks them against real
//! Gradle.
//!
//! Two behaviours changed in Gradle 7 (measured on 6.9.4 against 7.6.6,
//! 8.14.3 and 9.8.0), so the `*_for` functions take the Gradle major:
//!
//! - Gradle 6 ranks only `dev` < (any other word) < `rc` < `release` <
//!   `final`; Gradle 7+ ranks `dev` < (any other word) < `rc` < `snapshot`
//!   < `final` < `ga` < `release` < `sp` (case-insensitively).
//! - Gradle 7+ makes an exclusive upper bound also exclude the qualified
//!   versions of that bound: `[1.9,1.10.0)` rejects `1.10.0-rc1` and
//!   `1.10.0-socket.4d5e6f70`, which Gradle 6 admits because they sort
//!   below `1.10.0`.
//!
//! The plain functions use the current (7+) semantics.

use std::cmp::Ordering;
use std::sync::OnceLock;

/// The Gradle major the plain (non-`_for`) functions model.
pub const CURRENT_MAJOR: u32 = 9;

/// One end of a version range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    pub version: String,
    pub inclusive: bool,
}

/// A parsed version selector (the version part of a dependency request).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    /// A plain version (`1.10.0`), also the single-value range `[1.10.0]`.
    /// Like Gradle, anything that is not a well-formed range, prefix or
    /// `latest.*` selector is an exact (string-equality) selector, so
    /// `[1.0` or `[1,2),[3,4)` only admit themselves.
    Exact(String),
    /// `[a,b]`, `[a,b)`, `]a,b]`, `(a,b]`, `[a,b[`, `(,b]`, `[a,)`;
    /// `None` = open.
    Range {
        lower: Option<Bound>,
        upper: Option<Bound>,
    },
    /// `1.+`, `1.1+`, `+`: the text before the `+`.
    Prefix(String),
    /// `latest.release`, `latest.integration`, `latest.<status>`.
    Latest(String),
    /// No version (Gradle: any version, decided by constraints), an
    /// interpolated one, or a `!!` strict shorthand not yet split.
    Unknown,
}

struct RangeRes {
    finite: regex::Regex,
    lower_infinite: regex::Regex,
    upper_infinite: regex::Regex,
    single: regex::Regex,
}

fn range_res() -> &'static RangeRes {
    static RES: OnceLock<RangeRes> = OnceLock::new();
    RES.get_or_init(|| {
        // Gradle's VersionRangeSelector patterns.
        const ANY: &str = r"[^\[\]\(\),]+?";
        let re = |p: String| regex::Regex::new(&p).expect("static range pattern");
        RangeRes {
            finite: re(format!(
                r"^([\[\]\(])\s*({ANY})\s*,\s*({ANY})\s*([\]\[\)])$"
            )),
            lower_infinite: re(format!(r"^\(\s*,\s*({ANY})\s*([\]\[\)])$")),
            upper_infinite: re(format!(r"^([\[\]\(])\s*({ANY})\s*,\s*\)$")),
            single: re(format!(r"^\[\s*({ANY})\s*\]$")),
        }
    })
}

/// Parse a version selector the way Gradle does.
pub fn parse_selector(s: &str) -> Selector {
    if s.is_empty() || s.contains('$') || s.contains("!!") {
        return Selector::Unknown;
    }
    if let Some(range) = parse_range(s) {
        return range;
    }
    if let Some(prefix) = s.strip_suffix('+') {
        return Selector::Prefix(prefix.to_string());
    }
    if s.starts_with("latest.") {
        return Selector::Latest(s.to_string());
    }
    Selector::Exact(s.to_string())
}

fn parse_range(s: &str) -> Option<Selector> {
    let res = range_res();
    let bound = |v: &str, inclusive: bool| Bound {
        version: v.to_string(),
        inclusive,
    };
    if let Some(c) = res.single.captures(s) {
        return Some(Selector::Exact(c[1].to_string()));
    }
    if let Some(c) = res.finite.captures(s) {
        return Some(Selector::Range {
            lower: Some(bound(&c[2], &c[1] == "[")),
            upper: Some(bound(&c[3], &c[4] == "]")),
        });
    }
    if let Some(c) = res.lower_infinite.captures(s) {
        return Some(Selector::Range {
            lower: None,
            upper: Some(bound(&c[1], &c[2] == "]")),
        });
    }
    if let Some(c) = res.upper_infinite.captures(s) {
        return Some(Selector::Range {
            lower: Some(bound(&c[2], &c[1] == "[")),
            upper: None,
        });
    }
    None
}

/// Whether `sel` admits version `v` on current Gradle. `None` when that
/// depends on more than the version string (`latest.*` needs the module's
/// status) or the selector is [`Selector::Unknown`].
pub fn admits(sel: &Selector, v: &str) -> Option<bool> {
    admits_for(sel, v, CURRENT_MAJOR)
}

/// [`admits`] as Gradle `major` decides it.
pub fn admits_for(sel: &Selector, v: &str, major: u32) -> Option<bool> {
    match sel {
        Selector::Exact(e) => Some(e == v),
        Selector::Prefix(p) => Some(v.starts_with(p.as_str())),
        Selector::Range { lower, upper } => {
            let lower_ok = lower.as_ref().is_none_or(|b| {
                let c = gradle_version_cmp_for(v, &b.version, major);
                c == Ordering::Greater || (b.inclusive && c == Ordering::Equal)
            });
            let upper_ok = upper.as_ref().is_none_or(|b| {
                let c = gradle_version_cmp_for(v, &b.version, major);
                if b.inclusive {
                    c != Ordering::Greater
                } else {
                    c == Ordering::Less && !(major >= 7 && qualifies(v, &b.version))
                }
            });
            Some(lower_ok && upper_ok)
        }
        Selector::Latest(_) | Selector::Unknown => None,
    }
}

/// Whether `v` is `bound` plus more parts (`1.10.0-rc1` of `1.10.0`).
fn qualifies(v: &str, bound: &str) -> bool {
    let (pv, pb) = (version_parts(v), version_parts(bound));
    pv.len() > pb.len() && pv[..pb.len()] == pb[..]
}

/// Gradle's parts of a version: split at `.`, `-`, `_`, `+` and between
/// digits and non-digits. Empty parts between two separators are kept; a
/// trailing separator adds none.
pub fn version_parts(v: &str) -> Vec<&str> {
    let b = v.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0;
    let mut digit = false;
    for (pos, &ch) in b.iter().enumerate() {
        if matches!(ch, b'.' | b'_' | b'-' | b'+') {
            parts.push(&v[start..pos]);
            start = pos + 1;
            digit = false;
        } else if ch.is_ascii_digit() {
            if !digit && pos > start {
                parts.push(&v[start..pos]);
                start = pos;
            }
            digit = true;
        } else {
            if digit && pos > start {
                parts.push(&v[start..pos]);
                start = pos;
            }
            digit = false;
        }
    }
    if b.len() > start {
        parts.push(&v[start..]);
    }
    parts
}

fn is_numeric(part: &str) -> bool {
    !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())
}

fn numeric_cmp(a: &str, b: &str) -> Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Gradle's rank of the qualifiers it treats specially: `dev` below any
/// other word, the rest above any other word in this order.
fn special(part: &str, major: u32) -> Option<i8> {
    let lower = part.to_ascii_lowercase();
    if major < 7 {
        return match lower.as_str() {
            "dev" => Some(-1),
            "rc" => Some(1),
            "release" => Some(2),
            "final" => Some(3),
            _ => None,
        };
    }
    match lower.as_str() {
        "dev" => Some(-1),
        "rc" => Some(1),
        "snapshot" => Some(2),
        "final" => Some(3),
        "ga" => Some(4),
        "release" => Some(5),
        "sp" => Some(6),
        _ => None,
    }
}

/// Compare two versions the way current Gradle orders them.
pub fn gradle_version_cmp(a: &str, b: &str) -> Ordering {
    gradle_version_cmp_for(a, b, CURRENT_MAJOR)
}

/// [`gradle_version_cmp`] as Gradle `major` orders them.
pub fn gradle_version_cmp_for(a: &str, b: &str, major: u32) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let pa = version_parts(a);
    let pb = version_parts(b);
    let common = pa.len().min(pb.len());
    for i in 0..common {
        let (x, y) = (pa[i], pb[i]);
        match (is_numeric(x), is_numeric(y)) {
            (true, true) => match numeric_cmp(x, y) {
                Ordering::Equal => continue,
                o => return o,
            },
            (true, false) => return Ordering::Greater,
            (false, true) => return Ordering::Less,
            (false, false) => {}
        }
        if x == y {
            continue;
        }
        return match (special(x, major), special(y, major)) {
            (Some(s), Some(t)) => s.cmp(&t),
            (Some(s), None) => {
                if s < 0 {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }
            (None, Some(t)) => {
                if t < 0 {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            }
            (None, None) => x.cmp(y),
        };
    }
    // One is a prefix of the other: an extra numeric part makes it higher,
    // an extra qualifier lower.
    match pa.len().cmp(&pb.len()) {
        Ordering::Greater => {
            if is_numeric(pa[common]) {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        }
        Ordering::Less => {
            if is_numeric(pb[common]) {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        }
        Ordering::Equal => Ordering::Equal,
    }
}

/// `(a, b, gradle_version_cmp_for(a, b, major))` on every Gradle major
/// from 6 to 9.
pub const GOLDEN_ORDERING: &[(&str, &str, Ordering)] = &[
    ("1.10.0-socket.4d5e6f70", "1.10.0", Ordering::Less),
    ("1.10.0", "1.10.0-socket.4d5e6f70", Ordering::Greater),
    ("1.10.0-socket.4d5e6f70", "1.9", Ordering::Greater),
    ("1.10.0-socket.4d5e6f70", "1.10.1", Ordering::Less),
    (
        "1.10.0-socket.4d5e6f70",
        "1.10.0-socket.4d5e6f70",
        Ordering::Equal,
    ),
    (
        "1.10.0-socket.0abcdef1",
        "1.10.0-socket.4d5e6f70",
        Ordering::Less,
    ),
    ("1.10.0-socket.4d5e6f70", "1.10.0-rc1", Ordering::Less),
    ("1.10.0-socket.4d5e6f70", "1.10.0-alpha1", Ordering::Greater),
    ("2.13.4-socket.00000001", "2.13.4", Ordering::Less),
    ("2.13.4-socket.00000001", "2.13.3", Ordering::Greater),
    ("1.9", "1.10.0", Ordering::Less),
    ("1.10", "1.10.0", Ordering::Less),
    ("2.0", "10.0", Ordering::Less),
    ("1.01", "1.1", Ordering::Equal),
    ("1.0a", "1.0-a", Ordering::Equal),
    ("1.0-SNAPSHOT", "1.0", Ordering::Less),
    ("1.0-rc-1", "1.0", Ordering::Less),
    ("1.0-alpha", "1.0-beta", Ordering::Less),
    ("1.0-dev", "1.0-alpha", Ordering::Less),
    ("1.0-snapshot", "1.0-final", Ordering::Less),
    ("1.0-ga", "1.0-release", Ordering::Less),
    ("1.0-rc", "1.0-release", Ordering::Less),
    ("1.0-sp", "1.0", Ordering::Less),
    ("1.0-RC", "1.0-rc", Ordering::Equal),
    ("1.0.1", "1.0-beta", Ordering::Greater),
    ("1.0.0.Final", "1.0.0", Ordering::Less),
    ("31.1-jre", "31.1-android", Ordering::Greater),
    ("1.2.3+build.5", "1.2.3", Ordering::Less),
];

/// Orderings that differ on Gradle 6: `(a, b, on 6, on 7+)`.
pub const GOLDEN_ORDERING_BY_MAJOR: &[(&str, &str, Ordering, Ordering)] = &[
    (
        "1.10.0-socket.4d5e6f70",
        "1.10.0-SNAPSHOT",
        Ordering::Greater,
        Ordering::Less,
    ),
    ("1.0-rc", "1.0-snapshot", Ordering::Greater, Ordering::Less),
    ("1.0-final", "1.0-ga", Ordering::Greater, Ordering::Less),
    ("1.0-release", "1.0-sp", Ordering::Greater, Ordering::Less),
    (
        "1.0-release",
        "1.0-final",
        Ordering::Less,
        Ordering::Greater,
    ),
    ("1.0-SNAPSHOT", "1.0-a", Ordering::Less, Ordering::Greater),
];

/// `(selector, version, admits_for(parse_selector(selector), version,
/// major))` on every Gradle major from 6 to 9.
pub const GOLDEN_ADMITS: &[(&str, &str, Option<bool>)] = &[
    ("[1.9,1.10.0]", "1.10.0", Some(true)),
    ("[1.9,1.10.0)", "1.10.0", Some(false)),
    ("[1.9,1.11)", "1.10.0", Some(true)),
    ("[1.9,1.11)", "1.10.0-socket.4d5e6f70", Some(true)),
    ("[1.9, 1.11)", "1.10.0", Some(true)),
    ("[ 1.9 , 1.11 ]", "1.10.0", Some(true)),
    ("[1.9,1.11)", "1.11", Some(false)),
    ("[1.9,1.11[", "1.11", Some(false)),
    ("]1.9,1.10.0]", "1.9", Some(false)),
    ("(1.9,1.10.0]", "1.9", Some(false)),
    ("(1.9,1.10.0)", "1.9.5", Some(true)),
    ("(,1.10.0]", "1.10.0", Some(true)),
    ("[1.10.0,)", "1.10.0", Some(true)),
    ("[1.10.0,)", "1.10.0-socket.4d5e6f70", Some(false)),
    ("[1.10.0,)", "1.11", Some(true)),
    ("]1.9,)", "1.10.0", Some(true)),
    ("[1.10.0]", "1.10.0", Some(true)),
    ("[1.10.0]", "1.10.0-socket.4d5e6f70", Some(false)),
    ("[1.0,2.0)", "2-rc1", Some(true)),
    ("[1.0,2.0-rc1)", "2.0-rc0", Some(true)),
    // Not ranges to Gradle: exact selectors that only admit themselves.
    ("],1.10.0]", "1.10.0", Some(false)),
    ("[1.10.0,]", "1.10.0", Some(false)),
    ("[1.10.0,[", "1.10.0", Some(false)),
    ("(,)", "1.10.0", Some(false)),
    ("[1.9", "1.9", Some(false)),
    ("[1,2),[3,4)", "1.5", Some(false)),
    (" 1.10.0", "1.10.0", Some(false)),
    ("1.+", "1.10.0", Some(true)),
    ("1.1+", "1.10.0", Some(true)),
    ("1.2+", "1.10.0", Some(false)),
    ("+", "1.10.0", Some(true)),
    ("1.10.0", "1.10.0", Some(true)),
    ("1.10.0", "1.10", Some(false)),
    ("1.10.0", "1.10.0-socket.4d5e6f70", Some(false)),
    ("latest.release", "1.10.0", None),
    ("latest.integration", "1.10.0", None),
];

/// Admissions that differ on Gradle 6: `(selector, version, on 6, on 7+)`.
pub const GOLDEN_ADMITS_BY_MAJOR: &[(&str, &str, Option<bool>, Option<bool>)] = &[
    (
        "[1.9,1.10.0)",
        "1.10.0-socket.4d5e6f70",
        Some(true),
        Some(false),
    ),
    ("[1.0,2.0)", "2.0-rc1", Some(true), Some(false)),
    ("[1.0,2.0[", "2.0-SNAPSHOT", Some(true), Some(false)),
    ("(,2.0)", "2.0-dev", Some(true), Some(false)),
    ("[1.0,2)", "2-rc1", Some(true), Some(false)),
    ("[1.0,2.0-rc1)", "2.0-SNAPSHOT", Some(true), Some(false)),
    ("[1.0,2.0-rc1)", "2.0-rc1-x", Some(true), Some(false)),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_ordering() {
        for major in 6..=9 {
            for (a, b, want) in GOLDEN_ORDERING {
                assert_eq!(
                    gradle_version_cmp_for(a, b, major),
                    *want,
                    "{a} vs {b} on {major}"
                );
                assert_eq!(
                    gradle_version_cmp_for(b, a, major),
                    want.reverse(),
                    "{b} vs {a} on {major}"
                );
            }
            for (a, b, six, later) in GOLDEN_ORDERING_BY_MAJOR {
                let want = if major < 7 { six } else { later };
                assert_eq!(
                    gradle_version_cmp_for(a, b, major),
                    *want,
                    "{a} vs {b} on {major}"
                );
                assert_eq!(gradle_version_cmp_for(b, a, major), want.reverse());
            }
        }
        assert_eq!(
            gradle_version_cmp("1.0-final", "1.0-ga"),
            Ordering::Less,
            "the plain function models current Gradle"
        );
    }

    #[test]
    fn golden_admits() {
        for major in 6..=9 {
            for (sel, v, want) in GOLDEN_ADMITS {
                assert_eq!(
                    admits_for(&parse_selector(sel), v, major),
                    *want,
                    "{sel} admits {v} on {major}"
                );
            }
            for (sel, v, six, later) in GOLDEN_ADMITS_BY_MAJOR {
                let want = if major < 7 { six } else { later };
                assert_eq!(
                    admits_for(&parse_selector(sel), v, major),
                    *want,
                    "{sel} admits {v} on {major}"
                );
            }
        }
        assert_eq!(
            admits(&parse_selector("[1.9,1.10.0]"), "1.10.0"),
            Some(true)
        );
        assert_eq!(
            admits(&parse_selector("[1.9,1.10.0)"), "1.10.0-socket.4d5e6f70"),
            Some(false)
        );
    }

    #[test]
    fn selector_kinds() {
        assert_eq!(parse_selector("1.+"), Selector::Prefix("1.".into()));
        assert_eq!(parse_selector("1.10.0"), Selector::Exact("1.10.0".into()));
        assert_eq!(parse_selector("[1.10.0]"), Selector::Exact("1.10.0".into()));
        assert_eq!(
            parse_selector("latest.release"),
            Selector::Latest("latest.release".into())
        );
        assert_eq!(
            parse_selector("[1.9,1.10.0)"),
            Selector::Range {
                lower: Some(Bound {
                    version: "1.9".into(),
                    inclusive: true
                }),
                upper: Some(Bound {
                    version: "1.10.0".into(),
                    inclusive: false
                }),
            }
        );
        assert_eq!(
            parse_selector("]1.9,)"),
            Selector::Range {
                lower: Some(Bound {
                    version: "1.9".into(),
                    inclusive: false
                }),
                upper: None,
            }
        );
        for unknown in ["", "$v", "${v}", "1.0!!", "[1.0,2.0)!!1.5"] {
            assert_eq!(parse_selector(unknown), Selector::Unknown, "{unknown:?}");
        }
        for exact in [
            "[1.0",
            "[,]",
            "(1.0]",
            "[1,2),[3,4)",
            "1.0,2.0",
            "[1.0,)x",
            "1 .0",
        ] {
            assert_eq!(
                parse_selector(exact),
                Selector::Exact(exact.into()),
                "{exact:?}"
            );
        }
        assert_eq!(admits(&Selector::Unknown, "1"), None);
    }

    #[test]
    fn parts_follow_gradle() {
        assert_eq!(
            version_parts("1.10.0-socket.4d5e6f70"),
            ["1", "10", "0", "socket", "4", "d", "5", "e", "6", "f", "70"]
        );
        assert_eq!(version_parts("1..2"), ["1", "", "2"]);
        assert_eq!(version_parts("1.0-"), ["1", "0"]);
        assert_eq!(version_parts("rc1"), ["rc", "1"]);
        assert!(version_parts("").is_empty());
    }

    #[test]
    fn suffixed_versions_sort_between_neighbours() {
        let mut vs = vec![
            "1.10.1",
            "1.10.0",
            "1.10.0-socket.4d5e6f70",
            "1.9",
            "1.10.0-rc1",
            "1.9.9",
        ];
        vs.sort_by(|a, b| gradle_version_cmp(a, b));
        assert_eq!(
            vs,
            [
                "1.9",
                "1.9.9",
                "1.10.0-socket.4d5e6f70",
                "1.10.0-rc1",
                "1.10.0",
                "1.10.1"
            ]
        );
    }
}
