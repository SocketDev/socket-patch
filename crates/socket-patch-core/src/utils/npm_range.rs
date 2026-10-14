//! npm semver ranges, read the way npm reads them, over the `semver`
//! crate (whose bare-version and partial-version rules differ from npm's).

/// Whether the npm semver `range` admits `version`; `None` for a range
/// this reader does not decide (a dist-tag, a partial hyphen bound).
pub(crate) fn npm_range_admits(range: &str, version: &str) -> Option<bool> {
    let version = semver::Version::parse(version).ok()?;
    let mut admits = false;
    for alternative in range.split("||") {
        let comparators: Vec<String> = match alternative.split_once(" - ") {
            // `a - b` with full versions is `>=a <=b`.
            Some((low, high)) => {
                let full = |v: &str| {
                    let v = v.trim().trim_start_matches(['v', '=']);
                    semver::Version::parse(v).ok().map(|_| v.to_string())
                };
                vec![format!(">={}", full(low)?), format!("<={}", full(high)?)]
            }
            None => glue_operators(alternative)
                .iter()
                .map(|c| npm_comparator(c))
                .collect::<Option<_>>()?,
        };
        let req = match comparators.is_empty() {
            true => "*".to_string(),
            false => comparators.join(", "),
        };
        admits |= semver::VersionReq::parse(&req).ok()?.matches(&version);
    }
    Some(admits)
}

/// The comparators of one npm range alternative, an operator npm allows
/// to stand apart (`>= 1.2.0`) joined to its version.
fn glue_operators(alternative: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut pending = String::new();
    for token in alternative.split_whitespace() {
        if token
            .chars()
            .all(|c| matches!(c, '^' | '~' | '>' | '<' | '='))
        {
            pending.push_str(token);
        } else {
            out.push(format!("{}{token}", std::mem::take(&mut pending)));
        }
    }
    out
}

/// One npm comparator in the `semver` crate's syntax, which differs for a
/// bare version: npm's `1.3.0` is exact and `1.3` means `~1.3`, where the
/// crate reads both as caret ranges.
fn npm_comparator(comparator: &str) -> Option<String> {
    let op_len = comparator
        .find(|c: char| !matches!(c, '^' | '~' | '>' | '<' | '='))
        .unwrap_or(comparator.len());
    let (op, version) = comparator.split_at(op_len);
    let version = version.strip_prefix('v').unwrap_or(version);
    if !op.is_empty() {
        return Some(format!("{op}{version}"));
    }
    // Prerelease and build tags ride on the patch part.
    let core = version.split(['-', '+']).next().unwrap_or(version);
    let parts: Vec<&str> = core.split('.').collect();
    let wildcard = |p: &&str| matches!(*p, "*" | "x" | "X");
    if parts.iter().any(wildcard) {
        return Some(version.to_string());
    }
    match parts.len() {
        3 => Some(format!("={version}")),
        1 | 2 => Some(format!("~{version}")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_range_admits_reads_npm_semantics() {
        for (range, version, want) in [
            ("1.3.0", "1.3.0", Some(true)),
            ("1.3.0", "1.3.1", Some(false)),
            ("^1.3.0", "1.9.0", Some(true)),
            ("^1.3.0", "2.0.0", Some(false)),
            ("~1.3.0", "1.3.5", Some(true)),
            ("~1.3.0", "1.4.0", Some(false)),
            ("1.3", "1.3.9", Some(true)),
            ("1.3", "1.4.0", Some(false)),
            ("1", "1.9.0", Some(true)),
            ("1.x", "1.9.0", Some(true)),
            ("*", "4.0.0", Some(true)),
            ("", "4.0.0", Some(true)),
            (">=1.2.0 <1.4.0", "1.3.0", Some(true)),
            (">=1.2.0 <1.3.0", "1.3.0", Some(false)),
            ("^2.0.0 || ^1.3.0", "1.3.0", Some(true)),
            ("1.0.0 - 2.0.0", "1.3.0", Some(true)),
            ("1.0.0 - 1.2.0", "1.3.0", Some(false)),
            ("1.0 - 2", "1.3.0", None),
            (">= 1.2.0", "1.3.0", Some(true)),
            ("< 1.3.0", "1.3.0", Some(false)),
            ("v1.3.0", "1.3.0", Some(true)),
            ("=1.3.0", "1.3.0", Some(true)),
            ("1.3.0-beta.1", "1.3.0-beta.1", Some(true)),
            ("1.3.0-beta.1", "1.3.0", Some(false)),
            ("latest", "1.3.0", None),
        ] {
            assert_eq!(
                npm_range_admits(range, version),
                want,
                "{range} vs {version}"
            );
        }
    }
}
