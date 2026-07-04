use crate::crawlers::types::CrawledPackage;

/// Match type for sorting results by relevance; declaration order is the
/// ranking (earlier = better). Internal to this module — `fuzzy_match_packages`
/// is the only external entry point and it returns a plain sorted
/// `Vec<CrawledPackage>`, so callers never see the match-type tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MatchType {
    /// Exact match on full name (including namespace).
    ExactFull,
    /// Exact match on package name only.
    ExactName,
    /// Query is a prefix of the full name.
    PrefixFull,
    /// Query is a prefix of the package name.
    PrefixName,
    /// Query is contained in the full name.
    ContainsFull,
    /// Query is contained in the package name.
    ContainsName,
}

/// Get the full display name for a package (including namespace if present).
fn get_full_name(pkg: &CrawledPackage) -> String {
    match &pkg.namespace {
        Some(ns) => format!("{ns}/{}", pkg.name),
        None => pkg.name.clone(),
    }
}

/// Determine the match type for a package against a query, or `None` if there
/// is no match. All inputs must already be lowercased.
fn get_match_type(full_name: &str, name: &str, query: &str) -> Option<MatchType> {
    if full_name == query {
        Some(MatchType::ExactFull)
    } else if name == query {
        Some(MatchType::ExactName)
    } else if full_name.starts_with(query) {
        Some(MatchType::PrefixFull)
    } else if name.starts_with(query) {
        Some(MatchType::PrefixName)
    } else if full_name.contains(query) {
        Some(MatchType::ContainsFull)
    } else if name.contains(query) {
        Some(MatchType::ContainsName)
    } else {
        None
    }
}

/// Fuzzy match packages against a query string.
///
/// Matches are sorted by relevance:
/// 1. Exact match on full name (e.g., `"@types/node"` matches `"@types/node"`)
/// 2. Exact match on package name (e.g., `"node"` matches `"@types/node"`)
/// 3. Prefix match on full name
/// 4. Prefix match on package name
/// 5. Contains match on full name
/// 6. Contains match on package name
///
/// Within the same match type, results are sorted alphabetically by full name.
pub fn fuzzy_match_packages(
    query: &str,
    packages: &[CrawledPackage],
    limit: usize,
) -> Vec<CrawledPackage> {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return Vec::new();
    }

    let mut matches: Vec<(MatchType, String, CrawledPackage)> = packages
        .iter()
        .filter_map(|pkg| {
            let full_name = get_full_name(pkg).to_lowercase();
            let match_type = get_match_type(&full_name, &pkg.name.to_lowercase(), &query)?;
            Some((match_type, full_name, pkg.clone()))
        })
        .collect();

    // Sort by match type (lower is better), then alphabetically by full name.
    // Matching is case-insensitive, so the tie-break compares the lowercased
    // full name too — otherwise byte order sorts uppercase ('Z' = 0x5A) before
    // lowercase ('a' = 0x61), which is not alphabetical and can flip which
    // package lands at `matches[0]`.
    matches.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));

    matches.into_iter().take(limit).map(|m| m.2).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_pkg(name: &str, version: &str, namespace: Option<&str>) -> CrawledPackage {
        let ns = namespace.map(|s| s.to_string());
        let purl = match &ns {
            Some(n) => format!("pkg:npm/{n}/{name}@{version}"),
            None => format!("pkg:npm/{name}@{version}"),
        };
        CrawledPackage {
            name: name.to_string(),
            version: version.to_string(),
            namespace: ns,
            purl,
            path: PathBuf::from("/fake"),
        }
    }

    #[test]
    fn test_exact_full_name() {
        let packages = vec![
            make_pkg("node", "20.0.0", Some("@types")),
            make_pkg("node-fetch", "3.0.0", None),
        ];

        let results = fuzzy_match_packages("@types/node", &packages, 20);
        // "node-fetch" does NOT contain "@types/node", so only 1 result
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "node"); // ExactFull
        assert_eq!(results[0].namespace.as_deref(), Some("@types"));
    }

    #[test]
    fn test_exact_name_only() {
        let packages = vec![
            make_pkg("node", "20.0.0", Some("@types")),
            make_pkg("lodash", "4.17.21", None),
        ];

        let results = fuzzy_match_packages("node", &packages, 20);
        assert_eq!(results[0].name, "node"); // ExactName
    }

    #[test]
    fn test_prefix_match() {
        let packages = vec![
            make_pkg("lodash", "4.17.21", None),
            make_pkg("lodash-es", "4.17.21", None),
        ];

        let results = fuzzy_match_packages("lodash", &packages, 20);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].name, "lodash"); // ExactName is better than PrefixName
    }

    #[test]
    fn test_contains_match() {
        let packages = vec![make_pkg("string-width", "5.0.0", None)];

        let results = fuzzy_match_packages("width", &packages, 20);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "string-width");
    }

    #[test]
    fn test_no_match() {
        let packages = vec![make_pkg("lodash", "4.17.21", None)];

        let results = fuzzy_match_packages("zzzzz", &packages, 20);
        assert!(results.is_empty());
    }

    #[test]
    fn test_empty_query() {
        let packages = vec![make_pkg("lodash", "4.17.21", None)];
        assert!(fuzzy_match_packages("", &packages, 20).is_empty());
        assert!(fuzzy_match_packages("   ", &packages, 20).is_empty());
    }

    #[test]
    fn test_case_insensitive() {
        let packages = vec![make_pkg("React", "18.0.0", None)];
        let results = fuzzy_match_packages("react", &packages, 20);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_limit() {
        let packages: Vec<CrawledPackage> = (0..50)
            .map(|i| make_pkg(&format!("pkg-{i}"), "1.0.0", None))
            .collect();

        let results = fuzzy_match_packages("pkg", &packages, 10);
        assert_eq!(results.len(), 10);
    }

    /// Regression: within a single match tier the alphabetical tie-break must
    /// be case-insensitive, matching the case-insensitive matching above. With
    /// a raw byte-order comparison, 'Z' (0x5A) sorts before 'a' (0x61), so
    /// "Zebra" would wrongly precede "apple" and become `matches[0]`.
    #[test]
    fn test_tiebreak_is_case_insensitive() {
        let packages = vec![
            make_pkg("Zebra", "1.0.0", None),
            make_pkg("apple", "1.0.0", None),
        ];
        // "e" is a substring of both names but a prefix of neither, so both
        // land in the same ContainsFull tier and the tie-break decides order.
        let results = fuzzy_match_packages("e", &packages, 20);
        assert_eq!(results.len(), 2);
        assert_eq!(
            results[0].name, "apple",
            "alphabetical tie-break must ignore case"
        );
        assert_eq!(results[1].name, "Zebra");
    }

    /// A better match tier must outrank alphabetical order, and the `limit`
    /// truncation must keep the best matches (it is applied after sorting).
    #[test]
    fn test_best_tier_survives_limit() {
        let packages = vec![
            make_pkg("ax", "1.0.0", None),
            make_pkg("bx", "1.0.0", None),
            make_pkg("x", "1.0.0", None), // ExactFull, but alphabetically last
        ];
        let results = fuzzy_match_packages("x", &packages, 1);
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].name, "x",
            "exact match must beat alphabetically-earlier contains matches"
        );
    }

    /// A namespaced package whose bare name (but not its namespace-qualified
    /// full name) prefixes the query is a PrefixName match, which ranks below
    /// a non-namespaced PrefixFull match for the same query.
    #[test]
    fn test_namespaced_prefix_name_ranks_below_full() {
        let packages = vec![
            make_pkg("lodash", "4.17.21", Some("@scope")),
            make_pkg("lodash-es", "4.17.21", None),
        ];
        let results = fuzzy_match_packages("lod", &packages, 20);
        assert_eq!(results.len(), 2);
        assert_eq!(
            results[0].name, "lodash-es",
            "PrefixFull (no namespace) outranks PrefixName (namespaced)"
        );
        assert!(results[0].namespace.is_none());
    }
}
