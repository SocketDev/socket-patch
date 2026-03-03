use crate::crawlers::types::CrawledPackage;

// ---------------------------------------------------------------------------
// MatchType enum
// ---------------------------------------------------------------------------

/// Match type for sorting results by relevance.
///
/// Lower numeric value = better match. The ordering is:
/// 1. Exact match on full name (including namespace)
/// 2. Exact match on package name only
/// 3. Prefix match on full name
/// 4. Prefix match on package name
/// 5. Contains match on full name
/// 6. Contains match on package name
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MatchType {
    /// Exact match on full name (including namespace).
    ExactFull = 0,
    /// Exact match on package name only.
    ExactName = 1,
    /// Query is a prefix of the full name.
    PrefixFull = 2,
    /// Query is a prefix of the package name.
    PrefixName = 3,
    /// Query is contained in the full name.
    ContainsFull = 4,
    /// Query is contained in the package name.
    ContainsName = 5,
}

// ---------------------------------------------------------------------------
// Internal match result
// ---------------------------------------------------------------------------

struct MatchResult {
    package: CrawledPackage,
    match_type: MatchType,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Get the full display name for a package (including namespace if present).
fn get_full_name(pkg: &CrawledPackage) -> String {
    match &pkg.namespace {
        Some(ns) => format!("{ns}/{}", pkg.name),
        None => pkg.name.clone(),
    }
}

/// Determine the match type for a package against a query.
/// Returns `None` if there is no match.
fn get_match_type(pkg: &CrawledPackage, query: &str) -> Option<MatchType> {
    let lower_query = query.to_lowercase();
    let full_name = get_full_name(pkg).to_lowercase();
    let name = pkg.name.to_lowercase();

    // Check exact matches
    if full_name == lower_query {
        return Some(MatchType::ExactFull);
    }
    if name == lower_query {
        return Some(MatchType::ExactName);
    }

    // Check prefix matches
    if full_name.starts_with(&lower_query) {
        return Some(MatchType::PrefixFull);
    }
    if name.starts_with(&lower_query) {
        return Some(MatchType::PrefixName);
    }

    // Check contains matches
    if full_name.contains(&lower_query) {
        return Some(MatchType::ContainsFull);
    }
    if name.contains(&lower_query) {
        return Some(MatchType::ContainsName);
    }

    None
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

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
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut matches: Vec<MatchResult> = Vec::new();

    for pkg in packages {
        if let Some(match_type) = get_match_type(pkg, trimmed) {
            matches.push(MatchResult {
                package: pkg.clone(),
                match_type,
            });
        }
    }

    // Sort by match type (lower is better), then alphabetically by full name
    matches.sort_by(|a, b| {
        let type_cmp = a.match_type.cmp(&b.match_type);
        if type_cmp != std::cmp::Ordering::Equal {
            return type_cmp;
        }
        get_full_name(&a.package).cmp(&get_full_name(&b.package))
    });

    matches
        .into_iter()
        .take(limit)
        .map(|m| m.package)
        .collect()
}

/// Check if a string looks like a PURL.
pub fn is_purl(s: &str) -> bool {
    s.starts_with("pkg:")
}

/// Check if a string looks like a scoped npm package name.
pub fn is_scoped_package(s: &str) -> bool {
    s.starts_with('@') && s.contains('/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_pkg(
        name: &str,
        version: &str,
        namespace: Option<&str>,
    ) -> CrawledPackage {
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

    #[test]
    fn test_is_purl() {
        assert!(is_purl("pkg:npm/lodash@4.17.21"));
        assert!(is_purl("pkg:pypi/requests@2.28.0"));
        assert!(!is_purl("lodash"));
        assert!(!is_purl("@types/node"));
    }

    #[test]
    fn test_is_scoped_package() {
        assert!(is_scoped_package("@types/node"));
        assert!(is_scoped_package("@scope/pkg"));
        assert!(!is_scoped_package("lodash"));
        assert!(!is_scoped_package("@scope"));
    }
}
