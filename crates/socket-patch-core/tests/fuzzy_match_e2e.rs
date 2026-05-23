//! Integration coverage for `socket_patch_core::utils::fuzzy_match`.
//!
//! `fuzzy_match_packages` powers `socket-patch get <identifier>`'s
//! "did you mean…" fallback when the caller's identifier doesn't
//! resolve to a known PURL. The function's match-type ordering is
//! the user-visible behavior locked in here.

use std::path::PathBuf;

use socket_patch_core::crawlers::types::CrawledPackage;
use socket_patch_core::utils::fuzzy_match::fuzzy_match_packages;

fn pkg(name: &str, version: &str, namespace: Option<&str>) -> CrawledPackage {
    let ns = namespace.map(str::to_string);
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
fn exact_full_name_match_wins() {
    let packages = vec![
        pkg("node", "20.0.0", Some("@types")),
        pkg("node-fetch", "3.0.0", None),
    ];
    let results = fuzzy_match_packages("@types/node", &packages, 20);
    assert_eq!(results.len(), 1, "exact full-name match excludes substrings");
    assert_eq!(results[0].name, "node");
    assert_eq!(results[0].namespace.as_deref(), Some("@types"));
}

#[test]
fn exact_name_match_wins_over_prefix() {
    let packages = vec![
        pkg("node", "20.0.0", Some("@types")),
        pkg("lodash", "4.17.21", None),
    ];
    let results = fuzzy_match_packages("node", &packages, 20);
    assert_eq!(
        results[0].name, "node",
        "exact name match beats no-match siblings"
    );
}

#[test]
fn prefix_match_orders_before_contains() {
    let packages = vec![pkg("lodash", "4.17.21", None), pkg("lodash-es", "4.17.21", None)];
    let results = fuzzy_match_packages("lodash", &packages, 20);
    assert_eq!(results.len(), 2);
    assert_eq!(
        results[0].name, "lodash",
        "ExactName outranks PrefixName for the same query"
    );
}

#[test]
fn contains_match_returns_partial() {
    let packages = vec![pkg("string-width", "5.0.0", None)];
    let results = fuzzy_match_packages("width", &packages, 20);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "string-width");
}

#[test]
fn no_match_returns_empty() {
    let packages = vec![pkg("lodash", "4.17.21", None)];
    let results = fuzzy_match_packages("zzz-no-such-thing", &packages, 20);
    assert!(results.is_empty());
}

#[test]
fn empty_or_whitespace_query_returns_empty() {
    let packages = vec![pkg("lodash", "4.17.21", None)];
    assert!(fuzzy_match_packages("", &packages, 20).is_empty());
    assert!(fuzzy_match_packages("   ", &packages, 20).is_empty());
}

#[test]
fn case_insensitive_match() {
    let packages = vec![pkg("React", "18.0.0", None)];
    let results = fuzzy_match_packages("react", &packages, 20);
    assert_eq!(results.len(), 1);
}

#[test]
fn limit_caps_result_count() {
    let packages: Vec<CrawledPackage> = (0..50)
        .map(|i| pkg(&format!("pkg-{i}"), "1.0.0", None))
        .collect();
    let results = fuzzy_match_packages("pkg", &packages, 10);
    assert_eq!(results.len(), 10);
}
