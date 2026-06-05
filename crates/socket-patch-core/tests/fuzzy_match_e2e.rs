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
    assert_eq!(
        results.len(),
        1,
        "exact full-name match excludes substrings: only @types/node matches \
         the namespaced query, node-fetch must be filtered out"
    );
    assert_eq!(results[0].name, "node");
    assert_eq!(results[0].namespace.as_deref(), Some("@types"));
    assert_eq!(results[0].purl, "pkg:npm/@types/node@20.0.0");
}

#[test]
fn exact_name_match_wins_over_prefix() {
    // `node` is an ExactName match; `node-fetch` is a PrefixName match for the
    // same query. The exact match MUST sort first, and BOTH must be returned
    // (a regression collapsing exact-vs-prefix into one tier, or dropping the
    // prefix sibling entirely, would otherwise slip through).
    let packages = vec![
        pkg("node-fetch", "3.0.0", None),
        pkg("node", "20.0.0", Some("@types")),
    ];
    let results = fuzzy_match_packages("node", &packages, 20);
    assert_eq!(
        results.len(),
        2,
        "both the exact and the prefix sibling match query 'node'"
    );
    assert_eq!(
        results[0].name, "node",
        "ExactName must outrank PrefixName"
    );
    assert_eq!(results[0].namespace.as_deref(), Some("@types"));
    assert_eq!(
        results[1].name, "node-fetch",
        "the prefix match ranks second, not dropped"
    );
}

#[test]
fn prefix_match_orders_before_contains() {
    // Genuinely exercise the Prefix tier vs the Contains tier for one query:
    // `dashboard` is a prefix match of "dash"; `lodash` only *contains* "dash".
    // Prefix must outrank Contains regardless of alphabetical order ("dashboard"
    // happens to sort before "lodash", so a tie-break-only impl would also need
    // the tier ordering to be wrong-but-lucky — guard with a third, alphabetically
    // earliest, contains-only package).
    let packages = vec![
        pkg("lodash", "4.17.21", None),
        pkg("dashboard", "1.0.0", None),
        pkg("abc-dash", "1.0.0", None),
    ];
    let results = fuzzy_match_packages("dash", &packages, 20);
    assert_eq!(results.len(), 3, "all three match query 'dash'");
    assert_eq!(
        results[0].name, "dashboard",
        "PrefixName must outrank ContainsName even though 'abc-dash' sorts earlier"
    );
    // The remaining two are contains matches, ordered alphabetically.
    assert_eq!(results[1].name, "abc-dash");
    assert_eq!(results[2].name, "lodash");
}

#[test]
fn contains_match_returns_partial() {
    // `string-width` contains "width"; the decoy must be filtered out so a
    // single non-empty result can't pass vacuously.
    let packages = vec![
        pkg("string-width", "5.0.0", None),
        pkg("lodash", "4.17.21", None),
    ];
    let results = fuzzy_match_packages("width", &packages, 20);
    assert_eq!(results.len(), 1, "only the contains match survives filtering");
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
    // Tabs/newlines must trim to empty too.
    assert!(fuzzy_match_packages("\t\n", &packages, 20).is_empty());
}

#[test]
fn case_insensitive_match() {
    // The query case differs from the stored name; a non-matching decoy ensures
    // we're asserting the case-folded match actually fires, not that "any single
    // package is returned".
    let packages = vec![
        pkg("React", "18.0.0", None),
        pkg("lodash", "4.17.21", None),
    ];
    let results = fuzzy_match_packages("react", &packages, 20);
    assert_eq!(results.len(), 1, "case-insensitive match selects exactly React");
    assert_eq!(results[0].name, "React");
    // Uppercased query must resolve to the same package.
    let upper = fuzzy_match_packages("REACT", &packages, 20);
    assert_eq!(upper.len(), 1);
    assert_eq!(upper[0].name, "React");
}

#[test]
fn same_tier_ties_break_case_insensitively() {
    // Both names contain "e" (prefix of neither), so they share a match tier
    // and the alphabetical tie-break — which must ignore case — decides which
    // package becomes `matches[0]` and drives the patch lookup in `get`.
    let packages = vec![pkg("Zebra", "1.0.0", None), pkg("apple", "1.0.0", None)];
    let results = fuzzy_match_packages("e", &packages, 20);
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].name, "apple");
    assert_eq!(results[1].name, "Zebra");
}

#[test]
fn limit_caps_result_count() {
    let packages: Vec<CrawledPackage> = (0..50)
        .map(|i| pkg(&format!("pkg-{i}"), "1.0.0", None))
        .collect();
    let results = fuzzy_match_packages("pkg", &packages, 10);
    assert_eq!(results.len(), 10);
    // Every returned package must be a genuine match (no padding/garbage), and
    // they must be distinct.
    let mut names: Vec<&str> = results.iter().map(|p| p.name.as_str()).collect();
    assert!(
        names.iter().all(|n| n.starts_with("pkg-")),
        "limit must not invent or carry over non-matching entries"
    );
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), 10, "limited results must be distinct packages");
}

#[test]
fn limit_keeps_best_tier_not_first_seen() {
    // The exact match is appended LAST and is alphabetically last, so a
    // regression that truncated to `limit` BEFORE sorting (or sorted only
    // alphabetically) would drop it and surface a contains/prefix match instead.
    let packages = vec![
        pkg("ax", "1.0.0", None), // ContainsName of "x"
        pkg("bx", "1.0.0", None), // ContainsName of "x"
        pkg("x", "1.0.0", None),  // ExactFull — best tier, alphabetically last
    ];
    let results = fuzzy_match_packages("x", &packages, 1);
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].name, "x",
        "limit must keep the best-tier match, applied AFTER sorting"
    );
}

#[test]
fn namespaced_prefix_name_ranks_below_full() {
    // A namespaced package whose bare name prefixes the query is only a
    // PrefixName match (its "@scope/lodash" full name does not start with
    // "lod"); the un-namespaced "lodash-es" is a PrefixFull match and must
    // outrank it.
    let packages = vec![
        pkg("lodash", "4.17.21", Some("@scope")),
        pkg("lodash-es", "4.17.21", None),
    ];
    let results = fuzzy_match_packages("lod", &packages, 20);
    assert_eq!(results.len(), 2);
    assert_eq!(
        results[0].name, "lodash-es",
        "PrefixFull (no namespace) must outrank PrefixName (namespaced)"
    );
    assert!(results[0].namespace.is_none());
    assert_eq!(results[1].name, "lodash");
    assert_eq!(results[1].namespace.as_deref(), Some("@scope"));
}
