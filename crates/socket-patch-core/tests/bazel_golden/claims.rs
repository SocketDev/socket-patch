//! Goldens: writes `target/bazel-claims.json`, what `lanes::claims_json()`
//! renders, for the claims audit (design 9.5): `scripts/bazel-matrix-audit.py
//! --claims` holds every claimed Bazel line, dependency system and OS to
//! the report of an executed real-Bazel cell.
//!
//! The audit job runs exactly the test `claims::dump` and then requires
//! the file, so the test keeps that name at the top level of this file
//! (`scripts/tests/test_ci_bazel_prefixes.py` holds it to that).

use std::path::Path;

use serde_json::Value;
use socket_patch_core::bazel::lanes;

/// The keys of a claim row. The audit reads the first eight, and holds
/// `bump` (the test that ran the lane's bump cell) to a `ran` report
/// where `classes` list a hook or a tag edit; the rest say what the lane
/// may do to a repository (revision 4, section 5 item 8), for the
/// reviewer of the claim.
const KEYS: [&str; 13] = [
    "lane", "mode", "ruleset", "tier", "lo", "hi", "system", "os", "classes", "anchor", "stale",
    "tool", "bump",
];

#[test]
fn dump() {
    let claims = lanes::claims_json();
    let doc: Value = serde_json::from_str(&claims).expect("the claims are JSON");
    assert_eq!(doc["version"], 2, "the audit reads version 2");
    let rows = doc["claims"].as_array().expect("a list of claims");
    // A lane claims a line only with the change that enables it, and no
    // production lane is enabled: the list is empty until one is.
    let enabled = lanes::PRODUCTION.specs().filter(|(_, spec)| spec.enabled);
    let claimed: usize = enabled
        .map(|(_, spec)| spec.supported.len() + lanes::claims::line_claims(spec.id).count())
        .sum();
    assert_eq!(rows.len(), claimed);
    for row in rows {
        let row = row.as_object().expect("a claim is an object");
        let keys: Vec<&str> = row.keys().map(String::as_str).collect();
        assert!(
            KEYS.iter().all(|key| keys.contains(key)) && keys.len() == KEYS.len(),
            "{row:?}"
        );
    }
    let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    std::fs::create_dir_all(&target).expect("create target/");
    std::fs::write(target.join("bazel-claims.json"), &claims).expect("write the claims");
}
