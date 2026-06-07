//! Cross-cutting OpenVEX 0.2.0 spec conformance tests.
//!
//! These tests do not fit cleanly inside any single submodule —
//! they assert invariants that span the whole pipeline (schema +
//! builder + serializer). Source of truth:
//! <https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md>.
//!
//! If a future schema or builder change breaks any of these, the
//! generated documents will fail external validators (Grype, Trivy,
//! `vexctl merge`) — so we want a tight failure here, not at the
//! integration boundary.

use super::*;
use crate::manifest::schema::{
    PatchFileInfo, PatchManifest, PatchRecord, VulnerabilityInfo,
};
use std::collections::HashMap;

fn vuln(cves: &[&str]) -> VulnerabilityInfo {
    VulnerabilityInfo {
        cves: cves.iter().map(|s| (*s).to_string()).collect(),
        summary: String::new(),
        severity: "high".to_string(),
        description: String::new(),
    }
}

fn record(uuid: &str, vulns: &[(&str, &[&str])]) -> PatchRecord {
    let mut vmap = HashMap::new();
    for (id, cves) in vulns {
        vmap.insert((*id).to_string(), vuln(cves));
    }
    let mut files = HashMap::new();
    files.insert(
        "index.js".to_string(),
        PatchFileInfo {
            before_hash: "aa".to_string(),
            after_hash: "bb".to_string(),
        },
    );
    PatchRecord {
        uuid: uuid.to_string(),
        exported_at: String::new(),
        files,
        vulnerabilities: vmap,
        description: String::new(),
        license: "MIT".to_string(),
        tier: "free".to_string(),
    }
}

fn options() -> BuildOptions {
    BuildOptions {
        product_id: "pkg:npm/test-app@1.0.0".to_string(),
        doc_id: "urn:uuid:11111111-1111-4111-8111-111111111111".to_string(),
        author: "Socket".to_string(),
        tooling: Some("socket-patch 3.0.0".to_string()),
    }
}

fn sample_doc() -> Document {
    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/lodash@4.17.20".to_string(),
        record(
            "uuid-1",
            &[("GHSA-aaaa", &["CVE-2024-1", "CVE-2024-2"])],
        ),
    );
    manifest.patches.insert(
        "pkg:npm/minimist@1.2.0".to_string(),
        record("uuid-2", &[("GHSA-bbbb", &["CVE-2024-3"])]),
    );
    build_document(
        &manifest,
        &[
            "pkg:npm/lodash@4.17.20".to_string(),
            "pkg:npm/minimist@1.2.0".to_string(),
        ],
        &options(),
    )
    .expect("build sample doc")
}

/// A document whose single statement is the result of MERGING two
/// patches that share one vuln id and one overlapping CVE. Unlike
/// `sample_doc` (every statement carries a single subcomponent and a
/// set of all-distinct aliases), this fixture forces the builder's
/// transpose to collapse:
///   * two PURLs into one product with TWO subcomponents, and
///   * the duplicated `CVE-DUP` into a single alias.
/// The uniqueness/dedup conformance invariants below are vacuous
/// against `sample_doc`; they only have teeth against a merged
/// statement.
fn merged_doc() -> Document {
    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/aaa@1.0.0".to_string(),
        record("uuid-a", &[("GHSA-shared", &["CVE-DUP", "CVE-A-ONLY"])]),
    );
    manifest.patches.insert(
        "pkg:npm/bbb@2.0.0".to_string(),
        record("uuid-b", &[("GHSA-shared", &["CVE-DUP", "CVE-B-ONLY"])]),
    );
    build_document(
        &manifest,
        &[
            "pkg:npm/aaa@1.0.0".to_string(),
            "pkg:npm/bbb@2.0.0".to_string(),
        ],
        &options(),
    )
    .expect("build merged doc")
}

// ── 1. `@context` literal value ─────────────────────────────────

#[test]
fn context_is_the_canonical_v0_2_0_iri() {
    assert_eq!(OPENVEX_CONTEXT_V0_2_0, "https://openvex.dev/ns/v0.2.0");
    let doc = sample_doc();
    assert_eq!(doc.context, OPENVEX_CONTEXT_V0_2_0);
    let v = serde_json::to_value(&doc).unwrap();
    assert_eq!(v["@context"], OPENVEX_CONTEXT_V0_2_0);
}

// ── 2. JSON-LD `@`-prefixed keys are emitted as such ────────────

#[test]
fn at_prefixed_keys_use_at_sign_in_output() {
    let doc = sample_doc();
    let v = serde_json::to_value(&doc).unwrap();
    let doc_obj = v.as_object().unwrap();
    // Document-level.
    assert!(doc_obj.contains_key("@context"));
    assert!(doc_obj.contains_key("@id"));
    assert!(!doc_obj.contains_key("context"));
    assert!(!doc_obj.contains_key("id"));
    // Product-level (every product `@id` field).
    for st in v["statements"].as_array().unwrap() {
        for p in st["products"].as_array().unwrap() {
            let p_obj = p.as_object().unwrap();
            assert!(p_obj.contains_key("@id"), "product missing @id");
            assert!(!p_obj.contains_key("id"));
            // Subcomponents too.
            if let Some(subs) = p_obj.get("subcomponents") {
                for sub in subs.as_array().unwrap() {
                    let sub_obj = sub.as_object().unwrap();
                    assert!(sub_obj.contains_key("@id"));
                    assert!(!sub_obj.contains_key("id"));
                }
            }
        }
    }
}

// ── 3. Status / justification literal strings ───────────────────

#[test]
fn all_four_status_literals_match_spec() {
    // Spec section: "Status enum values".
    let expected = [
        (Status::NotAffected, "not_affected"),
        (Status::Affected, "affected"),
        (Status::Fixed, "fixed"),
        (Status::UnderInvestigation, "under_investigation"),
    ];
    for (variant, literal) in expected {
        assert_eq!(
            serde_json::to_value(variant).unwrap(),
            serde_json::Value::String(literal.to_string())
        );
    }
}

#[test]
fn all_five_justification_literals_match_spec() {
    // Spec section: "Status justifications". Pin each variant to
    // the exact snake_case string the spec calls out.
    let expected = [
        (Justification::ComponentNotPresent, "component_not_present"),
        (
            Justification::VulnerableCodeNotPresent,
            "vulnerable_code_not_present",
        ),
        (
            Justification::VulnerableCodeNotInExecutePath,
            "vulnerable_code_not_in_execute_path",
        ),
        (
            Justification::VulnerableCodeCannotBeControlledByAdversary,
            "vulnerable_code_cannot_be_controlled_by_adversary",
        ),
        (
            Justification::InlineMitigationsAlreadyExist,
            "inline_mitigations_already_exist",
        ),
    ];
    for (variant, literal) in expected {
        assert_eq!(
            serde_json::to_value(variant).unwrap(),
            serde_json::Value::String(literal.to_string())
        );
    }
}

// ── 4. Status ↔ Justification interaction ───────────────────────

#[test]
fn builder_only_emits_not_affected_with_justification() {
    // Spec: when status == not_affected, a statement MUST carry
    // either a justification or an impact_statement. Our builder
    // always emits both.
    let doc = sample_doc();
    assert!(!doc.statements.is_empty());
    for st in &doc.statements {
        assert_eq!(st.status, Status::NotAffected);
        assert!(
            st.justification.is_some(),
            "not_affected requires a justification"
        );
        assert!(
            st.impact_statement.is_some(),
            "not_affected requires an impact_statement (we always emit one)"
        );
        // Conversely, action_statement (canonical for `affected`)
        // MUST be absent when status is `not_affected`.
        assert!(
            st.action_statement.is_none(),
            "action_statement is reserved for status=affected"
        );
    }
}

#[test]
fn affected_statement_in_json_omits_justification() {
    // We never construct affected statements via the builder, but
    // we DO ship the type — pin the schema invariant that an
    // affected statement with no justification serializes without
    // emitting a `justification` key (per spec).
    let s = Statement {
        id: None,
        vulnerability: Vulnerability {
            name: "CVE-X".to_string(),
            aliases: Vec::new(),
        },
        timestamp: Some("2024-01-01T00:00:00Z".to_string()),
        last_updated: None,
        products: vec![Product {
            id: "pkg:npm/x@1.0.0".to_string(),
            identifiers: None,
            hashes: None,
            subcomponents: Vec::new(),
        }],
        status: Status::Affected,
        supplier: None,
        justification: None,
        impact_statement: None,
        action_statement: Some("Upgrade to 1.0.1".to_string()),
    };
    let v = serde_json::to_value(&s).unwrap();
    assert_eq!(v["status"], "affected");
    let obj = v.as_object().unwrap();
    assert!(!obj.contains_key("justification"));
    assert!(!obj.contains_key("impact_statement"));
    assert_eq!(v["action_statement"], "Upgrade to 1.0.1");
}

// ── 5. Required-field presence guarantees ───────────────────────

#[test]
fn every_required_top_level_document_field_is_serialized() {
    let v = serde_json::to_value(sample_doc()).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "@context",
        "@id",
        "author",
        "timestamp",
        "version",
        "statements",
    ] {
        assert!(obj.contains_key(key), "required key {key:?} missing");
    }
}

#[test]
fn every_required_statement_field_is_serialized() {
    let v = serde_json::to_value(sample_doc()).unwrap();
    for st in v["statements"].as_array().unwrap() {
        let obj = st.as_object().unwrap();
        for key in ["vulnerability", "timestamp", "products", "status"] {
            assert!(obj.contains_key(key), "required key {key:?} missing");
        }
    }
}

#[test]
fn every_required_product_field_is_serialized() {
    let v = serde_json::to_value(sample_doc()).unwrap();
    for st in v["statements"].as_array().unwrap() {
        for p in st["products"].as_array().unwrap() {
            assert!(p.as_object().unwrap().contains_key("@id"));
        }
    }
}

// ── 6. Identifier non-emptiness ─────────────────────────────────

#[test]
fn vulnerability_name_is_non_empty_in_every_emitted_statement() {
    let doc = sample_doc();
    for st in &doc.statements {
        assert!(
            !st.vulnerability.name.is_empty(),
            "vulnerability.name must not be empty"
        );
    }
}

#[test]
fn product_id_is_non_empty_in_every_emitted_statement() {
    let doc = sample_doc();
    for st in &doc.statements {
        for p in &st.products {
            assert!(!p.id.is_empty(), "product @id must not be empty");
            for sub in &p.subcomponents {
                assert!(!sub.id.is_empty(), "subcomponent @id must not be empty");
            }
        }
    }
}

#[test]
fn document_id_is_non_empty() {
    let doc = sample_doc();
    assert!(!doc.id.is_empty(), "document @id must not be empty");
}

// ── 7. Timestamp consistency ────────────────────────────────────

#[test]
fn all_statement_timestamps_match_document_timestamp() {
    let doc = sample_doc();
    for st in &doc.statements {
        assert_eq!(
            st.timestamp.as_deref(),
            Some(doc.timestamp.as_str()),
            "statement timestamp must match document timestamp"
        );
    }
}

#[test]
fn document_timestamp_is_rfc3339_z_form() {
    let doc = sample_doc();
    // Format: YYYY-MM-DDTHH:MM:SSZ — 20 chars total.
    assert_eq!(doc.timestamp.len(), 20);
    assert!(doc.timestamp.ends_with('Z'));
    assert_eq!(&doc.timestamp[4..5], "-");
    assert_eq!(&doc.timestamp[7..8], "-");
    assert_eq!(&doc.timestamp[10..11], "T");
    assert_eq!(&doc.timestamp[13..14], ":");
    assert_eq!(&doc.timestamp[16..17], ":");
    // Separators alone are not enough — a regression that emitted
    // `20X4-..` with correct punctuation would slip through. Assert the
    // numeric fields actually parse into plausible calendar ranges.
    let year: u32 = doc.timestamp[0..4].parse().expect("year digits");
    let month: u32 = doc.timestamp[5..7].parse().expect("month digits");
    let day: u32 = doc.timestamp[8..10].parse().expect("day digits");
    let hour: u32 = doc.timestamp[11..13].parse().expect("hour digits");
    let minute: u32 = doc.timestamp[14..16].parse().expect("minute digits");
    let second: u32 = doc.timestamp[17..19].parse().expect("second digits");
    assert!((1970..3000).contains(&year), "year out of range: {year}");
    assert!((1..=12).contains(&month), "month out of range: {month}");
    assert!((1..=31).contains(&day), "day out of range: {day}");
    assert!(hour < 24, "hour out of range: {hour}");
    assert!(minute < 60, "minute out of range: {minute}");
    assert!(second < 60, "second out of range: {second}");
}

// ── 8. Document revision counter ────────────────────────────────

#[test]
fn newly_built_document_starts_at_version_1() {
    // Spec: "The version field starts at 1 and is incremented on
    // each update to the document."
    let doc = sample_doc();
    assert_eq!(doc.version, 1);
}

#[test]
fn document_version_serializes_as_a_json_number_not_string() {
    // Regression: the struct field is `u32`, but a future `#[serde]`
    // attribute (or a switch to `String`) could emit `"version": "1"`.
    // OpenVEX validators (vexctl/Grype) require an integer here, so pin
    // the JSON *type* — `doc.version == 1` (test above) can't catch a
    // numeric-string drift since serde would still round-trip it.
    let v = serde_json::to_value(sample_doc()).unwrap();
    assert!(
        v["version"].is_u64(),
        "version must serialize as a JSON number, got {:?}",
        v["version"]
    );
    assert_eq!(v["version"].as_u64(), Some(1));
}

// ── 9. Full round-trip with every optional field populated ──────

#[test]
fn fully_populated_doc_round_trips_through_serde() {
    use std::collections::BTreeMap;

    let mut idents = BTreeMap::new();
    idents.insert("purl".to_string(), "pkg:npm/x@1.0".to_string());
    idents.insert("cpe23".to_string(), "cpe:2.3:a:foo:bar".to_string());
    let mut hashes = BTreeMap::new();
    hashes.insert("sha256".to_string(), "deadbeef".to_string());

    let doc = Document {
        context: OPENVEX_CONTEXT_V0_2_0.to_string(),
        id: "urn:uuid:abc".to_string(),
        author: "Socket <vex@socket.dev>".to_string(),
        role: Some("publisher".to_string()),
        timestamp: "2024-01-01T00:00:00Z".to_string(),
        last_updated: Some("2024-06-01T00:00:00Z".to_string()),
        version: 7,
        tooling: Some("socket-patch 3.0.0".to_string()),
        statements: vec![Statement {
            id: Some("urn:uuid:stmt-1".to_string()),
            vulnerability: Vulnerability {
                name: "GHSA-xxx".to_string(),
                aliases: vec!["CVE-2024-1".to_string(), "CVE-2024-2".to_string()],
            },
            timestamp: Some("2024-01-01T00:00:00Z".to_string()),
            last_updated: Some("2024-06-01T00:00:00Z".to_string()),
            products: vec![Product {
                id: "pkg:npm/app@1.0.0".to_string(),
                identifiers: Some(idents.clone()),
                hashes: Some(hashes.clone()),
                subcomponents: vec![Subcomponent {
                    id: "pkg:npm/lodash@4.17.21".to_string(),
                    identifiers: Some(idents),
                    hashes: Some(hashes),
                }],
            }],
            status: Status::NotAffected,
            supplier: Some("https://example.com/supplier".to_string()),
            justification: Some(Justification::InlineMitigationsAlreadyExist),
            impact_statement: Some("Patched via Socket".to_string()),
            action_statement: None,
        }],
    };
    let json = serde_json::to_string_pretty(&doc).unwrap();
    let parsed: Document = serde_json::from_str(&json).unwrap();
    assert_eq!(doc, parsed, "fully-populated doc must round-trip");
}

// ── 10. No `null` values anywhere in builder output ─────────────

#[test]
fn builder_output_contains_no_null_json_values() {
    // skip_serializing_if invariant: every optional field is
    // omitted, not serialized as `null`. Walk the entire tree.
    fn assert_no_nulls(v: &serde_json::Value, path: &str) {
        match v {
            serde_json::Value::Null => panic!("found null at {path}"),
            serde_json::Value::Object(map) => {
                for (k, child) in map {
                    let p = format!("{path}.{k}");
                    assert_no_nulls(child, &p);
                }
            }
            serde_json::Value::Array(arr) => {
                for (i, child) in arr.iter().enumerate() {
                    let p = format!("{path}[{i}]");
                    assert_no_nulls(child, &p);
                }
            }
            _ => {}
        }
    }
    let v = serde_json::to_value(sample_doc()).unwrap();
    assert_no_nulls(&v, "<root>");
}

// ── 11. Builder produces UTF-8-safe JSON ────────────────────────

#[test]
fn builder_output_is_valid_utf8_json() {
    let doc = sample_doc();
    // Both encoders must succeed and produce identical parsed JSON.
    let compact = serde_json::to_string(&doc).unwrap();
    let pretty = serde_json::to_string_pretty(&doc).unwrap();
    let v_compact: serde_json::Value = serde_json::from_str(&compact).unwrap();
    let v_pretty: serde_json::Value = serde_json::from_str(&pretty).unwrap();
    // NOTE: compact-vs-pretty equality alone is a tautology — it holds
    // for ANY serializable value. The real interop invariant is that
    // the emitted JSON deserializes back into an *equal* `Document`
    // (this is what `vexctl merge` / Grype / Trivy rely on), so assert
    // that too.
    assert_eq!(v_compact, v_pretty);
    let reparsed_compact: Document = serde_json::from_str(&compact).unwrap();
    let reparsed_pretty: Document = serde_json::from_str(&pretty).unwrap();
    assert_eq!(reparsed_compact, doc, "compact output must round-trip");
    assert_eq!(reparsed_pretty, doc, "pretty output must round-trip");
}

// ── 12. Each emitted statement has at least one product ─────────

#[test]
fn every_emitted_statement_has_at_least_one_product() {
    // Spec: products is required and non-empty. The builder always
    // populates exactly one entry (the top-level product).
    let doc = sample_doc();
    for st in &doc.statements {
        assert!(!st.products.is_empty(), "products MUST NOT be empty");
    }
}

// ── 13. Vulnerability aliases are unique within a statement ─────

#[test]
fn vulnerability_aliases_are_unique_within_statement() {
    // Built from a MERGED statement so the dedup path is actually
    // exercised: two patches both list `CVE-DUP`, and the builder must
    // collapse it. (Against `sample_doc`, where every alias is already
    // distinct, this loop can never observe a duplicate — see the doc
    // comment on `merged_doc`.)
    let doc = merged_doc();
    for st in &doc.statements {
        let mut seen = std::collections::HashSet::new();
        for alias in &st.vulnerability.aliases {
            assert!(
                seen.insert(alias.clone()),
                "duplicate alias {alias:?} in statement"
            );
        }
    }
    // Non-vacuous guard: the merged statement carries multiple aliases
    // with the overlapping CVE present exactly once. If alias dedup
    // regressed, the loop above would fire on `CVE-DUP`.
    assert_eq!(doc.statements.len(), 1, "fixture must merge to one statement");
    assert_eq!(
        doc.statements[0].vulnerability.aliases,
        vec![
            "CVE-A-ONLY".to_string(),
            "CVE-B-ONLY".to_string(),
            "CVE-DUP".to_string(),
        ],
    );
}

// ── 14. Subcomponent @ids are unique within a product ───────────

#[test]
fn subcomponent_ids_are_unique_within_product() {
    // Built from a MERGED statement so a product with MORE THAN ONE
    // subcomponent actually exists. Against `sample_doc` every product
    // has exactly one subcomponent, so the uniqueness loop body runs at
    // most once and can never catch a duplicate.
    let doc = merged_doc();
    let mut saw_multi_subcomponent_product = false;
    for st in &doc.statements {
        for p in &st.products {
            if p.subcomponents.len() > 1 {
                saw_multi_subcomponent_product = true;
            }
            let mut seen = std::collections::HashSet::new();
            for sub in &p.subcomponents {
                assert!(
                    seen.insert(sub.id.clone()),
                    "duplicate subcomponent {:?} in product",
                    sub.id
                );
            }
        }
    }
    assert!(
        saw_multi_subcomponent_product,
        "fixture must exercise a product with >1 subcomponent, else this test is vacuous"
    );
}

// ── 15. Merged-statement transpose, at the JSON layer ───────────

#[test]
fn merged_statement_emits_all_subcomponents_with_at_id_in_serialized_json() {
    // The `PURL -> {vulnId}` → `vulnId -> {PURL}` transpose is the
    // crux of the builder; pin its serialized shape (not just the
    // in-memory structs `merged_doc` already exercises). The two
    // merged PURLs must surface as sorted subcomponents, each under the
    // JSON-LD `@id` key (never raw `id`).
    let doc = merged_doc();
    let v = serde_json::to_value(&doc).unwrap();
    let statements = v["statements"].as_array().unwrap();
    assert_eq!(statements.len(), 1, "two patches sharing a vuln → one statement");

    let subs = statements[0]["products"][0]["subcomponents"]
        .as_array()
        .unwrap();
    let ids: Vec<&str> = subs
        .iter()
        .map(|s| {
            let obj = s.as_object().unwrap();
            assert!(obj.contains_key("@id"), "subcomponent must use @id");
            assert!(!obj.contains_key("id"), "raw `id` must not leak");
            s["@id"].as_str().unwrap()
        })
        .collect();
    // Sorted for deterministic downstream diffs.
    assert_eq!(ids, vec!["pkg:npm/aaa@1.0.0", "pkg:npm/bbb@2.0.0"]);
}

// ── 16. Statement-level `@id` rename (gap in test #2) ───────────

#[test]
fn statement_level_id_renders_under_at_sign() {
    // The builder never sets `Statement.id`, so the cross-cutting
    // `@`-prefix test above (which walks builder output) never covers
    // the statement-level rename. Pin it directly: a present statement
    // id MUST serialize as `@id`, never raw `id`.
    let mut s = Statement {
        id: Some("urn:uuid:stmt-7".to_string()),
        vulnerability: Vulnerability {
            name: "GHSA-z".to_string(),
            aliases: Vec::new(),
        },
        timestamp: Some("2024-01-01T00:00:00Z".to_string()),
        last_updated: None,
        products: vec![Product {
            id: "pkg:npm/x@1.0.0".to_string(),
            identifiers: None,
            hashes: None,
            subcomponents: Vec::new(),
        }],
        status: Status::NotAffected,
        supplier: None,
        justification: Some(Justification::InlineMitigationsAlreadyExist),
        impact_statement: Some("Patched via Socket".to_string()),
        action_statement: None,
    };
    let v = serde_json::to_value(&s).unwrap();
    assert_eq!(v["@id"], "urn:uuid:stmt-7");
    assert!(!v.as_object().unwrap().contains_key("id"));

    // And when absent, neither `@id` nor `id` appears.
    s.id = None;
    let v = serde_json::to_value(&s).unwrap();
    let obj = v.as_object().unwrap();
    assert!(!obj.contains_key("@id"), "absent statement id must omit @id");
    assert!(!obj.contains_key("id"));
}

// ── 17. One statement per vulnerability id (grouping invariant) ──

#[test]
fn no_two_statements_share_a_vulnerability_name() {
    // The builder's transpose groups by vuln id, so a well-formed doc
    // never emits two statements for the same vulnerability — merging
    // collapses them into one (with all PURLs as subcomponents). Pin
    // that at the document layer: `sample_doc` carries two *distinct*
    // vulns (GHSA-aaaa / GHSA-bbbb) and `merged_doc` collapses a shared
    // one (GHSA-shared) to a single statement. A grouping regression
    // (e.g. keying on purl+vuln instead of vuln) would surface as a
    // duplicate name here.
    for doc in [sample_doc(), merged_doc()] {
        let mut seen = std::collections::HashSet::new();
        for st in &doc.statements {
            assert!(
                seen.insert(st.vulnerability.name.clone()),
                "duplicate vulnerability name {:?} across statements",
                st.vulnerability.name
            );
        }
    }
    // Non-vacuity: the two fixtures exercise both the multi-statement
    // (distinct vulns) and the single-merged-statement shapes.
    assert_eq!(sample_doc().statements.len(), 2);
    assert_eq!(merged_doc().statements.len(), 1);
}

// ── 18. Fixtures stay non-vacuous (guards the tests above) ──────

#[test]
fn fixtures_carry_subcomponents_so_at_id_walks_have_teeth() {
    // Several tests above (#2 `@`-prefix walk, #6 non-emptiness) only
    // reach the subcomponent assertions when the fixture actually
    // produces subcomponents. If a future fixture edit dropped them,
    // those tests would pass vacuously. Pin the precondition directly.
    for st in &sample_doc().statements {
        for p in &st.products {
            assert!(
                !p.subcomponents.is_empty(),
                "sample_doc product must carry >=1 subcomponent"
            );
        }
    }
    let merged = merged_doc();
    assert!(
        merged.statements[0].products[0].subcomponents.len() >= 2,
        "merged_doc must produce a product with >=2 subcomponents"
    );
}
