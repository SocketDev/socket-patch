//! OpenVEX 0.2.0 schema types.
//!
//! Hand-rolled from the OpenVEX 0.2.0 spec
//! (<https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md>) and
//! cross-checked against the Go reference implementation
//! (<https://github.com/openvex/go-vex/tree/main/pkg/vex>). The serde
//! representation must match the spec verbatim; the `vexctl merge`
//! step in our e2e suite is what catches drift.
//!
//! Field-level notes:
//! * `@context` / `@id` use serde renames because JSON-LD requires the
//!   literal `@`-prefixed keys.
//! * Optional fields use `Option<T>` + `skip_serializing_if = "Option::is_none"`
//!   so the emitted JSON omits them rather than emitting `null`. Matches
//!   the Go implementation's `omitempty` behavior.
//! * `version` is the OpenVEX document revision counter (integer,
//!   starts at 1). NOT the schema version.
//! * `Vec<Statement>` is always present (the spec allows it to be empty
//!   in principle, but our generator errors out before that state).
//! * `Product.identifiers` / `Product.hashes` (and same on
//!   `Subcomponent`) use `BTreeMap` instead of `HashMap` for
//!   deterministic key ordering — easier diffing across runs.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const OPENVEX_CONTEXT_V0_2_0: &str = "https://openvex.dev/ns/v0.2.0";

/// Top-level OpenVEX document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Document {
    #[serde(rename = "@context")]
    pub context: String,
    #[serde(rename = "@id")]
    pub id: String,
    pub author: String,
    /// Optional role declaration for `author`. Free-form per spec.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub role: Option<String>,
    pub timestamp: String,
    /// RFC 3339 timestamp of the most recent revision of this doc.
    /// Optional; absent in newly-issued documents.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_updated: Option<String>,
    pub version: u32,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tooling: Option<String>,
    pub statements: Vec<Statement>,
}

/// One VEX statement — the unit of "I am asserting that vulnerability X
/// has status S relative to product P".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Statement {
    /// Optional per-statement identifier. When present, must be unique
    /// within the document. Spec says it's used to track revisions.
    #[serde(rename = "@id", skip_serializing_if = "Option::is_none", default)]
    pub id: Option<String>,
    pub vulnerability: Vulnerability,
    /// RFC 3339 timestamp the statement's assertion was known true.
    /// Optional per spec — it cascades down from the document when a
    /// statement omits it (see OpenVEX inheritance rules), so a
    /// spec-valid document may legitimately leave it out. We always
    /// emit one (the builder clones the document timestamp), but the
    /// type must still accept its absence on parse, mirroring the
    /// sibling `last_updated` field below.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub timestamp: Option<String>,
    /// RFC 3339 timestamp of the most recent revision of this statement.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_updated: Option<String>,
    pub products: Vec<Product>,
    pub status: Status,
    /// Optional supplier IRI overriding the document-level author for
    /// this statement.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub supplier: Option<String>,
    /// Required when `status == not_affected` (per spec; we don't
    /// enforce at the type level — see `vex::conformance_tests`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub justification: Option<Justification>,
    /// Free-form explanation paired with `not_affected`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub impact_statement: Option<String>,
    /// Canonical companion to `status == affected` (per spec).
    /// We never emit `affected` today, but the field exists so the type
    /// round-trips a richer doc through our parser.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub action_statement: Option<String>,
}

/// Vulnerability identifier. `name` is the primary ID (we use the GHSA),
/// `aliases` holds the CVE list.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Vulnerability {
    pub name: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub aliases: Vec<String>,
}

/// A product the statement applies to. `@id` is a PURL or any URI; the
/// subcomponent list pinpoints the vulnerable transitive dep.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Product {
    #[serde(rename = "@id")]
    pub id: String,
    /// Optional auxiliary identifiers (PURL, CPE 2.2, CPE 2.3, etc.).
    /// Keys are the identifier type (e.g. `"purl"`, `"cpe23"`),
    /// values are the literal identifier strings.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub identifiers: Option<BTreeMap<String, String>>,
    /// Optional content hashes that pin the product to specific bytes.
    /// Keys are hash algorithms (e.g. `"sha256"`), values are hex.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub hashes: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub subcomponents: Vec<Subcomponent>,
}

/// A subcomponent of the product — i.e. the actual vulnerable dependency
/// the patch covers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Subcomponent {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub identifiers: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub hashes: Option<BTreeMap<String, String>>,
}

/// VEX status. Spec defines exactly these four values.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    NotAffected,
    Affected,
    Fixed,
    UnderInvestigation,
}

/// VEX `justification` enum — only required when `status = not_affected`.
/// Spec lists five canonical values; we expose them all even though
/// `socket-patch` only emits `InlineMitigationsAlreadyExist` today.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Justification {
    ComponentNotPresent,
    VulnerableCodeNotPresent,
    VulnerableCodeNotInExecutePath,
    VulnerableCodeCannotBeControlledByAdversary,
    InlineMitigationsAlreadyExist,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Status enum: every variant round-trips ─────────────────────

    /// Spec strings for `Status`. The list IS the contract — keep it
    /// matched against the OpenVEX 0.2.0 spec section "Statement
    /// Properties → status".
    const STATUS_LITERALS: &[(Status, &str)] = &[
        (Status::NotAffected, "not_affected"),
        (Status::Affected, "affected"),
        (Status::Fixed, "fixed"),
        (Status::UnderInvestigation, "under_investigation"),
    ];

    #[test]
    fn every_status_variant_serializes_to_spec_literal() {
        for (variant, literal) in STATUS_LITERALS {
            let json = serde_json::to_string(variant).unwrap();
            assert_eq!(json, format!("\"{literal}\""), "variant {variant:?}");
        }
    }

    #[test]
    fn every_status_variant_deserializes_from_spec_literal() {
        for (variant, literal) in STATUS_LITERALS {
            let parsed: Status = serde_json::from_str(&format!("\"{literal}\"")).unwrap();
            assert_eq!(parsed, *variant, "literal {literal:?}");
        }
    }

    #[test]
    fn status_rejects_unknown_literal() {
        let r: Result<Status, _> = serde_json::from_str("\"pending\"");
        assert!(r.is_err(), "unknown status literal must fail to parse");
    }

    // ── Justification enum: every variant round-trips ──────────────

    const JUSTIFICATION_LITERALS: &[(Justification, &str)] = &[
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

    #[test]
    fn every_justification_variant_serializes_to_spec_literal() {
        for (variant, literal) in JUSTIFICATION_LITERALS {
            let json = serde_json::to_string(variant).unwrap();
            assert_eq!(json, format!("\"{literal}\""), "variant {variant:?}");
        }
    }

    #[test]
    fn every_justification_variant_deserializes_from_spec_literal() {
        for (variant, literal) in JUSTIFICATION_LITERALS {
            let parsed: Justification = serde_json::from_str(&format!("\"{literal}\"")).unwrap();
            assert_eq!(parsed, *variant, "literal {literal:?}");
        }
    }

    #[test]
    fn justification_rejects_unknown_literal() {
        let r: Result<Justification, _> = serde_json::from_str("\"hand_waving\"");
        assert!(r.is_err());
    }

    // ── Document field shape ──────────────────────────────────────

    fn empty_doc() -> Document {
        Document {
            context: OPENVEX_CONTEXT_V0_2_0.to_string(),
            id: "urn:uuid:1111".to_string(),
            author: "Socket".to_string(),
            role: None,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            last_updated: None,
            version: 1,
            tooling: None,
            statements: Vec::new(),
        }
    }

    #[test]
    fn document_renames_context_and_id() {
        let v = serde_json::to_value(empty_doc()).unwrap();
        assert_eq!(v["@context"], OPENVEX_CONTEXT_V0_2_0);
        assert_eq!(v["@id"], "urn:uuid:1111");
        let obj = v.as_object().unwrap();
        assert!(obj.get("context").is_none(), "raw `context` must not leak");
        assert!(obj.get("id").is_none(), "raw `id` must not leak");
    }

    #[test]
    fn document_omits_all_optional_fields_when_none() {
        let v = serde_json::to_value(empty_doc()).unwrap();
        let obj = v.as_object().unwrap();
        for key in ["role", "last_updated", "tooling"] {
            assert!(
                !obj.contains_key(key),
                "key {key:?} must be omitted when None"
            );
        }
    }

    #[test]
    fn document_emits_optional_fields_when_some() {
        let mut doc = empty_doc();
        doc.role = Some("publisher".to_string());
        doc.last_updated = Some("2024-02-01T00:00:00Z".to_string());
        doc.tooling = Some("socket-patch 3.0.0".to_string());

        let v = serde_json::to_value(&doc).unwrap();
        assert_eq!(v["role"], "publisher");
        assert_eq!(v["last_updated"], "2024-02-01T00:00:00Z");
        assert_eq!(v["tooling"], "socket-patch 3.0.0");
    }

    #[test]
    fn document_version_round_trips_arbitrary_u32() {
        for v in [1u32, 2, 7, 42, u32::MAX] {
            let mut doc = empty_doc();
            doc.version = v;
            let json = serde_json::to_string(&doc).unwrap();
            let parsed: Document = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.version, v);
        }
    }

    #[test]
    fn document_rejects_missing_required_fields() {
        // Drop the `@context` key — required field, parser must error.
        let bad = r#"{
            "@id": "urn:uuid:1",
            "author": "Socket",
            "timestamp": "2024-01-01T00:00:00Z",
            "version": 1,
            "statements": []
        }"#;
        let r: Result<Document, _> = serde_json::from_str(bad);
        assert!(r.is_err());
    }

    // ── Statement field shape ─────────────────────────────────────

    fn minimal_statement() -> Statement {
        Statement {
            id: None,
            vulnerability: Vulnerability {
                name: "GHSA-xxxx".to_string(),
                aliases: Vec::new(),
            },
            timestamp: Some("2024-01-01T00:00:00Z".to_string()),
            last_updated: None,
            products: vec![Product {
                id: "pkg:npm/app@1.0.0".to_string(),
                identifiers: None,
                hashes: None,
                subcomponents: Vec::new(),
            }],
            status: Status::NotAffected,
            supplier: None,
            justification: None,
            impact_statement: None,
            action_statement: None,
        }
    }

    #[test]
    fn statement_omits_all_optional_fields_when_none() {
        let v = serde_json::to_value(minimal_statement()).unwrap();
        let obj = v.as_object().unwrap();
        for key in [
            "@id",
            "last_updated",
            "supplier",
            "justification",
            "impact_statement",
            "action_statement",
        ] {
            assert!(
                !obj.contains_key(key),
                "key {key:?} must be omitted when None"
            );
        }
        // The `aliases` key on the inner vulnerability also omits-empty.
        assert!(
            v["vulnerability"]
                .as_object()
                .unwrap()
                .get("aliases")
                .is_none(),
            "empty aliases must omit the key"
        );
    }

    #[test]
    fn statement_emits_id_under_at_prefix_and_other_optional_fields() {
        let mut s = minimal_statement();
        s.id = Some("urn:uuid:stmt-1".to_string());
        s.last_updated = Some("2024-02-01T00:00:00Z".to_string());
        s.supplier = Some("https://example.com/supplier".to_string());
        s.justification = Some(Justification::InlineMitigationsAlreadyExist);
        s.impact_statement = Some("Patched via Socket".to_string());
        s.action_statement = Some("Apply socket-patch <uuid>".to_string());

        let v = serde_json::to_value(&s).unwrap();
        // `@id` not raw `id`.
        assert_eq!(v["@id"], "urn:uuid:stmt-1");
        assert!(v.as_object().unwrap().get("id").is_none());

        assert_eq!(v["last_updated"], "2024-02-01T00:00:00Z");
        assert_eq!(v["supplier"], "https://example.com/supplier");
        assert_eq!(v["justification"], "inline_mitigations_already_exist");
        assert_eq!(v["impact_statement"], "Patched via Socket");
        assert_eq!(v["action_statement"], "Apply socket-patch <uuid>");
    }

    #[test]
    fn statement_with_both_justification_and_impact_emits_both_keys() {
        let mut s = minimal_statement();
        s.justification = Some(Justification::ComponentNotPresent);
        s.impact_statement = Some("Component is not bundled".to_string());
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["justification"], "component_not_present");
        assert_eq!(v["impact_statement"], "Component is not bundled");
    }

    // ── Vulnerability shape ───────────────────────────────────────

    #[test]
    fn vulnerability_with_zero_aliases_omits_key() {
        let v = serde_json::to_value(Vulnerability {
            name: "GHSA-x".to_string(),
            aliases: Vec::new(),
        })
        .unwrap();
        assert!(v.as_object().unwrap().get("aliases").is_none());
        assert_eq!(v["name"], "GHSA-x");
    }

    #[test]
    fn vulnerability_with_one_alias() {
        let v = serde_json::to_value(Vulnerability {
            name: "GHSA-x".to_string(),
            aliases: vec!["CVE-2024-1".to_string()],
        })
        .unwrap();
        let arr = v["aliases"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0], "CVE-2024-1");
    }

    #[test]
    fn vulnerability_with_many_aliases_preserves_order() {
        // Builder sorts aliases, but the type itself preserves input
        // order — important so callers can rely on Vec semantics.
        let aliases = vec![
            "CVE-Z".to_string(),
            "CVE-A".to_string(),
            "CVE-M".to_string(),
        ];
        let v = serde_json::to_value(Vulnerability {
            name: "GHSA-x".to_string(),
            aliases: aliases.clone(),
        })
        .unwrap();
        let arr = v["aliases"].as_array().unwrap();
        assert_eq!(arr.len(), 3);
        for (i, want) in aliases.iter().enumerate() {
            assert_eq!(arr[i], *want);
        }
    }

    // ── Product / Subcomponent shape ──────────────────────────────

    #[test]
    fn product_renames_id_and_omits_empty_subcomponents() {
        let p = Product {
            id: "pkg:npm/app@1.0.0".to_string(),
            identifiers: None,
            hashes: None,
            subcomponents: Vec::new(),
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["@id"], "pkg:npm/app@1.0.0");
        let obj = v.as_object().unwrap();
        assert!(obj.get("subcomponents").is_none());
        assert!(obj.get("identifiers").is_none());
        assert!(obj.get("hashes").is_none());
    }

    #[test]
    fn product_serializes_identifiers_and_hashes_when_set() {
        let mut idents = BTreeMap::new();
        idents.insert("purl".to_string(), "pkg:npm/app@1.0.0".to_string());
        idents.insert("cpe23".to_string(), "cpe:2.3:a:foo:bar:1.0".to_string());

        let mut hashes = BTreeMap::new();
        hashes.insert("sha256".to_string(), "deadbeef".to_string());

        let p = Product {
            id: "pkg:npm/app@1.0.0".to_string(),
            identifiers: Some(idents),
            hashes: Some(hashes),
            subcomponents: Vec::new(),
        };
        let v = serde_json::to_value(&p).unwrap();
        // BTreeMap → keys appear in sorted order in the JSON.
        assert_eq!(v["identifiers"]["cpe23"], "cpe:2.3:a:foo:bar:1.0");
        assert_eq!(v["identifiers"]["purl"], "pkg:npm/app@1.0.0");
        assert_eq!(v["hashes"]["sha256"], "deadbeef");
    }

    #[test]
    fn product_serializes_subcomponents_in_input_order() {
        let p = Product {
            id: "pkg:npm/app@1.0.0".to_string(),
            identifiers: None,
            hashes: None,
            subcomponents: vec![
                Subcomponent {
                    id: "pkg:npm/z@1.0".to_string(),
                    identifiers: None,
                    hashes: None,
                },
                Subcomponent {
                    id: "pkg:npm/a@1.0".to_string(),
                    identifiers: None,
                    hashes: None,
                },
            ],
        };
        let v = serde_json::to_value(&p).unwrap();
        let arr = v["subcomponents"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["@id"], "pkg:npm/z@1.0");
        assert_eq!(arr[1]["@id"], "pkg:npm/a@1.0");
    }

    #[test]
    fn subcomponent_with_identifiers_and_hashes_round_trips() {
        let mut idents = BTreeMap::new();
        idents.insert("purl".to_string(), "pkg:npm/lodash@4.17.21".to_string());
        let mut hashes = BTreeMap::new();
        hashes.insert("sha256".to_string(), "abc123".to_string());

        let sub = Subcomponent {
            id: "pkg:npm/lodash@4.17.21".to_string(),
            identifiers: Some(idents),
            hashes: Some(hashes),
        };
        let json = serde_json::to_string(&sub).unwrap();
        let parsed: Subcomponent = serde_json::from_str(&json).unwrap();
        assert_eq!(sub, parsed);
    }

    // ── Full-document round-trips ─────────────────────────────────

    #[test]
    fn document_roundtrips_minimal() {
        let doc = empty_doc();
        let json = serde_json::to_string(&doc).unwrap();
        let parsed: Document = serde_json::from_str(&json).unwrap();
        assert_eq!(doc, parsed);
    }

    #[test]
    fn document_roundtrips_with_all_fields_populated() {
        let mut idents = BTreeMap::new();
        idents.insert("purl".to_string(), "pkg:npm/app@1.0.0".to_string());
        let mut hashes = BTreeMap::new();
        hashes.insert("sha256".to_string(), "deadbeef".to_string());

        let doc = Document {
            context: OPENVEX_CONTEXT_V0_2_0.to_string(),
            id: "urn:uuid:abc".to_string(),
            author: "Socket".to_string(),
            role: Some("publisher".to_string()),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            last_updated: Some("2024-06-01T00:00:00Z".to_string()),
            version: 3,
            tooling: Some("socket-patch 3.0.0".to_string()),
            statements: vec![Statement {
                id: Some("urn:uuid:stmt-1".to_string()),
                vulnerability: Vulnerability {
                    name: "GHSA-xxx".to_string(),
                    aliases: vec!["CVE-2024-0001".to_string()],
                },
                timestamp: Some("2024-01-01T00:00:00Z".to_string()),
                last_updated: Some("2024-06-01T00:00:00Z".to_string()),
                products: vec![Product {
                    id: "pkg:npm/app@1.0.0".to_string(),
                    identifiers: Some(idents.clone()),
                    hashes: Some(hashes.clone()),
                    subcomponents: vec![Subcomponent {
                        id: "pkg:npm/lodash@4.17.21".to_string(),
                        identifiers: Some(idents.clone()),
                        hashes: Some(hashes.clone()),
                    }],
                }],
                status: Status::NotAffected,
                supplier: Some("https://example.com/supplier".to_string()),
                justification: Some(Justification::InlineMitigationsAlreadyExist),
                impact_statement: Some("Patched via Socket".to_string()),
                action_statement: Some("Apply socket-patch <uuid>".to_string()),
            }],
        };
        let json = serde_json::to_string_pretty(&doc).unwrap();
        let parsed: Document = serde_json::from_str(&json).unwrap();
        assert_eq!(doc, parsed);
    }

    #[test]
    fn parsing_a_doc_without_optional_fields_succeeds_via_default() {
        // Spec consumers will hand us docs that omit our new optional
        // fields. Defaulting must work end-to-end.
        let minimal = r#"{
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "urn:uuid:1",
            "author": "Socket",
            "timestamp": "2024-01-01T00:00:00Z",
            "version": 1,
            "statements": [
              {
                "vulnerability": {"name": "GHSA-x"},
                "timestamp": "2024-01-01T00:00:00Z",
                "products": [{"@id": "pkg:npm/app@1.0.0"}],
                "status": "not_affected"
              }
            ]
        }"#;
        let doc: Document = serde_json::from_str(minimal).unwrap();
        assert!(doc.role.is_none());
        assert!(doc.last_updated.is_none());
        assert!(doc.tooling.is_none());
        let st = &doc.statements[0];
        assert!(st.id.is_none());
        assert!(st.last_updated.is_none());
        assert!(st.supplier.is_none());
        assert!(st.action_statement.is_none());
    }

    // ── Statement timestamp is optional/inheritable per spec ───────

    /// Regression: the statement-level `timestamp` is OPTIONAL in
    /// OpenVEX 0.2.0 — it cascades from the document when omitted. A
    /// spec-valid statement that leaves it out (the canonical spec
    /// example does exactly this for a `fixed` statement) MUST parse,
    /// not error with "missing field `timestamp`". Previously the
    /// field was a required `String`, so this document was rejected.
    #[test]
    fn statement_without_timestamp_parses_and_leaves_it_none() {
        let doc_json = r#"{
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "urn:uuid:1",
            "author": "Socket",
            "timestamp": "2024-01-01T00:00:00Z",
            "version": 1,
            "statements": [
              {
                "vulnerability": {"name": "CVE-2014-123456"},
                "products": [{"@id": "pkg:apk/wolfi/bash@1.0.0"}],
                "status": "fixed"
              }
            ]
        }"#;
        let doc: Document =
            serde_json::from_str(doc_json).expect("statement may omit timestamp (inherited)");
        assert_eq!(doc.statements.len(), 1);
        assert!(
            doc.statements[0].timestamp.is_none(),
            "omitted statement timestamp must deserialize to None, not error"
        );
    }

    /// A statement timestamp that IS present round-trips through the
    /// `Option<String>` field, and an absent one is omitted from the
    /// serialized JSON (no `null`, no empty string).
    #[test]
    fn statement_timestamp_some_emits_none_omits() {
        let mut s = minimal_statement(); // carries Some(timestamp)
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["timestamp"], "2024-01-01T00:00:00Z");

        s.timestamp = None;
        let v = serde_json::to_value(&s).unwrap();
        assert!(
            v.as_object().unwrap().get("timestamp").is_none(),
            "None timestamp must be omitted, never serialized as null/empty"
        );
    }

    // ── Forward-compat: unmodeled spec fields are tolerated ────────

    /// OpenVEX 0.2.0 carries fields we intentionally don't model
    /// (statement-level `version`, `status_notes`,
    /// `action_statement_timestamp`, vulnerability `@id`/`description`).
    /// Real documents and future spec revisions will include them.
    /// Because no struct uses `#[serde(deny_unknown_fields)]`, parsing
    /// MUST ignore them rather than erroring — pin that so a future
    /// `deny_unknown_fields` (which would break interop) regresses here.
    #[test]
    fn parsing_tolerates_unmodeled_spec_fields() {
        let doc_json = r#"{
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "urn:uuid:1",
            "author": "Socket",
            "timestamp": "2024-01-01T00:00:00Z",
            "version": 1,
            "extra_doc_field": "ignored",
            "statements": [
              {
                "@id": "urn:uuid:stmt-1",
                "version": 2,
                "vulnerability": {
                  "@id": "https://nvd.example/CVE-2024-1",
                  "name": "GHSA-x",
                  "description": "an unmodeled field",
                  "aliases": ["CVE-2024-1"]
                },
                "timestamp": "2024-01-01T00:00:00Z",
                "status_notes": "determined by hand",
                "products": [{
                  "@id": "pkg:npm/app@1.0.0",
                  "subcomponents": [{"@id": "pkg:npm/lodash@4.17.21"}]
                }],
                "status": "not_affected",
                "justification": "inline_mitigations_already_exist",
                "action_statement_timestamp": "2024-01-02T00:00:00Z"
              }
            ]
        }"#;
        let doc: Document =
            serde_json::from_str(doc_json).expect("unmodeled spec fields must be ignored");
        assert_eq!(doc.statements.len(), 1);
        let st = &doc.statements[0];
        assert_eq!(st.vulnerability.name, "GHSA-x");
        assert_eq!(st.vulnerability.aliases, vec!["CVE-2024-1".to_string()]);
        assert_eq!(st.status, Status::NotAffected);
        assert_eq!(st.products[0].subcomponents[0].id, "pkg:npm/lodash@4.17.21");
    }

    // ── Wire format: multi-word keys stay snake_case ───────────────

    /// The statement-level multi-word keys MUST be emitted in the
    /// OpenVEX snake_case spelling. `Statement` has no `rename_all`, so
    /// this relies on the field idents already being snake_case.
    /// Round-trip tests can't catch a switch to
    /// `rename_all = "camelCase"` (ser/de would stay symmetric), so pin
    /// the exact emitted keys — and assert the camelCase forms are absent.
    #[test]
    fn statement_multiword_keys_emit_in_snake_case() {
        let mut s = minimal_statement();
        s.last_updated = Some("2024-02-01T00:00:00Z".to_string());
        s.impact_statement = Some("x".to_string());
        s.action_statement = Some("y".to_string());
        let v = serde_json::to_value(&s).unwrap();
        let obj = v.as_object().unwrap();
        for snake in ["last_updated", "impact_statement", "action_statement"] {
            assert!(obj.contains_key(snake), "missing snake_case key {snake:?}");
        }
        for camel in ["lastUpdated", "impactStatement", "actionStatement"] {
            assert!(
                !obj.contains_key(camel),
                "camelCase key {camel:?} must never be emitted"
            );
        }
    }
}
