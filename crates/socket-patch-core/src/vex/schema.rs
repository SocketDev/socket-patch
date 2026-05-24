//! OpenVEX 0.2.0 schema types.
//!
//! Hand-rolled from the OpenVEX 0.2.0 spec
//! (<https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md>) and validated
//! against the Go reference implementation
//! (<https://github.com/openvex/go-vex/tree/main/pkg/vex>). The serde
//! representation must match the spec verbatim; the `vexctl validate`
//! step in our e2e suite is what catches drift.
//!
//! Field-level notes:
//! * `@context` and `@id` use serde renames because JSON-LD requires
//!   the literal `@`-prefixed keys.
//! * Optional fields use `Option<T>` + `skip_serializing_if = "Option::is_none"`
//!   so the emitted JSON omits them rather than emitting `null` — matches
//!   the Go implementation's omitempty behavior.
//! * `version` is the OpenVEX document revision counter (integer, starts at
//!   1). It is NOT the schema version.
//! * `Vec<Statement>` is always present (per spec it can be empty in
//!   principle, but our generator errors out before reaching that state —
//!   see `vex::generate`).

use serde::{Deserialize, Serialize};

pub const OPENVEX_CONTEXT_V0_2_0: &str = "https://openvex.dev/ns/v0.2.0";

/// Top-level OpenVEX document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Document {
    #[serde(rename = "@context")]
    pub context: String,
    #[serde(rename = "@id")]
    pub id: String,
    pub author: String,
    pub timestamp: String,
    pub version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tooling: Option<String>,
    pub statements: Vec<Statement>,
}

/// One VEX statement — the unit of "I am asserting that vulnerability X
/// has status S relative to product P".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Statement {
    pub vulnerability: Vulnerability,
    pub timestamp: String,
    pub products: Vec<Product>,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<Justification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact_statement: Option<String>,
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
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub subcomponents: Vec<Subcomponent>,
}

/// A subcomponent of the product — i.e. the actual vulnerable dependency
/// the patch covers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Subcomponent {
    #[serde(rename = "@id")]
    pub id: String,
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

    #[test]
    fn status_serializes_snake_case() {
        let s = serde_json::to_string(&Status::NotAffected).unwrap();
        assert_eq!(s, "\"not_affected\"");
        let s = serde_json::to_string(&Status::UnderInvestigation).unwrap();
        assert_eq!(s, "\"under_investigation\"");
    }

    #[test]
    fn justification_serializes_snake_case() {
        let j = serde_json::to_string(&Justification::InlineMitigationsAlreadyExist).unwrap();
        assert_eq!(j, "\"inline_mitigations_already_exist\"");
    }

    #[test]
    fn document_renames_context_and_id() {
        let doc = Document {
            context: OPENVEX_CONTEXT_V0_2_0.to_string(),
            id: "urn:uuid:1111".to_string(),
            author: "Socket".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            version: 1,
            tooling: Some("socket-patch 3.0.0".to_string()),
            statements: Vec::new(),
        };
        let v: serde_json::Value = serde_json::to_value(&doc).unwrap();
        assert_eq!(v["@context"], OPENVEX_CONTEXT_V0_2_0);
        assert_eq!(v["@id"], "urn:uuid:1111");
        assert!(v.as_object().unwrap().get("context").is_none());
        assert!(v.as_object().unwrap().get("id").is_none());
    }

    #[test]
    fn product_renames_id_and_omits_empty_subcomponents() {
        let p = Product {
            id: "pkg:npm/app@1.0.0".to_string(),
            subcomponents: Vec::new(),
        };
        let v: serde_json::Value = serde_json::to_value(&p).unwrap();
        assert_eq!(v["@id"], "pkg:npm/app@1.0.0");
        assert!(v.as_object().unwrap().get("subcomponents").is_none());
    }

    #[test]
    fn statement_skips_optional_fields_when_none() {
        let s = Statement {
            vulnerability: Vulnerability {
                name: "GHSA-xxxx".to_string(),
                aliases: Vec::new(),
            },
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            products: vec![Product {
                id: "pkg:npm/app@1.0.0".to_string(),
                subcomponents: Vec::new(),
            }],
            status: Status::NotAffected,
            justification: None,
            impact_statement: None,
        };
        let v: serde_json::Value = serde_json::to_value(&s).unwrap();
        let obj = v.as_object().unwrap();
        assert!(obj.get("justification").is_none());
        assert!(obj.get("impact_statement").is_none());
        assert!(v["vulnerability"].as_object().unwrap().get("aliases").is_none());
    }

    #[test]
    fn document_roundtrips_through_json() {
        let doc = Document {
            context: OPENVEX_CONTEXT_V0_2_0.to_string(),
            id: "urn:uuid:abc".to_string(),
            author: "Socket".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            version: 1,
            tooling: None,
            statements: vec![Statement {
                vulnerability: Vulnerability {
                    name: "GHSA-xxx".to_string(),
                    aliases: vec!["CVE-2024-0001".to_string()],
                },
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                products: vec![Product {
                    id: "pkg:npm/app@1.0.0".to_string(),
                    subcomponents: vec![Subcomponent {
                        id: "pkg:npm/lodash@4.17.21".to_string(),
                    }],
                }],
                status: Status::NotAffected,
                justification: Some(Justification::InlineMitigationsAlreadyExist),
                impact_statement: Some("Patched via Socket".to_string()),
            }],
        };
        let json = serde_json::to_string_pretty(&doc).unwrap();
        let parsed: Document = serde_json::from_str(&json).unwrap();
        assert_eq!(doc, parsed);
    }
}
