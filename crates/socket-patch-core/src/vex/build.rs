//! Manifest + applied-set → OpenVEX `Document` builder.
//!
//! The grouping rule (one statement per vulnerability ID) means we
//! transpose the manifest: it stores `PURL -> { vulnId -> info }`, but
//! VEX wants `vulnId -> { products (and subcomponents) }`. We do that
//! transpose once, then sort to keep output deterministic.
//!
//! GHSA naming convention: we use the vuln-ID key (typically GHSA-xxxx)
//! as `Vulnerability.name` and the `cves` array as `aliases`. If a
//! single manifest entry has both — the manifest's key and `cves` —
//! the latter become aliases. When two patches fix the same vuln ID
//! they merge into one statement with both PURLs as subcomponents.

use std::collections::BTreeMap;

use crate::manifest::schema::PatchManifest;
use crate::vex::schema::{
    Document, Justification, Product, Statement, Status, Subcomponent, Vulnerability,
    OPENVEX_CONTEXT_V0_2_0,
};
use crate::vex::time::now_rfc3339;

/// Inputs for the document builder. The caller owns config like
/// `author` and `doc_id` so the builder stays pure.
#[derive(Debug, Clone)]
pub struct BuildOptions {
    /// Top-level product PURL/identifier.
    pub product_id: String,
    /// Document `@id` (e.g. `urn:uuid:...`). Caller-controlled so the
    /// CLI can honor a `--doc-id` override or default to a random UUID.
    pub doc_id: String,
    /// Document `author` field. Defaults to "Socket" at the CLI layer.
    pub author: String,
    /// Optional `tooling` string. Conventionally `socket-patch <version>`.
    pub tooling: Option<String>,
}

/// Build a VEX document from a manifest and a set of applied PURLs.
///
/// `applied` is a list of PURLs that have been verified (or were
/// declared verified via `--no-verify`). Manifest entries not in
/// `applied` are silently dropped — see the design note in
/// `vex::verify` for why we never emit `affected`.
///
/// Returns `None` when no statements can be emitted (no applied
/// patches matched the manifest). The CLI converts `None` into a
/// non-zero exit code per the agreed contract.
pub fn build_document(
    manifest: &PatchManifest,
    applied: &[String],
    opts: &BuildOptions,
) -> Option<Document> {
    let timestamp = now_rfc3339();
    let applied_set: std::collections::HashSet<&str> =
        applied.iter().map(|s| s.as_str()).collect();

    // vuln-id -> (aliases, impact-statement parts, subcomponent PURLs)
    // BTreeMap keeps statement order deterministic by vuln id, which
    // helps reproducibility for downstream diffs.
    let mut grouped: BTreeMap<String, VulnGroup> = BTreeMap::new();

    for (purl, record) in &manifest.patches {
        if !applied_set.contains(purl.as_str()) {
            continue;
        }
        for (vuln_id, info) in &record.vulnerabilities {
            let entry = grouped.entry(vuln_id.clone()).or_default();
            for cve in &info.cves {
                if !entry.aliases.contains(cve) {
                    entry.aliases.push(cve.clone());
                }
            }
            entry.subcomponents.insert(purl.clone());
            entry
                .impact_parts
                .push(format!("Patched via Socket patch {}", record.uuid));
        }
    }

    if grouped.is_empty() {
        return None;
    }

    let mut statements = Vec::with_capacity(grouped.len());
    for (vuln_id, group) in grouped {
        let mut aliases = group.aliases;
        aliases.sort();

        let mut subcomponent_ids: Vec<String> = group.subcomponents.into_iter().collect();
        subcomponent_ids.sort();
        let subcomponents = subcomponent_ids
            .into_iter()
            .map(|id| Subcomponent { id })
            .collect();

        let mut parts = group.impact_parts;
        parts.sort();
        parts.dedup();
        let impact_statement = if parts.is_empty() {
            None
        } else {
            Some(parts.join("; "))
        };

        statements.push(Statement {
            vulnerability: Vulnerability {
                name: vuln_id,
                aliases,
            },
            timestamp: timestamp.clone(),
            products: vec![Product {
                id: opts.product_id.clone(),
                subcomponents,
            }],
            status: Status::NotAffected,
            justification: Some(Justification::InlineMitigationsAlreadyExist),
            impact_statement,
        });
    }

    Some(Document {
        context: OPENVEX_CONTEXT_V0_2_0.to_string(),
        id: opts.doc_id.clone(),
        author: opts.author.clone(),
        timestamp,
        version: 1,
        tooling: opts.tooling.clone(),
        statements,
    })
}

#[derive(Default)]
struct VulnGroup {
    aliases: Vec<String>,
    subcomponents: std::collections::HashSet<String>,
    impact_parts: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::schema::{PatchFileInfo, PatchRecord, VulnerabilityInfo};
    use std::collections::HashMap;

    fn record(uuid: &str, vulns: Vec<(&str, Vec<&str>)>) -> PatchRecord {
        let mut vmap = HashMap::new();
        for (vid, cves) in vulns {
            vmap.insert(
                vid.to_string(),
                VulnerabilityInfo {
                    cves: cves.into_iter().map(String::from).collect(),
                    summary: String::new(),
                    severity: "high".to_string(),
                    description: String::new(),
                },
            );
        }
        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash: "aaaa".to_string(),
                after_hash: "bbbb".to_string(),
            },
        );
        PatchRecord {
            uuid: uuid.to_string(),
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            files,
            vulnerabilities: vmap,
            description: String::new(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
        }
    }

    fn opts() -> BuildOptions {
        BuildOptions {
            product_id: "pkg:npm/app@1.0.0".to_string(),
            doc_id: "urn:uuid:test".to_string(),
            author: "Socket".to_string(),
            tooling: Some("socket-patch 3.0.0".to_string()),
        }
    }

    #[test]
    fn empty_applied_returns_none() {
        let manifest = PatchManifest::new();
        assert!(build_document(&manifest, &[], &opts()).is_none());
    }

    #[test]
    fn unapplied_patch_is_skipped() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/lodash@4.0.0".to_string(),
            record("u1", vec![("GHSA-aaaa", vec!["CVE-2024-1"])]),
        );
        // applied is empty → no statements → None.
        assert!(build_document(&manifest, &[], &opts()).is_none());
    }

    #[test]
    fn single_patch_single_vuln_produces_one_statement() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/lodash@4.0.0".to_string(),
            record("u1", vec![("GHSA-aaaa", vec!["CVE-2024-1"])]),
        );
        let doc = build_document(
            &manifest,
            &["pkg:npm/lodash@4.0.0".to_string()],
            &opts(),
        )
        .unwrap();

        assert_eq!(doc.statements.len(), 1);
        let st = &doc.statements[0];
        assert_eq!(st.vulnerability.name, "GHSA-aaaa");
        assert_eq!(st.vulnerability.aliases, vec!["CVE-2024-1".to_string()]);
        assert_eq!(st.status, Status::NotAffected);
        assert_eq!(
            st.justification,
            Some(Justification::InlineMitigationsAlreadyExist)
        );
        assert_eq!(st.products.len(), 1);
        assert_eq!(st.products[0].id, "pkg:npm/app@1.0.0");
        assert_eq!(st.products[0].subcomponents.len(), 1);
        assert_eq!(
            st.products[0].subcomponents[0].id,
            "pkg:npm/lodash@4.0.0"
        );
        assert!(st.impact_statement.as_ref().unwrap().contains("u1"));
    }

    #[test]
    fn cves_flatten_into_aliases() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record(
                "u1",
                vec![("GHSA-bbbb", vec!["CVE-2024-2", "CVE-2024-3"])],
            ),
        );
        let doc = build_document(&manifest, &["pkg:npm/x@1.0.0".to_string()], &opts())
            .unwrap();
        let aliases = &doc.statements[0].vulnerability.aliases;
        assert_eq!(aliases.len(), 2);
        // Sorted for determinism.
        assert_eq!(aliases[0], "CVE-2024-2");
        assert_eq!(aliases[1], "CVE-2024-3");
    }

    #[test]
    fn two_patches_sharing_ghsa_merge_into_one_statement() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record("u1", vec![("GHSA-cccc", vec!["CVE-A"])]),
        );
        manifest.patches.insert(
            "pkg:npm/y@2.0.0".to_string(),
            record("u2", vec![("GHSA-cccc", vec!["CVE-A"])]),
        );

        let doc = build_document(
            &manifest,
            &[
                "pkg:npm/x@1.0.0".to_string(),
                "pkg:npm/y@2.0.0".to_string(),
            ],
            &opts(),
        )
        .unwrap();

        assert_eq!(doc.statements.len(), 1);
        let subs = &doc.statements[0].products[0].subcomponents;
        assert_eq!(subs.len(), 2);
        let ids: Vec<&str> = subs.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"pkg:npm/x@1.0.0"));
        assert!(ids.contains(&"pkg:npm/y@2.0.0"));
        // Both patch UUIDs surface in the impact statement.
        let imp = doc.statements[0].impact_statement.as_ref().unwrap();
        assert!(imp.contains("u1"));
        assert!(imp.contains("u2"));
    }

    #[test]
    fn one_patch_multiple_vulns_produces_one_statement_each() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record(
                "u1",
                vec![
                    ("GHSA-aaaa", vec!["CVE-1"]),
                    ("GHSA-bbbb", vec!["CVE-2"]),
                ],
            ),
        );

        let doc = build_document(&manifest, &["pkg:npm/x@1.0.0".to_string()], &opts())
            .unwrap();
        assert_eq!(doc.statements.len(), 2);
        // BTreeMap order → sorted by vuln id.
        assert_eq!(doc.statements[0].vulnerability.name, "GHSA-aaaa");
        assert_eq!(doc.statements[1].vulnerability.name, "GHSA-bbbb");
    }

    #[test]
    fn doc_carries_caller_supplied_fields() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record("u1", vec![("GHSA-aaaa", vec![])]),
        );
        let doc = build_document(&manifest, &["pkg:npm/x@1.0.0".to_string()], &opts())
            .unwrap();
        assert_eq!(doc.context, OPENVEX_CONTEXT_V0_2_0);
        assert_eq!(doc.id, "urn:uuid:test");
        assert_eq!(doc.author, "Socket");
        assert_eq!(doc.tooling.as_deref(), Some("socket-patch 3.0.0"));
        assert_eq!(doc.version, 1);
    }
}
