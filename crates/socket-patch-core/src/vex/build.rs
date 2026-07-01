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
    build_document_with_vendored(manifest, applied, &[], opts)
}

/// [`build_document`] with vendored-patch awareness: PURLs in `vendored`
/// (a subset of `applied`, from `VerifyOutcome::vendored`) carry the
/// impact-statement phrasing "Patched via Socket patch `<uuid>` (vendored)"
/// so the attestation records that the evidence is the committed
/// `.socket/vendor/` artifact, not the installed tree. Status and
/// justification are identical to the non-vendored form.
pub fn build_document_with_vendored(
    manifest: &PatchManifest,
    applied: &[String],
    vendored: &[String],
    opts: &BuildOptions,
) -> Option<Document> {
    build_document_with_provenance(manifest, applied, vendored, &[], opts)
}

/// [`build_document_with_vendored`] extended with a `redirected` set (PURLs
/// pointed at Socket's hosted vendored patches by `scan --redirect`). A
/// redirected PURL carries the phrasing "Patched via Socket patch `<uuid>`
/// (redirected)". `vendored` and `redirected` are disjoint in practice
/// (`--redirect` conflicts with `--vendor`); if a PURL somehow appears in
/// both, `vendored` wins. Status and justification are unchanged.
pub fn build_document_with_provenance(
    manifest: &PatchManifest,
    applied: &[String],
    vendored: &[String],
    redirected: &[String],
    opts: &BuildOptions,
) -> Option<Document> {
    let timestamp = now_rfc3339();
    let applied_set: std::collections::HashSet<&str> = applied.iter().map(|s| s.as_str()).collect();
    let vendored_set: std::collections::HashSet<&str> =
        vendored.iter().map(|s| s.as_str()).collect();
    let redirected_set: std::collections::HashSet<&str> =
        redirected.iter().map(|s| s.as_str()).collect();

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
                .push(if vendored_set.contains(purl.as_str()) {
                    format!("Patched via Socket patch {} (vendored)", record.uuid)
                } else if redirected_set.contains(purl.as_str()) {
                    format!("Patched via Socket patch {} (redirected)", record.uuid)
                } else {
                    format!("Patched via Socket patch {}", record.uuid)
                });
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
            .map(|id| Subcomponent {
                id,
                identifiers: None,
                hashes: None,
            })
            .collect();

        let mut parts = group.impact_parts;
        parts.sort();
        parts.dedup();
        // The `parts.is_empty()` branch is unreachable from the
        // public API: the loop above pushes one entry per applied
        // (purl, vuln) pair, so every group present in `grouped`
        // has ≥1 entry. The defensive `None` arm stays in case a
        // future refactor decouples grouping from impact tracking.
        let impact_statement = if parts.is_empty() {
            None
        } else {
            Some(parts.join("; "))
        };

        statements.push(Statement {
            id: None,
            vulnerability: Vulnerability {
                name: vuln_id,
                aliases,
            },
            timestamp: Some(timestamp.clone()),
            last_updated: None,
            products: vec![Product {
                id: opts.product_id.clone(),
                identifiers: None,
                hashes: None,
                subcomponents,
            }],
            status: Status::NotAffected,
            supplier: None,
            justification: Some(Justification::InlineMitigationsAlreadyExist),
            impact_statement,
            action_statement: None,
        });
    }

    Some(Document {
        context: OPENVEX_CONTEXT_V0_2_0.to_string(),
        id: opts.doc_id.clone(),
        author: opts.author.clone(),
        role: None,
        timestamp,
        last_updated: None,
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
        let doc =
            build_document(&manifest, &["pkg:npm/lodash@4.0.0".to_string()], &opts()).unwrap();

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
        assert_eq!(st.products[0].subcomponents[0].id, "pkg:npm/lodash@4.0.0");
        assert!(st.impact_statement.as_ref().unwrap().contains("u1"));
    }

    #[test]
    fn cves_flatten_into_aliases() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record("u1", vec![("GHSA-bbbb", vec!["CVE-2024-2", "CVE-2024-3"])]),
        );
        let doc = build_document(&manifest, &["pkg:npm/x@1.0.0".to_string()], &opts()).unwrap();
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
            &["pkg:npm/x@1.0.0".to_string(), "pkg:npm/y@2.0.0".to_string()],
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
                vec![("GHSA-aaaa", vec!["CVE-1"]), ("GHSA-bbbb", vec!["CVE-2"])],
            ),
        );

        let doc = build_document(&manifest, &["pkg:npm/x@1.0.0".to_string()], &opts()).unwrap();
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
        let doc = build_document(&manifest, &["pkg:npm/x@1.0.0".to_string()], &opts()).unwrap();
        assert_eq!(doc.context, OPENVEX_CONTEXT_V0_2_0);
        assert_eq!(doc.id, "urn:uuid:test");
        assert_eq!(doc.author, "Socket");
        assert_eq!(doc.tooling.as_deref(), Some("socket-patch 3.0.0"));
        assert_eq!(doc.version, 1);
    }

    // ── Edge-case coverage ────────────────────────────────────────

    /// `applied` references a PURL the manifest doesn't have. Must
    /// not panic, must not emit a statement for the missing PURL.
    #[test]
    fn applied_purl_absent_from_manifest_is_silently_skipped() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/in-manifest@1.0.0".to_string(),
            record("u1", vec![("GHSA-aaaa", vec!["CVE-1"])]),
        );

        let doc = build_document(
            &manifest,
            &[
                "pkg:npm/in-manifest@1.0.0".to_string(),
                "pkg:npm/ghost@9.9.9".to_string(), // not in manifest
            ],
            &opts(),
        )
        .unwrap();

        assert_eq!(doc.statements.len(), 1);
        let subs = &doc.statements[0].products[0].subcomponents;
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].id, "pkg:npm/in-manifest@1.0.0");
    }

    /// A patch in the manifest with zero vulnerabilities contributes
    /// no statements. Important: a patch is applied to fix files
    /// *without* a vuln record (rare but legal) → silently skip.
    #[test]
    fn applied_patch_with_zero_vulnerabilities_emits_no_statement() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/with-vuln@1.0.0".to_string(),
            record("u1", vec![("GHSA-aaaa", vec!["CVE-1"])]),
        );
        manifest
            .patches
            .insert("pkg:npm/no-vuln@2.0.0".to_string(), record("u2", vec![]));

        let doc = build_document(
            &manifest,
            &[
                "pkg:npm/with-vuln@1.0.0".to_string(),
                "pkg:npm/no-vuln@2.0.0".to_string(),
            ],
            &opts(),
        )
        .unwrap();

        assert_eq!(doc.statements.len(), 1);
        let subs = &doc.statements[0].products[0].subcomponents;
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].id, "pkg:npm/with-vuln@1.0.0");
    }

    /// A vulnerability with an empty CVE list → statement carries
    /// no `aliases` key (omit-when-empty per the serde attribute).
    #[test]
    fn empty_cve_list_produces_statement_with_no_aliases_key() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record("u1", vec![("GHSA-no-cves", vec![])]),
        );
        let doc = build_document(&manifest, &["pkg:npm/x@1.0.0".to_string()], &opts()).unwrap();
        assert_eq!(doc.statements[0].vulnerability.aliases.len(), 0);

        // Serialize and verify the JSON omits the `aliases` key.
        let v = serde_json::to_value(&doc.statements[0]).unwrap();
        assert!(v["vulnerability"]
            .as_object()
            .unwrap()
            .get("aliases")
            .is_none());
    }

    /// Two patches share a GHSA AND share a CVE → the CVE appears
    /// once in `aliases` (dedup-by-HashSet semantics).
    #[test]
    fn duplicate_cve_across_patches_deduped_in_aliases() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record(
                "u1",
                vec![("GHSA-shared", vec!["CVE-SHARED", "CVE-X-ONLY"])],
            ),
        );
        manifest.patches.insert(
            "pkg:npm/y@2.0.0".to_string(),
            record(
                "u2",
                vec![("GHSA-shared", vec!["CVE-SHARED", "CVE-Y-ONLY"])],
            ),
        );

        let doc = build_document(
            &manifest,
            &["pkg:npm/x@1.0.0".to_string(), "pkg:npm/y@2.0.0".to_string()],
            &opts(),
        )
        .unwrap();

        assert_eq!(doc.statements.len(), 1);
        let aliases = &doc.statements[0].vulnerability.aliases;
        // Three unique CVEs, sorted.
        assert_eq!(
            aliases.as_slice(),
            &[
                "CVE-SHARED".to_string(),
                "CVE-X-ONLY".to_string(),
                "CVE-Y-ONLY".to_string(),
            ]
        );
    }

    /// Same patch UUID used by two PURLs that share a GHSA → the
    /// impact_statement dedups the UUID-mention (no double-count).
    #[test]
    fn same_uuid_across_two_purls_deduped_in_impact_statement() {
        // Two manifest entries, identical UUID and GHSA. Real world:
        // the same patch package is fingerprinted against multiple
        // installed versions. Builder must dedup the impact line.
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record("shared-uuid", vec![("GHSA-shared", vec!["CVE-1"])]),
        );
        manifest.patches.insert(
            "pkg:npm/x@1.0.1".to_string(),
            record("shared-uuid", vec![("GHSA-shared", vec!["CVE-1"])]),
        );

        let doc = build_document(
            &manifest,
            &["pkg:npm/x@1.0.0".to_string(), "pkg:npm/x@1.0.1".to_string()],
            &opts(),
        )
        .unwrap();
        let imp = doc.statements[0].impact_statement.as_ref().unwrap();
        // Count occurrences of "shared-uuid" — must be exactly 1.
        assert_eq!(
            imp.matches("shared-uuid").count(),
            1,
            "duplicate UUID must collapse: {imp}"
        );
    }

    /// `BuildOptions.tooling = None` → `Document.tooling` is None and
    /// the JSON output omits the key. Previously only `Some` was
    /// asserted.
    #[test]
    fn tooling_none_omits_key_in_document() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record("u1", vec![("GHSA-x", vec![])]),
        );
        let opts = BuildOptions {
            product_id: "pkg:npm/app@1.0.0".to_string(),
            doc_id: "urn:uuid:t".to_string(),
            author: "Socket".to_string(),
            tooling: None,
        };
        let doc = build_document(&manifest, &["pkg:npm/x@1.0.0".to_string()], &opts).unwrap();
        assert!(doc.tooling.is_none());

        let v = serde_json::to_value(&doc).unwrap();
        assert!(v.as_object().unwrap().get("tooling").is_none());
    }

    /// Empty author string is allowed through unchanged. We don't
    /// special-case it; the CLI layer ensures a sensible default.
    #[test]
    fn empty_author_is_preserved_not_substituted() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record("u1", vec![("GHSA-x", vec![])]),
        );
        let opts = BuildOptions {
            product_id: "pkg:npm/app@1.0.0".to_string(),
            doc_id: "urn:uuid:t".to_string(),
            author: String::new(),
            tooling: None,
        };
        let doc = build_document(&manifest, &["pkg:npm/x@1.0.0".to_string()], &opts).unwrap();
        assert_eq!(doc.author, "");
    }

    /// Two builds with the same inputs produce statements with
    /// identical content and ordering. Timestamps may differ (the
    /// builder calls `now_rfc3339`) but the `statements` field is
    /// fully determined by the inputs.
    #[test]
    fn build_is_deterministic_modulo_timestamps() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record(
                "u1",
                vec![
                    ("GHSA-bbbb", vec!["CVE-2", "CVE-1"]),
                    ("GHSA-aaaa", vec!["CVE-3"]),
                ],
            ),
        );
        manifest.patches.insert(
            "pkg:npm/y@2.0.0".to_string(),
            record("u2", vec![("GHSA-aaaa", vec!["CVE-3"])]),
        );

        let applied = vec!["pkg:npm/x@1.0.0".to_string(), "pkg:npm/y@2.0.0".to_string()];

        let a = build_document(&manifest, &applied, &opts()).unwrap();
        let b = build_document(&manifest, &applied, &opts()).unwrap();

        // Sanity-strip the per-run timestamp before comparing.
        let strip = |mut d: Document| -> Document {
            d.timestamp = String::new();
            for s in d.statements.iter_mut() {
                s.timestamp = None;
            }
            d
        };
        assert_eq!(strip(a), strip(b));
    }

    /// Every statement's `timestamp` equals the document's `timestamp`.
    /// Builder pulls `now_rfc3339()` once and clones into each
    /// statement; the contract is "one wall-clock per invocation".
    #[test]
    fn all_statement_timestamps_equal_document_timestamp() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record(
                "u1",
                vec![("GHSA-a", vec!["CVE-1"]), ("GHSA-b", vec!["CVE-2"])],
            ),
        );
        let doc = build_document(&manifest, &["pkg:npm/x@1.0.0".to_string()], &opts()).unwrap();
        for st in &doc.statements {
            assert_eq!(st.timestamp.as_deref(), Some(doc.timestamp.as_str()));
        }
    }

    /// Every applied patch lacking a vulnerability record → `None`.
    /// Distinct from `applied_patch_with_zero_vulnerabilities_emits_no_statement`
    /// (which mixes a with-vuln patch in): here the *entire* applied set
    /// is vuln-free, so `grouped` stays empty and the builder must
    /// short-circuit to `None` rather than emit a statement-less document.
    #[test]
    fn all_applied_patches_vuln_free_returns_none() {
        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert("pkg:npm/a@1.0.0".to_string(), record("u1", vec![]));
        manifest
            .patches
            .insert("pkg:npm/b@2.0.0".to_string(), record("u2", vec![]));
        let doc = build_document(
            &manifest,
            &["pkg:npm/a@1.0.0".to_string(), "pkg:npm/b@2.0.0".to_string()],
            &opts(),
        );
        assert!(
            doc.is_none(),
            "no vuln records anywhere → None, not an empty doc"
        );
    }

    /// Order-independence: the `statements` payload is fully determined
    /// by the *logical* manifest content, NOT by `HashMap` iteration
    /// order. `build_is_deterministic_modulo_timestamps` only re-iterates
    /// the *same* manifest (so it sees the same order twice) — it proves
    /// purity, not order-independence. Here we build two manifests whose
    /// patches/vulns/cves are inserted in opposite orders and assert the
    /// stripped documents are byte-identical, pinning the sort-based
    /// determinism the transpose relies on.
    #[test]
    fn output_is_independent_of_manifest_insertion_order() {
        let strip = |mut d: Document| -> Document {
            d.timestamp = String::new();
            for s in d.statements.iter_mut() {
                s.timestamp = None;
            }
            d
        };

        // Manifest A: forward insertion order.
        let mut a = PatchManifest::new();
        a.patches.insert(
            "pkg:npm/aaa@1.0.0".to_string(),
            record("u-a", vec![("GHSA-shared", vec!["CVE-1", "CVE-2"])]),
        );
        a.patches.insert(
            "pkg:npm/zzz@9.0.0".to_string(),
            record(
                "u-z",
                vec![
                    ("GHSA-shared", vec!["CVE-3"]),
                    ("GHSA-only-z", vec!["CVE-9"]),
                ],
            ),
        );

        // Manifest B: same logical content, reversed insertion order
        // (and reversed cve order) to force a different iteration order.
        let mut b = PatchManifest::new();
        b.patches.insert(
            "pkg:npm/zzz@9.0.0".to_string(),
            record(
                "u-z",
                vec![
                    ("GHSA-only-z", vec!["CVE-9"]),
                    ("GHSA-shared", vec!["CVE-3"]),
                ],
            ),
        );
        b.patches.insert(
            "pkg:npm/aaa@1.0.0".to_string(),
            record("u-a", vec![("GHSA-shared", vec!["CVE-2", "CVE-1"])]),
        );

        let applied = vec![
            "pkg:npm/aaa@1.0.0".to_string(),
            "pkg:npm/zzz@9.0.0".to_string(),
        ];
        let da = strip(build_document(&a, &applied, &opts()).unwrap());
        let db = strip(build_document(&b, &applied, &opts()).unwrap());
        assert_eq!(da, db, "output must not depend on manifest insertion order");
    }

    /// Subcomponent IDs are sorted within a merged statement. Pin
    /// this so downstream tools can rely on stable diff output.
    #[test]
    fn merged_subcomponents_are_sorted_alphabetically() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/zzz@1.0.0".to_string(),
            record("u-z", vec![("GHSA-shared", vec![])]),
        );
        manifest.patches.insert(
            "pkg:npm/aaa@1.0.0".to_string(),
            record("u-a", vec![("GHSA-shared", vec![])]),
        );
        manifest.patches.insert(
            "pkg:npm/mmm@1.0.0".to_string(),
            record("u-m", vec![("GHSA-shared", vec![])]),
        );

        let doc = build_document(
            &manifest,
            &[
                "pkg:npm/zzz@1.0.0".to_string(),
                "pkg:npm/aaa@1.0.0".to_string(),
                "pkg:npm/mmm@1.0.0".to_string(),
            ],
            &opts(),
        )
        .unwrap();

        let subs = &doc.statements[0].products[0].subcomponents;
        assert_eq!(subs.len(), 3);
        assert_eq!(subs[0].id, "pkg:npm/aaa@1.0.0");
        assert_eq!(subs[1].id, "pkg:npm/mmm@1.0.0");
        assert_eq!(subs[2].id, "pkg:npm/zzz@1.0.0");
    }

    // ── Vendored-patch phrasing (`build_document_with_vendored`) ──

    /// A vendored PURL's impact statement carries the "(vendored)" suffix;
    /// status/justification stay identical to the non-vendored form.
    #[test]
    fn vendored_purl_gets_vendored_impact_phrasing() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:cargo/serde@1.0.0".to_string(),
            record("u-vend", vec![("GHSA-vvvv", vec!["CVE-2024-7"])]),
        );
        let applied = vec!["pkg:cargo/serde@1.0.0".to_string()];
        let doc = build_document_with_vendored(&manifest, &applied, &applied, &opts()).unwrap();
        let st = &doc.statements[0];
        assert_eq!(
            st.impact_statement.as_deref(),
            Some("Patched via Socket patch u-vend (vendored)")
        );
        // The vendored path must not perturb the pinned status/justification.
        assert_eq!(st.status, Status::NotAffected);
        assert_eq!(
            st.justification,
            Some(Justification::InlineMitigationsAlreadyExist)
        );
    }

    /// A redirected PURL's impact statement carries the "(redirected)"
    /// suffix; status/justification stay identical to the plain form.
    #[test]
    fn redirected_purl_gets_redirected_impact_phrasing() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/left-pad@1.3.0".to_string(),
            record("u-rdir", vec![("GHSA-rrrr", vec!["CVE-2024-8"])]),
        );
        let applied = vec!["pkg:npm/left-pad@1.3.0".to_string()];
        let doc =
            build_document_with_provenance(&manifest, &applied, &[], &applied, &opts()).unwrap();
        let st = &doc.statements[0];
        assert_eq!(
            st.impact_statement.as_deref(),
            Some("Patched via Socket patch u-rdir (redirected)")
        );
        assert_eq!(st.status, Status::NotAffected);
        assert_eq!(
            st.justification,
            Some(Justification::InlineMitigationsAlreadyExist)
        );
    }

    /// If a PURL is defensively present in BOTH the vendored and redirected
    /// sets, the vendored phrasing wins (they are disjoint in practice —
    /// `--redirect` conflicts with `--vendor`).
    #[test]
    fn vendored_takes_precedence_over_redirected() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:cargo/serde@1.0.0".to_string(),
            record("u-both", vec![("GHSA-both", vec!["CVE-2024-9"])]),
        );
        let applied = vec!["pkg:cargo/serde@1.0.0".to_string()];
        let doc =
            build_document_with_provenance(&manifest, &applied, &applied, &applied, &opts())
                .unwrap();
        assert_eq!(
            doc.statements[0].impact_statement.as_deref(),
            Some("Patched via Socket patch u-both (vendored)")
        );
    }

    /// `build_document` is exactly `build_document_with_vendored(.., &[], ..)`
    /// — no "(vendored)" phrasing without a vendored set.
    #[test]
    fn build_document_is_empty_vendored_wrapper() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record("u1", vec![("GHSA-aaaa", vec!["CVE-1"])]),
        );
        let applied = vec!["pkg:npm/x@1.0.0".to_string()];
        let strip = |mut d: Document| -> Document {
            d.timestamp = String::new();
            for s in d.statements.iter_mut() {
                s.timestamp = None;
            }
            d
        };
        let a = strip(build_document(&manifest, &applied, &opts()).unwrap());
        let b = strip(build_document_with_vendored(&manifest, &applied, &[], &opts()).unwrap());
        assert_eq!(a, b);
        assert!(!a.statements[0]
            .impact_statement
            .as_deref()
            .unwrap()
            .contains("(vendored)"));
    }

    /// Same patch UUID across a vendored and a non-vendored PURL sharing a
    /// GHSA: the two phrasings differ, so BOTH survive the dedup — the
    /// statement records that one attestation is vendored and one is not.
    #[test]
    fn same_uuid_vendored_and_non_vendored_keeps_both_phrasings() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record("shared-uuid", vec![("GHSA-shared", vec!["CVE-1"])]),
        );
        manifest.patches.insert(
            "pkg:npm/x@1.0.1".to_string(),
            record("shared-uuid", vec![("GHSA-shared", vec!["CVE-1"])]),
        );
        let applied = vec!["pkg:npm/x@1.0.0".to_string(), "pkg:npm/x@1.0.1".to_string()];
        let vendored = vec!["pkg:npm/x@1.0.1".to_string()];
        let doc = build_document_with_vendored(&manifest, &applied, &vendored, &opts()).unwrap();
        let imp = doc.statements[0].impact_statement.as_ref().unwrap();
        assert!(
            imp.contains("Patched via Socket patch shared-uuid (vendored)"),
            "vendored phrasing missing: {imp}"
        );
        assert!(
            imp.contains("Patched via Socket patch shared-uuid;")
                || imp.ends_with("Patched via Socket patch shared-uuid"),
            "plain phrasing missing: {imp}"
        );
        assert_eq!(
            imp.matches("shared-uuid").count(),
            2,
            "both forms kept: {imp}"
        );
    }

    /// Same UUID across two VENDORED PURLs sharing a GHSA: identical
    /// phrasing collapses to one mention (the vendored twin of
    /// `same_uuid_across_two_purls_deduped_in_impact_statement`).
    #[test]
    fn same_uuid_two_vendored_purls_deduped_in_impact_statement() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record("shared-uuid", vec![("GHSA-shared", vec!["CVE-1"])]),
        );
        manifest.patches.insert(
            "pkg:npm/x@1.0.1".to_string(),
            record("shared-uuid", vec![("GHSA-shared", vec!["CVE-1"])]),
        );
        let applied = vec!["pkg:npm/x@1.0.0".to_string(), "pkg:npm/x@1.0.1".to_string()];
        let doc = build_document_with_vendored(&manifest, &applied, &applied, &opts()).unwrap();
        let imp = doc.statements[0].impact_statement.as_ref().unwrap();
        assert_eq!(
            imp.matches("shared-uuid").count(),
            1,
            "duplicate vendored UUID must collapse: {imp}"
        );
        assert!(imp.contains("(vendored)"));
    }
}
