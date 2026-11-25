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
//!
//! A package the caller knows the build takes without its patch gets
//! `affected` statements ([`build_document_with`] with
//! [`Attested::affected`]): one per
//! vulnerability ID, of its own, after the `not_affected` one of the same
//! ID. Such statements are not merged, so that the action statement of
//! each is about one subcomponent.
//!
//! Each statement also names every one of its packages as a product of
//! its own, after the project. Trivy and Grype look a finding up by the
//! package's PURL and never match the project, so without these a
//! scanner suppresses nothing. A package is named by its PURL and, for a
//! gem built for a platform, by the forms those scanners report it under
//! ([`scanner_forms`]). A form that stands for packages with different
//! statuses for one vulnerability, under its ID or any alias (a patched
//! and an unpatched build of one gem, or a build whose patch the
//! document leaves out), is left out, so the scanner keeps reporting the
//! finding. That holds for a package's own PURL too.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::crawlers::Ecosystem;
use crate::manifest::schema::PatchManifest;
use crate::utils::purl::{percent_decode_purl_component, purl_qualifier, strip_purl_qualifiers};
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
/// `applied` is a list of PURLs that have been verified (a caller that
/// only declares them applied, as `--no-verify` does, says which with
/// [`build_document_marking_unverified`]). Manifest entries not in
/// `applied` are silently dropped — see the design note in
/// `vex::verify` for why a check that fails never emits `affected`.
///
/// PURLs in `vendored` (a subset of `applied`, from
/// `VerifyOutcome::vendored`) carry the impact-statement phrasing
/// "Patched via Socket patch `<uuid>` (vendored)" so the attestation
/// records that the evidence is the committed `.socket/vendor/`
/// artifact, not the installed tree. PURLs in `redirected` (wired to
/// Socket's hosted patches by hosted-mode `scan`) carry "(redirected)"
/// instead. The two sets are disjoint in practice (each PURL is attested
/// on exactly one basis); if a PURL somehow appears in both, `vendored`
/// wins. Status and justification are identical
/// across all three phrasings.
///
/// Returns `None` when no statements can be emitted (no applied
/// patches matched the manifest). The CLI converts `None` into a
/// non-zero exit code per the agreed contract.
pub fn build_document(
    manifest: &PatchManifest,
    applied: &[String],
    vendored: &[String],
    redirected: &[String],
    opts: &BuildOptions,
) -> Option<Document> {
    build_document_marking_unverified(manifest, applied, vendored, redirected, &[], opts)
}

/// What [`build_document_marking_unverified`] appends to the impact
/// statement part of a PURL nothing on disk was checked for. Appended
/// after the provenance marker, so the three marker strings stay intact.
pub const NOT_VERIFIED_SUFFIX: &str = "; not verified on disk";

/// [`build_document`], where the PURLs in `unverified` (a subset of
/// `applied`) were declared applied without any on-disk check
/// (`--no-verify`): their impact-statement part ends with
/// [`NOT_VERIFIED_SUFFIX`], so a reader of the document can tell a
/// statement that rests on hashed bytes from one that rests on the patch
/// records alone. With no such PURL the document is [`build_document`]'s,
/// byte for byte.
pub fn build_document_marking_unverified(
    manifest: &PatchManifest,
    applied: &[String],
    vendored: &[String],
    redirected: &[String],
    unverified: &[String],
    opts: &BuildOptions,
) -> Option<Document> {
    build_document_with(
        manifest,
        &Attested {
            applied,
            vendored,
            redirected,
            unverified,
            ..Attested::default()
        },
        opts,
    )
}

/// The PURLs a document attests, and on what basis each is attested.
#[derive(Debug, Clone, Copy, Default)]
pub struct Attested<'a> {
    /// Every attested PURL.
    pub applied: &'a [String],
    /// Attested from the committed vendor artifact ([`build_document`]).
    pub vendored: &'a [String],
    /// Attested from hosted wiring ([`build_document`]).
    pub redirected: &'a [String],
    /// Declared applied with nothing checked on disk
    /// ([`build_document_marking_unverified`]).
    pub unverified: &'a [String],
    /// Attested with nothing applied: no file of the patch is part of any
    /// installed build of the package
    /// ([`VerifyOutcome::code_not_present`](crate::vex::verify::VerifyOutcome::code_not_present)).
    pub code_not_present: &'a [String],
    /// PURLs whose patch the caller knows the build does not take, each
    /// with what to do about it. See [`build_document_with`].
    pub affected: &'a [(String, String)],
}

/// What the impact statement says of a PURL in
/// [`Attested::code_not_present`], before the patch's uuid.
pub const CODE_NOT_PRESENT_PREFIX: &str =
    "The code this vulnerability is in is not in the installed build of the package: no file of \
     Socket patch";

/// [`build_document_marking_unverified`], with two more kinds of PURL.
///
/// The PURLs in `attested.code_not_present` are not affected because the
/// code the patch changes is not in any installed build of the package,
/// with no patch applied to them. Their impact-statement part says so and
/// names the patch whose files were looked for. A statement all of whose
/// PURLs are of that kind carries the justification
/// `vulnerable_code_not_present`; any other keeps
/// `inline_mitigations_already_exist`, with one part per PURL saying which
/// is which.
///
/// `attested.affected` names the PURLs whose patch the caller knows the
/// build does not take, each with what to do about it. Every vulnerability
/// of such a PURL's record gets a statement of the PURL's own with the
/// status `affected`: the PURL is the one subcomponent of the product, and
/// the action statement is what the caller gave for it, so a reader knows
/// which package to act on. It has no justification and no impact
/// statement, which belong to `not_affected`.
///
/// A PURL is in `applied` or in `affected`, and `affected` wins for one
/// in both. A vulnerability that PURLs of both kinds share has the
/// `not_affected` statement of the patched ones first, then one
/// `affected` statement per PURL: a reader that keeps the last statement
/// of a document about a product and a vulnerability keeps one that says
/// `affected`. With neither kind of PURL the document is
/// [`build_document_marking_unverified`]'s, byte for byte.
pub fn build_document_with(
    manifest: &PatchManifest,
    attested: &Attested<'_>,
    opts: &BuildOptions,
) -> Option<Document> {
    fn set(purls: &[String]) -> HashSet<&str> {
        purls.iter().map(String::as_str).collect()
    }
    let timestamp = now_rfc3339();
    let applied_set = set(attested.applied);
    let vendored_set = set(attested.vendored);
    let redirected_set = set(attested.redirected);
    let unverified_set = set(attested.unverified);
    let code_not_present_set = set(attested.code_not_present);
    let actions: BTreeMap<&str, &str> = attested
        .affected
        .iter()
        .map(|(purl, action)| (purl.as_str(), action.as_str()))
        .collect();

    // (vuln-id, affected PURL) -> (aliases, statement parts, subcomponent
    // PURLs): the patched PURLs of an ID share a group, and each affected
    // one has its own.
    // BTreeMap/BTreeSet keep every output field sorted, which keeps
    // statement order deterministic and helps reproducibility for
    // downstream diffs.
    let mut grouped: BTreeMap<(String, Option<&str>), VulnGroup> = BTreeMap::new();

    for (purl, record) in &manifest.patches {
        let action = actions.get(purl.as_str());
        if action.is_none() && !applied_set.contains(purl.as_str()) {
            continue;
        }
        // A basis that rests on the patch's own artifact (vendored,
        // redirected) or on no check at all comes first: nothing was
        // looked for in an installed build then.
        let code_not_present = code_not_present_set.contains(purl.as_str())
            && !vendored_set.contains(purl.as_str())
            && !redirected_set.contains(purl.as_str())
            && !unverified_set.contains(purl.as_str());
        for (vuln_id, info) in &record.vulnerabilities {
            let alone = action.map(|_| purl.as_str());
            let entry = grouped.entry((vuln_id.clone(), alone)).or_default();
            entry.aliases.extend(info.cves.iter().cloned());
            entry.subcomponents.insert(purl.clone());
            if let Some(action) = action {
                entry.parts.insert(action.to_string());
                continue;
            }
            let mut part = if code_not_present {
                format!("{CODE_NOT_PRESENT_PREFIX} {} is part of it", record.uuid)
            } else if vendored_set.contains(purl.as_str()) {
                format!("Patched via Socket patch {} (vendored)", record.uuid)
            } else if redirected_set.contains(purl.as_str()) {
                format!("Patched via Socket patch {} (redirected)", record.uuid)
            } else {
                format!("Patched via Socket patch {}", record.uuid)
            };
            if unverified_set.contains(purl.as_str()) {
                part.push_str(NOT_VERIFIED_SUFFIX);
            }
            entry.patched |= !code_not_present;
            entry.parts.insert(part);
        }
    }

    if grouped.is_empty() {
        return None;
    }

    // (vulnerability ID or alias, package form) -> the statuses the form
    // stands for: `true` for unpatched, `false` for `not_affected`.
    // Scanners match a statement by its name or any alias, so a form is
    // judged under each of them.
    let mut form_statuses: HashMap<(String, String), BTreeSet<bool>> = HashMap::new();
    let mut mark = |ids: &[&str], purl: &str, unpatched: bool| {
        for id in ids {
            for form in package_forms(purl) {
                form_statuses
                    .entry((id.to_string(), form))
                    .or_default()
                    .insert(unpatched);
            }
        }
    };
    for ((vuln_id, affected), group) in &grouped {
        let ids = vuln_ids(vuln_id, &group.aliases);
        for purl in &group.subcomponents {
            mark(&ids, purl, affected.is_some());
        }
    }
    // A record the document leaves out (its check failed, or nothing
    // attested it) is a copy that may be unpatched.
    for (purl, record) in &manifest.patches {
        if applied_set.contains(purl.as_str()) || actions.contains_key(purl.as_str()) {
            continue;
        }
        for (vuln_id, info) in &record.vulnerabilities {
            mark(&vuln_ids(vuln_id, &info.cves), purl, true);
        }
    }
    let package_products: Vec<Vec<Product>> = grouped
        .iter()
        .map(|((vuln_id, _), group)| {
            let ids = vuln_ids(vuln_id, &group.aliases);
            let forms: BTreeSet<String> = group
                .subcomponents
                .iter()
                .flat_map(|purl| package_forms(purl))
                .filter(|form| {
                    *form != opts.product_id
                        && ids.iter().all(|id| {
                            form_statuses
                                .get(&(id.to_string(), form.clone()))
                                .is_some_and(|statuses| statuses.len() == 1)
                        })
                })
                .collect();
            forms
                .into_iter()
                .map(|id| Product {
                    id,
                    identifiers: None,
                    hashes: None,
                    subcomponents: Vec::new(),
                })
                .collect()
        })
        .collect();

    let mut statements = Vec::with_capacity(grouped.len());
    for (((vuln_id, affected), group), packages) in grouped.into_iter().zip(package_products) {
        let subcomponents = group
            .subcomponents
            .into_iter()
            .map(|id| Subcomponent {
                id,
                identifiers: None,
                hashes: None,
            })
            .collect();

        // The empty-parts branch is unreachable from the public
        // API: the loop above inserts one entry per applied
        // (purl, vuln) pair, so every group present in `grouped`
        // has ≥1 entry. The defensive `None` arm stays in case a
        // future refactor decouples grouping from impact tracking.
        let words = if group.parts.is_empty() {
            None
        } else {
            Some(group.parts.into_iter().collect::<Vec<_>>().join("; "))
        };
        let (status, justification, impact_statement, action_statement) = if affected.is_some() {
            (Status::Affected, None, None, words)
        } else {
            // A patch in place for any subcomponent is a mitigation; with
            // none, the statement rests on the code not being there.
            let justification = if group.patched {
                Justification::InlineMitigationsAlreadyExist
            } else {
                Justification::VulnerableCodeNotPresent
            };
            (Status::NotAffected, Some(justification), words, None)
        };

        statements.push(Statement {
            id: None,
            vulnerability: Vulnerability {
                name: vuln_id,
                aliases: group.aliases.into_iter().collect(),
            },
            timestamp: Some(timestamp.clone()),
            last_updated: None,
            products: std::iter::once(Product {
                id: opts.product_id.clone(),
                identifiers: None,
                hashes: None,
                subcomponents,
            })
            .chain(packages)
            .collect(),
            status,
            supplier: None,
            justification,
            impact_statement,
            action_statement,
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

/// A vulnerability's ID followed by its aliases.
fn vuln_ids<'a>(id: &'a str, aliases: impl IntoIterator<Item = &'a String>) -> Vec<&'a str> {
    std::iter::once(id)
        .chain(aliases.into_iter().map(String::as_str))
        .collect()
}

/// `purl` and the forms scanners report the same package under.
fn package_forms(purl: &str) -> impl Iterator<Item = String> {
    std::iter::once(purl.to_string()).chain(scanner_forms(purl))
}

/// The other forms Trivy, Grype and Syft report a gem built for a
/// platform under: Trivy without the platform, and Grype and Syft as
/// `name@version-platform` (no suffix for `ruby`). Other ecosystems'
/// qualifiers name a different artifact (a Maven classifier, a PyPI
/// file), so they get no extra form.
fn scanner_forms(purl: &str) -> Vec<String> {
    if Ecosystem::from_purl(purl) != Some(Ecosystem::Gem) {
        return Vec::new();
    }
    let Some(platform) = purl_qualifier(purl, "platform") else {
        return Vec::new();
    };
    let base = strip_purl_qualifiers(purl);
    if !base.contains('@') {
        return Vec::new();
    }
    let platform = percent_decode_purl_component(platform);
    let mut forms = vec![base.to_string()];
    if !platform.is_empty() && platform != "ruby" {
        forms.push(format!("{base}-{platform}"));
    }
    forms
}

#[derive(Default)]
struct VulnGroup {
    aliases: BTreeSet<String>,
    subcomponents: BTreeSet<String>,
    /// What each PURL adds to the impact statement of a `not_affected`
    /// statement, or the action statement of an `affected` one.
    parts: BTreeSet<String>,
    /// Some subcomponent is attested because a patch is in place.
    patched: bool,
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

    /// [`build_document`] with no vendored/redirected PURLs and the
    /// default [`opts`].
    fn build_plain(manifest: &PatchManifest, applied: &[String]) -> Option<Document> {
        build_document(manifest, applied, &[], &[], &opts())
    }

    /// [`build_document_with`] with `applied` and `affected` only.
    fn build_affected(
        manifest: &PatchManifest,
        applied: &[String],
        affected: &[(String, String)],
    ) -> Option<Document> {
        build_document_with(
            manifest,
            &Attested {
                applied,
                affected,
                ..Attested::default()
            },
            &opts(),
        )
    }

    #[test]
    fn empty_applied_returns_none() {
        let manifest = PatchManifest::new();
        assert!(build_plain(&manifest, &[]).is_none());
    }

    #[test]
    fn unapplied_patch_is_skipped() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/lodash@4.0.0".to_string(),
            record("u1", vec![("GHSA-aaaa", vec!["CVE-2024-1"])]),
        );
        // applied is empty → no statements → None.
        assert!(build_plain(&manifest, &[]).is_none());
    }

    #[test]
    fn single_patch_single_vuln_produces_one_statement() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/lodash@4.0.0".to_string(),
            record("u1", vec![("GHSA-aaaa", vec!["CVE-2024-1"])]),
        );
        let doc = build_plain(&manifest, &["pkg:npm/lodash@4.0.0".to_string()]).unwrap();

        assert_eq!(doc.statements.len(), 1);
        let st = &doc.statements[0];
        assert_eq!(st.vulnerability.name, "GHSA-aaaa");
        assert_eq!(st.vulnerability.aliases, vec!["CVE-2024-1".to_string()]);
        assert_eq!(st.status, Status::NotAffected);
        assert_eq!(
            st.justification,
            Some(Justification::InlineMitigationsAlreadyExist)
        );
        assert_eq!(st.products.len(), 2);
        assert_eq!(st.products[0].id, "pkg:npm/app@1.0.0");
        assert_eq!(st.products[0].subcomponents.len(), 1);
        assert_eq!(st.products[0].subcomponents[0].id, "pkg:npm/lodash@4.0.0");
        assert_eq!(st.products[1].id, "pkg:npm/lodash@4.0.0");
        assert!(st.products[1].subcomponents.is_empty());
        assert!(st.impact_statement.as_ref().unwrap().contains("u1"));
    }

    fn product_ids(st: &Statement) -> Vec<&str> {
        st.products.iter().map(|p| p.id.as_str()).collect()
    }

    #[test]
    fn native_gem_is_named_in_every_scanner_form() {
        let purl = "pkg:gem/nokogiri@1.13.9?platform=x86_64-linux";
        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert(purl.to_string(), record("u1", vec![("GHSA-aaaa", vec![])]));
        let doc = build_plain(&manifest, &[purl.to_string()]).unwrap();
        assert_eq!(
            product_ids(&doc.statements[0]),
            vec![
                "pkg:npm/app@1.0.0",
                "pkg:gem/nokogiri@1.13.9",
                "pkg:gem/nokogiri@1.13.9-x86_64-linux",
                purl,
            ]
        );
    }

    #[test]
    fn ruby_platform_gem_gets_no_platform_suffix() {
        let purl = "pkg:gem/nokogiri@1.13.9?platform=ruby";
        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert(purl.to_string(), record("u1", vec![("GHSA-aaaa", vec![])]));
        let doc = build_plain(&manifest, &[purl.to_string()]).unwrap();
        assert_eq!(
            product_ids(&doc.statements[0]),
            vec!["pkg:npm/app@1.0.0", "pkg:gem/nokogiri@1.13.9", purl]
        );
    }

    #[test]
    fn shared_form_is_left_out_when_one_build_is_affected() {
        let linux = "pkg:gem/nokogiri@1.13.9?platform=x86_64-linux";
        let darwin = "pkg:gem/nokogiri@1.13.9?platform=arm64-darwin";
        let mut manifest = PatchManifest::new();
        for purl in [linux, darwin] {
            manifest
                .patches
                .insert(purl.to_string(), record("u1", vec![("GHSA-aaaa", vec![])]));
        }
        let affected = vec![(darwin.to_string(), "Rebuild it.".to_string())];
        let doc = build_affected(&manifest, &[linux.to_string()], &affected).unwrap();
        assert_eq!(doc.statements.len(), 2);
        for st in &doc.statements {
            assert!(
                !product_ids(st).contains(&"pkg:gem/nokogiri@1.13.9"),
                "{:?} must not name the form both builds share",
                st.status
            );
        }
        let patched = doc
            .statements
            .iter()
            .find(|st| st.status == Status::NotAffected)
            .unwrap();
        assert_eq!(
            product_ids(patched),
            vec![
                "pkg:npm/app@1.0.0",
                "pkg:gem/nokogiri@1.13.9-x86_64-linux",
                linux,
            ]
        );
    }

    #[test]
    fn shared_form_is_kept_when_every_build_is_patched() {
        let linux = "pkg:gem/nokogiri@1.13.9?platform=x86_64-linux";
        let darwin = "pkg:gem/nokogiri@1.13.9?platform=arm64-darwin";
        let mut manifest = PatchManifest::new();
        for purl in [linux, darwin] {
            manifest
                .patches
                .insert(purl.to_string(), record("u1", vec![("GHSA-aaaa", vec![])]));
        }
        let doc = build_plain(&manifest, &[linux.to_string(), darwin.to_string()]).unwrap();
        assert_eq!(doc.statements.len(), 1);
        assert!(product_ids(&doc.statements[0]).contains(&"pkg:gem/nokogiri@1.13.9"));
    }

    #[test]
    fn shared_form_is_left_out_when_another_build_is_not_attested() {
        // The darwin build's check failed, so it is not in `applied`: the
        // document says nothing of it, and Trivy would read the shared
        // form as covering it.
        let linux = "pkg:gem/nokogiri@1.13.9?platform=x86_64-linux";
        let darwin = "pkg:gem/nokogiri@1.13.9?platform=arm64-darwin";
        let mut manifest = PatchManifest::new();
        for purl in [linux, darwin] {
            manifest
                .patches
                .insert(purl.to_string(), record("u1", vec![("GHSA-aaaa", vec![])]));
        }
        let doc = build_plain(&manifest, &[linux.to_string()]).unwrap();
        assert_eq!(
            product_ids(&doc.statements[0]),
            vec![
                "pkg:npm/app@1.0.0",
                "pkg:gem/nokogiri@1.13.9-x86_64-linux",
                linux,
            ]
        );
    }

    #[test]
    fn shared_form_is_judged_under_every_alias() {
        // One CVE, recorded under a different GHSA for each build.
        let linux = "pkg:gem/nokogiri@1.13.9?platform=x86_64-linux";
        let darwin = "pkg:gem/nokogiri@1.13.9?platform=arm64-darwin";
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            linux.to_string(),
            record("u1", vec![("GHSA-aaaa", vec!["CVE-2024-1"])]),
        );
        manifest.patches.insert(
            darwin.to_string(),
            record("u2", vec![("GHSA-bbbb", vec!["CVE-2024-1"])]),
        );
        let affected = vec![(darwin.to_string(), "Rebuild it.".to_string())];
        let doc = build_affected(&manifest, &[linux.to_string()], &affected).unwrap();
        for st in &doc.statements {
            assert!(
                !product_ids(st).contains(&"pkg:gem/nokogiri@1.13.9"),
                "{} must not name the form both builds share",
                st.vulnerability.name
            );
        }
    }

    #[test]
    fn percent_encoded_platform_is_decoded() {
        let purl = "pkg:gem/ffi@1.17.0?platform=x64%2Dmingw-ucrt";
        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert(purl.to_string(), record("u1", vec![("GHSA-aaaa", vec![])]));
        let doc = build_plain(&manifest, &[purl.to_string()]).unwrap();
        assert!(product_ids(&doc.statements[0]).contains(&"pkg:gem/ffi@1.17.0-x64-mingw-ucrt"));
    }

    #[test]
    fn other_qualifiers_get_no_extra_form() {
        let purl =
            "pkg:maven/io.netty/netty-transport-native-epoll@4.1.100.Final?classifier=linux-x86_64";
        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert(purl.to_string(), record("u1", vec![("GHSA-aaaa", vec![])]));
        let doc = build_plain(&manifest, &[purl.to_string()]).unwrap();
        assert_eq!(
            product_ids(&doc.statements[0]),
            vec!["pkg:npm/app@1.0.0", purl]
        );
    }

    #[test]
    fn product_override_naming_the_package_is_not_repeated() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/lodash@4.0.0".to_string(),
            record("u1", vec![("GHSA-aaaa", vec![])]),
        );
        let mut o = opts();
        o.product_id = "pkg:npm/lodash@4.0.0".to_string();
        let doc = build_document(
            &manifest,
            &["pkg:npm/lodash@4.0.0".to_string()],
            &[],
            &[],
            &o,
        )
        .unwrap();
        assert_eq!(
            product_ids(&doc.statements[0]),
            vec!["pkg:npm/lodash@4.0.0"]
        );
    }

    #[test]
    fn cves_flatten_into_aliases() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record("u1", vec![("GHSA-bbbb", vec!["CVE-2024-2", "CVE-2024-3"])]),
        );
        let doc = build_plain(&manifest, &["pkg:npm/x@1.0.0".to_string()]).unwrap();
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

        let doc = build_plain(
            &manifest,
            &["pkg:npm/x@1.0.0".to_string(), "pkg:npm/y@2.0.0".to_string()],
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

        let doc = build_plain(&manifest, &["pkg:npm/x@1.0.0".to_string()]).unwrap();
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
        let doc = build_plain(&manifest, &["pkg:npm/x@1.0.0".to_string()]).unwrap();
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

        let doc = build_plain(
            &manifest,
            &[
                "pkg:npm/in-manifest@1.0.0".to_string(),
                "pkg:npm/ghost@9.9.9".to_string(), // not in manifest
            ],
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

        let doc = build_plain(
            &manifest,
            &[
                "pkg:npm/with-vuln@1.0.0".to_string(),
                "pkg:npm/no-vuln@2.0.0".to_string(),
            ],
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
        let doc = build_plain(&manifest, &["pkg:npm/x@1.0.0".to_string()]).unwrap();
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

        let doc = build_plain(
            &manifest,
            &["pkg:npm/x@1.0.0".to_string(), "pkg:npm/y@2.0.0".to_string()],
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

        let doc = build_plain(
            &manifest,
            &["pkg:npm/x@1.0.0".to_string(), "pkg:npm/x@1.0.1".to_string()],
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
    /// the JSON output omits the key.
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
        let doc =
            build_document(&manifest, &["pkg:npm/x@1.0.0".to_string()], &[], &[], &opts).unwrap();
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
        let doc =
            build_document(&manifest, &["pkg:npm/x@1.0.0".to_string()], &[], &[], &opts).unwrap();
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

        let a = build_plain(&manifest, &applied).unwrap();
        let b = build_plain(&manifest, &applied).unwrap();

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
        let doc = build_plain(&manifest, &["pkg:npm/x@1.0.0".to_string()]).unwrap();
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
        let doc = build_plain(
            &manifest,
            &["pkg:npm/a@1.0.0".to_string(), "pkg:npm/b@2.0.0".to_string()],
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
        let da = strip(build_plain(&a, &applied).unwrap());
        let db = strip(build_plain(&b, &applied).unwrap());
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

        let doc = build_plain(
            &manifest,
            &[
                "pkg:npm/zzz@1.0.0".to_string(),
                "pkg:npm/aaa@1.0.0".to_string(),
                "pkg:npm/mmm@1.0.0".to_string(),
            ],
        )
        .unwrap();

        let subs = &doc.statements[0].products[0].subcomponents;
        assert_eq!(subs.len(), 3);
        assert_eq!(subs[0].id, "pkg:npm/aaa@1.0.0");
        assert_eq!(subs[1].id, "pkg:npm/mmm@1.0.0");
        assert_eq!(subs[2].id, "pkg:npm/zzz@1.0.0");
    }

    // ── Vendored/redirected-patch phrasing ────────────────────────

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
        let doc = build_document(&manifest, &applied, &applied, &[], &opts()).unwrap();
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
        let doc = build_document(&manifest, &applied, &[], &applied, &opts()).unwrap();
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
    /// each PURL is attested on one basis).
    #[test]
    fn vendored_takes_precedence_over_redirected() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:cargo/serde@1.0.0".to_string(),
            record("u-both", vec![("GHSA-both", vec!["CVE-2024-9"])]),
        );
        let applied = vec!["pkg:cargo/serde@1.0.0".to_string()];
        let doc = build_document(&manifest, &applied, &applied, &applied, &opts()).unwrap();
        assert_eq!(
            doc.statements[0].impact_statement.as_deref(),
            Some("Patched via Socket patch u-both (vendored)")
        );
    }

    /// Empty `vendored`/`redirected` sets → the plain phrasing, with
    /// no "(vendored)" or "(redirected)" suffix.
    #[test]
    fn empty_provenance_sets_produce_plain_phrasing() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record("u1", vec![("GHSA-aaaa", vec!["CVE-1"])]),
        );
        let applied = vec!["pkg:npm/x@1.0.0".to_string()];
        let doc = build_document(&manifest, &applied, &[], &[], &opts()).unwrap();
        assert_eq!(
            doc.statements[0].impact_statement.as_deref(),
            Some("Patched via Socket patch u1")
        );
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
        let doc = build_document(&manifest, &applied, &vendored, &[], &opts()).unwrap();
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
        let doc = build_document(&manifest, &applied, &applied, &[], &opts()).unwrap();
        let imp = doc.statements[0].impact_statement.as_ref().unwrap();
        assert_eq!(
            imp.matches("shared-uuid").count(),
            1,
            "duplicate vendored UUID must collapse: {imp}"
        );
        assert!(imp.contains("(vendored)"));
    }

    /// A PURL declared applied with nothing checked on disk says so after
    /// its provenance marker, per part: a statement mixing a hashed patch
    /// and an unverified one marks only the latter, and the three marker
    /// strings stay intact.
    #[test]
    fn unverified_purls_are_marked_after_their_provenance_marker() {
        let mut manifest = PatchManifest::new();
        for (purl, uuid) in [
            ("pkg:npm/agent@1.0.0", "u-agent"),
            ("pkg:npm/vend@1.0.0", "u-vend"),
            ("pkg:npm/host@1.0.0", "u-host"),
            ("pkg:npm/hashed@1.0.0", "u-hashed"),
        ] {
            manifest.patches.insert(
                purl.to_string(),
                record(uuid, vec![("GHSA-shared", vec!["CVE-1"])]),
            );
        }
        let applied: Vec<String> = manifest.patches.keys().cloned().collect();
        let vendored = vec!["pkg:npm/vend@1.0.0".to_string()];
        let redirected = vec!["pkg:npm/host@1.0.0".to_string()];
        let unverified: Vec<String> = applied
            .iter()
            .filter(|purl| *purl != "pkg:npm/hashed@1.0.0")
            .cloned()
            .collect();
        let doc = build_document_marking_unverified(
            &manifest,
            &applied,
            &vendored,
            &redirected,
            &unverified,
            &opts(),
        )
        .unwrap();
        assert_eq!(
            doc.statements[0].impact_statement.as_deref(),
            Some(
                "Patched via Socket patch u-agent; not verified on disk; \
                 Patched via Socket patch u-hashed; \
                 Patched via Socket patch u-host (redirected); not verified on disk; \
                 Patched via Socket patch u-vend (vendored); not verified on disk"
            )
        );
    }

    /// With nothing unverified the marking builder is [`build_document`]:
    /// the default path's document does not change by a byte.
    #[test]
    fn marking_nothing_unverified_changes_nothing() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record("u1", vec![("GHSA-x", vec!["CVE-1"])]),
        );
        let applied = vec!["pkg:npm/x@1.0.0".to_string()];
        let untimed = |doc: Option<Document>| {
            let mut v = serde_json::to_value(doc.unwrap()).unwrap();
            v["timestamp"] = serde_json::Value::Null;
            v["statements"][0]["timestamp"] = serde_json::Value::Null;
            serde_json::to_string(&v).unwrap()
        };
        assert_eq!(
            untimed(build_document(&manifest, &applied, &applied, &[], &opts())),
            untimed(build_document_marking_unverified(
                &manifest,
                &applied,
                &applied,
                &[],
                &[],
                &opts()
            ))
        );
    }

    /// A package attested because no file of its patch is part of any
    /// installed build is not a patched package: the statement says that
    /// the vulnerable code is not present, names the patch whose files
    /// were looked for, and never says "Patched via".
    #[test]
    fn code_not_present_is_stated_as_such() {
        let mut manifest = PatchManifest::new();
        let purl = "pkg:gem/nokogiri@1.18.10?platform=ruby".to_string();
        manifest.patches.insert(
            purl.clone(),
            record("u-c", vec![("GHSA-cccc", vec!["CVE-2026-3"])]),
        );
        let applied = vec![purl.clone()];
        let doc = build_document_with(
            &manifest,
            &Attested {
                applied: &applied,
                code_not_present: &applied,
                ..Attested::default()
            },
            &opts(),
        )
        .unwrap();
        assert_eq!(doc.statements.len(), 1);
        let st = &doc.statements[0];
        assert_eq!(st.status, Status::NotAffected);
        assert_eq!(
            st.justification,
            Some(Justification::VulnerableCodeNotPresent)
        );
        let impact = st.impact_statement.as_deref().unwrap();
        assert_eq!(
            impact,
            "The code this vulnerability is in is not in the installed build of the package: \
             no file of Socket patch u-c is part of it"
        );
        assert!(!impact.contains("Patched via"), "{impact}");
        assert_eq!(st.products[0].subcomponents[0].id, purl);

        // Without the mark the document is the usual one, byte for byte.
        let untimed = |doc: Option<Document>| {
            let mut doc = doc.unwrap();
            doc.timestamp = String::new();
            for st in &mut doc.statements {
                st.timestamp = None;
            }
            serde_json::to_string(&doc).unwrap()
        };
        assert_eq!(
            untimed(build_document_with(
                &manifest,
                &Attested {
                    applied: &applied,
                    ..Attested::default()
                },
                &opts()
            )),
            untimed(build_document(&manifest, &applied, &[], &[], &opts()))
        );
    }

    /// One statement covers every package of a vulnerability. When one of
    /// them is patched, a mitigation is in place and the justification
    /// says so; the impact statement still says of each package what is
    /// true of it. A basis that rests on the patch's own artifact
    /// (vendored, redirected) or on no check keeps its own wording.
    #[test]
    fn code_not_present_beside_a_patched_package_keeps_the_mitigation_justification() {
        let mut manifest = PatchManifest::new();
        let absent = "pkg:gem/nokogiri@1.18.10?platform=ruby".to_string();
        let patched = "pkg:gem/other@1.0.0".to_string();
        manifest
            .patches
            .insert(absent.clone(), record("u-c", vec![("GHSA-cccc", vec![])]));
        manifest
            .patches
            .insert(patched.clone(), record("u-p", vec![("GHSA-cccc", vec![])]));
        let applied = vec![absent.clone(), patched.clone()];
        let not_present = vec![absent.clone()];
        let doc = build_document_with(
            &manifest,
            &Attested {
                applied: &applied,
                code_not_present: &not_present,
                ..Attested::default()
            },
            &opts(),
        )
        .unwrap();
        assert_eq!(doc.statements.len(), 1);
        let st = &doc.statements[0];
        assert_eq!(
            st.justification,
            Some(Justification::InlineMitigationsAlreadyExist)
        );
        let impact = st.impact_statement.as_deref().unwrap();
        assert!(impact.contains("Patched via Socket patch u-p"), "{impact}");
        assert!(
            impact.contains("no file of Socket patch u-c is part of it"),
            "{impact}"
        );
        assert!(!impact.contains("Patched via Socket patch u-c"), "{impact}");

        for (vendored, redirected, unverified, wording) in [
            (
                &not_present[..],
                &[][..],
                &[][..],
                "Patched via Socket patch u-c (vendored)",
            ),
            (
                &[][..],
                &not_present[..],
                &[][..],
                "Patched via Socket patch u-c (redirected)",
            ),
            (
                &[][..],
                &[][..],
                &not_present[..],
                "Patched via Socket patch u-c; not verified",
            ),
        ] {
            let doc = build_document_with(
                &manifest,
                &Attested {
                    applied: &not_present,
                    vendored,
                    redirected,
                    unverified,
                    code_not_present: &not_present,
                    ..Attested::default()
                },
                &opts(),
            )
            .unwrap();
            let st = &doc.statements[0];
            assert_eq!(
                st.justification,
                Some(Justification::InlineMitigationsAlreadyExist),
                "{wording}"
            );
            assert!(
                st.impact_statement.as_deref().unwrap().contains(wording),
                "{:?}",
                st.impact_statement
            );
        }
    }

    /// A PURL the build takes without its patch is attested as affected:
    /// each vulnerability of its record gets a statement that names the
    /// PURL under the product as a `not_affected` statement does, and
    /// tells in its action statement what to do. It carries no
    /// justification and no impact statement. A document of such
    /// statements alone is a document.
    #[test]
    fn an_affected_purl_gets_an_affected_statement_per_vulnerability() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record(
                "u1",
                vec![("GHSA-aaaa", vec!["CVE-1"]), ("GHSA-bbbb", vec![])],
            ),
        );
        let affected = [("pkg:npm/x@1.0.0".to_string(), "Pin it.".to_string())];
        let doc = build_affected(&manifest, &[], &affected).unwrap();
        let said: Vec<_> = (doc.statements.iter())
            .map(|st| (st.vulnerability.name.as_str(), &st.vulnerability.aliases))
            .collect();
        let cve = vec!["CVE-1".to_string()];
        assert_eq!(said, [("GHSA-aaaa", &cve), ("GHSA-bbbb", &vec![])]);
        let patched = build_plain(&manifest, &["pkg:npm/x@1.0.0".to_string()]).unwrap();
        for (st, not_affected) in doc.statements.iter().zip(&patched.statements) {
            assert_eq!(st.status, Status::Affected);
            assert_eq!(st.action_statement.as_deref(), Some("Pin it."));
            assert_eq!((st.justification, &st.impact_statement), (None, &None));
            assert_eq!(st.products, not_affected.products);
            assert_eq!(st.timestamp.as_deref(), Some(doc.timestamp.as_str()));
        }
    }

    /// A vulnerability that a patched PURL and affected ones share has the
    /// `not_affected` statement of the patched one first, then an
    /// `affected` statement for each of the others, with that PURL alone
    /// and its own action, also where two share a patch and so the words.
    /// A PURL in both sets is affected, and one whose record names no
    /// vulnerability gets no statement.
    #[test]
    fn each_affected_purl_of_a_vulnerability_has_a_statement_of_its_own() {
        let mut manifest = PatchManifest::new();
        for (purl, uuid, vulns) in [
            ("pkg:npm/built@1.0.0", "u-built", vec!["GHSA-shared"]),
            ("pkg:npm/lost@1.0.0", "u-lost", vec!["GHSA-shared"]),
            ("pkg:npm/lost@2.0.0", "u-lost", vec!["GHSA-shared"]),
            (
                "pkg:pypi/gone@3.0",
                "u-gone",
                vec!["GHSA-shared", "GHSA-own"],
            ),
            ("pkg:npm/silent@1.0.0", "u-silent", vec![]),
        ] {
            let vulns = vulns.into_iter().map(|id| (id, vec!["CVE-1"])).collect();
            manifest
                .patches
                .insert(purl.to_string(), record(uuid, vulns));
        }
        let applied = [
            "pkg:npm/built@1.0.0".to_string(),
            "pkg:npm/lost@1.0.0".to_string(),
        ];
        let affected = [
            ("pkg:npm/lost@1.0.0", "Pin u-lost."),
            ("pkg:npm/lost@2.0.0", "Pin u-lost."),
            ("pkg:pypi/gone@3.0", "Revert u-gone."),
            ("pkg:npm/silent@1.0.0", "Pin u-silent."),
        ]
        .map(|(purl, action)| (purl.to_string(), action.to_string()));
        let doc = build_affected(&manifest, &applied, &affected).unwrap();
        let said: Vec<_> = (doc.statements.iter())
            .map(|st| {
                let subs = &st.products[0].subcomponents;
                let subs: Vec<&str> = subs.iter().map(|sub| sub.id.as_str()).collect();
                let words = st
                    .impact_statement
                    .as_deref()
                    .or(st.action_statement.as_deref());
                (st.vulnerability.name.as_str(), st.status, subs, words)
            })
            .collect();
        let affected_by = |id, purl, action| (id, Status::Affected, vec![purl], Some(action));
        assert_eq!(
            said,
            [
                affected_by("GHSA-own", "pkg:pypi/gone@3.0", "Revert u-gone."),
                (
                    "GHSA-shared",
                    Status::NotAffected,
                    vec!["pkg:npm/built@1.0.0"],
                    Some("Patched via Socket patch u-built")
                ),
                affected_by("GHSA-shared", "pkg:npm/lost@1.0.0", "Pin u-lost."),
                affected_by("GHSA-shared", "pkg:npm/lost@2.0.0", "Pin u-lost."),
                affected_by("GHSA-shared", "pkg:pypi/gone@3.0", "Revert u-gone."),
            ]
        );
        let silent = [affected[3].clone()];
        assert!(build_affected(&manifest, &[], &silent).is_none());
    }
}
