//! Maven vendor backend: a committed maven2-layout repository plus a surgical
//! `<repository>` insert into the project's `pom.xml` pointing every resolve of
//! the patched GAV at a rebuilt, patched `.jar` served from the tree.
//!
//! Mechanism (verified against Apache Maven inside the docker capstone):
//!
//! * artifact — the uuid dir IS a maven2 *repository root*. Maven's standard
//!   layout is `<groupId-as-path>/<artifactId>/<version>/<a>-<v>.jar` (+ the
//!   companion `<a>-<v>.pom`), so laying the files at
//!   `.socket/vendor/maven/<uuid>/<g>/<a>/<v>/…` makes the uuid dir a fully
//!   valid `file://` repository with no index needed. The `.jar` is rebuilt by
//!   extracting the cached `~/.m2` jar, force-applying the patch, and re-zipping
//!   deterministically (so a re-run never churns the committed bytes) — the
//!   twin of the NuGet feed's `.nupkg` rebuild.
//!
//! * pom — the vendored `<a>-<v>.pom` MUST be the REAL upstream pom (copied
//!   verbatim from `~/.m2`, or downloaded from the maven2 registry). Maven reads
//!   it to discover the artifact's TRANSITIVE dependencies; a hand-authored
//!   minimal pom would silently drop them and break the consumer's build. When
//!   neither source can supply it we refuse (`vendor_maven_pom_unavailable`)
//!   rather than fabricate one.
//!
//! * checksums — each committed file carries a `<file>.sha1` sidecar (the hex
//!   sha1 of its bytes). Our injected `<repository>` sets
//!   `checksumPolicy=fail`, so Maven fetches the sidecar and hard-fails the
//!   resolve if the jar/pom bytes don't match it (a tampered jar → checksum
//!   failure). sha1 is the checksum Maven validates first; an `.md5` twin is
//!   not written (it would need a new workspace dependency and Maven treats
//!   sha1 as authoritative — the capstone proves `checksumPolicy=fail` is
//!   fully enforced by the sha1 sidecar alone).
//!
//! * `pom.xml` — a single `<repository>` is inserted:
//!   `id=socket-patch-vendor-<uuid>`,
//!   `url=file://${project.basedir}/.socket/vendor/maven/<uuid>`,
//!   `checksumPolicy=fail`, `<snapshots><enabled>false`. `${project.basedir}`
//!   interpolates to the pom's own dir, so the file:// url resolves relative to
//!   the committed tree on any checkout.
//!
//! Refusals (fail-closed, before any write):
//! * a root pom declaring `<modules>` (an aggregator) —
//!   `vendor_maven_multimodule_unsupported`: `${project.basedir}` would
//!   interpolate to each SUBMODULE's dir, not the root, so the file:// url would
//!   point at the wrong place per module.
//! * a gradle-only project (a `build.gradle*` but no `pom.xml`) —
//!   `vendor_gradle_unsupported`: there is no `<repositories>` block to wire and
//!   Gradle ignores it.
//!
//! Always-on advisory: `vendor_maven_local_cache_shadow`. Maven checks the LOCAL
//! repository (`~/.m2`) BEFORE any configured `<repository>`, so a warm
//! `~/.m2` copy of the same GAV silently wins over our patched file:// artifact.
//! The warning carries the `mvn dependency:purge-local-repository` one-liner to
//! clear it.
//!
//! Edit order: artifact (jar + pom + sidecars) → `pom.xml`. Any failure after
//! the artifact removes the uuid dir; the `pom.xml` edit runs last so a failed
//! artifact never leaves a dangling `<repository>`.

use std::collections::HashMap;
use std::io::Read as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;
use sha1::Sha1;
use sha2::{Digest as _, Sha256};

use crate::constants::USER_AGENT;
use crate::manifest::schema::{PatchFileInfo, PatchRecord};
use crate::patch::apply::{
    is_safe_relative_subpath, normalize_file_path, ApplyResult, PatchSources,
};
use crate::patch::copy_tree::remove_tree;
use crate::patch::path_safety::is_safe_single_segment;
use crate::utils::fs::atomic_write_bytes;
use crate::utils::purl::{build_maven_purl, parse_maven_purl};

use super::common::{already_patched_verify, refused, synthesized_result};
use super::path::vendor_uuid_dir_rel;
use super::registry_fetch::extract_zip;
use super::service_fetch::{fetch_verified_archive, ServiceArtifact};
use super::state::{
    write_marker, VendorArtifact, VendorEntry, VendorMarker, WiringAction, WiringRecord,
};
use super::{RevertOutcome, VendorOutcome, VendorServiceConfig, VendorWarning};

/// The project file this backend wires (always at the project root).
const PROJECT_POM: &str = "pom.xml";

/// Wiring-record discriminator. The record carries the WHOLE-FILE pre/post
/// `pom.xml` snapshot (the authoritative revert record); its `key` is the
/// repository id we added, which the revert ownership gate keys off.
const REPO_WIRING_KIND: &str = "maven_pom_repository";

/// Marker schema version written into `socket-patch.vendor.json`.
const MARKER_SCHEMA_VERSION: u32 = 1;

/// Bound on a pom download from the registry — a pom is dependency metadata
/// (small XML); a multi-MB response is a mirror serving the wrong thing.
const MAX_POM_BYTES: usize = 8 * 1024 * 1024;

/// The maven2 registry base for the (fallback) pom download, overridable with
/// `SOCKET_MAVEN_REGISTRY` (the private-mirror / test escape hatch). Default is
/// Maven Central's maven2 endpoint.
fn maven_registry_base() -> String {
    std::env::var("SOCKET_MAVEN_REGISTRY")
        .ok()
        .map(|v| v.trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "https://repo1.maven.org/maven2".to_string())
}

/// Convert a dotted Maven groupId to its maven2 path segment
/// (`org.apache.commons` → `org/apache/commons`). Local twin of the private
/// `maven_crawler::group_id_to_path`; the coordinate has already passed
/// [`is_safe_group_id`] before this runs.
fn group_id_to_path(group_id: &str) -> String {
    group_id.replace('.', "/")
}

/// A groupId is safe to convert to a path and join onto the vendor root: each
/// dot-delimited segment must be a safe path segment on its own (non-empty, no
/// separator/backslash/colon/NUL), which also rejects the empty string and
/// leading/trailing/double dots. Same delegation as the maven crawler's
/// `is_safe_maven_coordinate` group half. Fails closed on tampered coordinates.
fn is_safe_group_id(group_id: &str) -> bool {
    group_id.split('.').all(is_safe_single_segment)
}

/// Vendor a Maven package: rebuild a patched `.jar` under a committed maven2
/// repository at `.socket/vendor/maven/<uuid>/`, copy the real upstream pom
/// beside it, and wire the project `pom.xml` with a `<repository>` serving it
/// (see the module doc).
///
/// `installed_dir` is the crawler's version dir
/// (`~/.m2/repository/<g>/<a>/<v>/`), which holds the cached pristine
/// `<a>-<v>.jar` the rebuild extracts from and the `<a>-<v>.pom` copied verbatim.
#[allow(clippy::too_many_arguments)]
pub async fn vendor_maven(
    purl: &str,
    installed_dir: &Path,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
    service: Option<&VendorServiceConfig>,
) -> VendorOutcome {
    // ── coordinates ──────────────────────────────────────────────────────
    let Some((group_id, artifact_id, version)) = parse_maven_purl(purl) else {
        return refused("unsafe_coordinates", format!("not a maven purl: {purl}"));
    };
    // SECURITY: `uuid`, `group_id`, `artifact_id`, and `version` come from
    // committed, tamper-able manifest data. They key the uuid dir vendor
    // creates and `--revert` deletes, the nested maven2 path, the vendored
    // filenames, and — via `pom.xml` — an XML attribute value. Reject anything
    // that could traverse out of `.socket/vendor/maven/` fail-closed before any
    // disk access.
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("maven", &record.uuid) else {
        return refused(
            "unsafe_coordinates",
            format!("non-canonical patch uuid {:?}", record.uuid),
        );
    };
    if !is_safe_group_id(group_id)
        || !is_safe_single_segment(artifact_id)
        || !is_safe_single_segment(version)
    {
        return refused(
            "unsafe_coordinates",
            format!("unsafe maven coordinates `{group_id}:{artifact_id}` @ `{version}`"),
        );
    }

    let group_path = group_id_to_path(group_id);
    let leaf_rel = format!("{uuid_dir_rel}/{group_path}/{artifact_id}/{version}");
    let jar_leaf = format!("{artifact_id}-{version}.jar");
    let pom_leaf = format!("{artifact_id}-{version}.pom");
    let jar_copy_rel = format!("{leaf_rel}/{jar_leaf}");
    let uuid_dir = project_root.join(&uuid_dir_rel);
    let leaf_dir = project_root.join(&leaf_rel);
    let jar_path = leaf_dir.join(&jar_leaf);
    let repo_id = format!("socket-patch-vendor-{}", record.uuid);

    // A patch with no files is meaningless to vendor: no-op success, no edits.
    if record.files.is_empty() {
        return VendorOutcome::Done {
            result: synthesized_result(purl, &jar_path, Vec::new(), true, None),
            entry: None,
            warnings: Vec::new(),
        };
    }

    // ── project pom.xml: presence + aggregator/gradle refusals ────────────
    let pom_xml_path = project_root.join(PROJECT_POM);
    let pom_xml_text: Option<String> = match tokio::fs::read_to_string(&pom_xml_path).await {
        Ok(t) => Some(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return refused(
                "vendor_maven_pom_unreadable",
                format!("unreadable {}: {e}", pom_xml_path.display()),
            );
        }
    };
    let Some(pom_xml_text) = pom_xml_text else {
        // No project pom.xml: a gradle-only project has no <repositories> to
        // wire (and Gradle ignores it); anything else is not a Maven project.
        if project_has_gradle(project_root).await {
            return refused(
                "vendor_gradle_unsupported",
                "this is a Gradle project (no pom.xml); vendoring wires a Maven \
                 <repository>, which Gradle does not consume",
            );
        }
        return refused(
            "vendor_maven_pom_project_missing",
            format!("no {PROJECT_POM} at the project root to wire a vendored <repository> into"),
        );
    };
    if declares_modules(&pom_xml_text) {
        return refused(
            "vendor_maven_multimodule_unsupported",
            "the root pom.xml declares <modules> (a multi-module aggregator); \
             ${project.basedir} would resolve to each submodule, not the root, so a \
             file:// vendored repository cannot be wired here",
        );
    }

    // The local-cache shadow is inherent to Maven's resolution order, so the
    // advisory is emitted on every run (including dry runs and the idempotent
    // hot path) — a warm ~/.m2 copy silently wins over the vendored artifact.
    let shadow_warning = local_cache_shadow_warning(group_id, artifact_id, version, &group_path);

    // ── idempotent hot path ──────────────────────────────────────────────
    // pom.xml already carries our <repository> and the committed jar/pom/
    // sidecars are all in sync → touch nothing, report AlreadyPatched. `entry`
    // stays `None`: the first run's ledger entry holds the only copy of the
    // verbatim pre-vendor pom.xml, and re-recording here would clobber it.
    let repo_wired = pom_xml_text.contains(&repo_id);
    if repo_wired {
        if artifact_in_sync(&leaf_dir, &jar_leaf, &pom_leaf, &record.files).await {
            let verified = record
                .files
                .keys()
                .map(|f| already_patched_verify(f))
                .collect();
            return VendorOutcome::Done {
                result: synthesized_result(purl, &jar_path, verified, true, None),
                entry: None,
                warnings: vec![shadow_warning],
            };
        }
        // Wired but the committed artifact is missing/stale: rebuild the
        // ARTIFACT only. pom.xml is already correct, and the full path would
        // re-record the live vendored pom.xml as `original`, breaking revert.
        if !dry_run {
            let mut warnings: Vec<VendorWarning> = vec![shadow_warning];
            let (_bytes, result) = match materialise_and_write(
                purl,
                installed_dir,
                &uuid_dir,
                &leaf_dir,
                &jar_leaf,
                &pom_leaf,
                &jar_path,
                group_id,
                artifact_id,
                version,
                &group_path,
                record,
                sources,
                force,
                service,
                &mut warnings,
            )
            .await
            {
                Ok(pair) => pair,
                Err(outcome) => return *outcome,
            };
            if !result.success {
                return VendorOutcome::Done {
                    result,
                    entry: None,
                    warnings,
                };
            }
            warnings.push(VendorWarning::new(
                "vendor_artifact_rebuilt",
                format!(
                    "the committed vendored artifact for {artifact_id}@{version} was missing or \
                     stale; rebuilt at {leaf_rel} (pom.xml untouched)"
                ),
            ));
            return VendorOutcome::Done {
                result,
                entry: None,
                warnings,
            };
        }
        // Dry runs fall through to the verify-only preview below.
    }

    // ── dry run: verify-only against the extracted local jar, no writes ───
    if dry_run {
        let mut dry_warnings: Vec<VendorWarning> = vec![shadow_warning];
        let result = dry_run_verify(
            purl,
            installed_dir,
            &jar_path,
            artifact_id,
            version,
            record,
            sources,
            force,
            &mut dry_warnings,
        )
        .await;
        return VendorOutcome::Done {
            result,
            entry: None,
            warnings: dry_warnings,
        };
    }

    // ── materialise the patched jar + real pom + sidecars ─────────────────
    let mut warnings: Vec<VendorWarning> = vec![shadow_warning];
    let (jar_bytes, mut result) = match materialise_and_write(
        purl,
        installed_dir,
        &uuid_dir,
        &leaf_dir,
        &jar_leaf,
        &pom_leaf,
        &jar_path,
        group_id,
        artifact_id,
        version,
        &group_path,
        record,
        sources,
        force,
        service,
        &mut warnings,
    )
    .await
    {
        Ok(pair) => pair,
        Err(outcome) => return *outcome,
    };
    if !result.success {
        // The rebuild left the result un-successful (and cleaned up its own
        // partial artifact); pom.xml was never touched.
        return VendorOutcome::Done {
            result,
            entry: None,
            warnings,
        };
    }
    result.package_path = jar_path.display().to_string();

    // ── pom.xml wiring (runs last) ────────────────────────────────────────
    let new_pom_xml = match build_repo_edit(&pom_xml_text, &repo_id, &uuid_dir_rel) {
        Ok(text) => text,
        Err(detail) => {
            let _ = remove_tree(&uuid_dir).await;
            result.success = false;
            result.error = Some(detail);
            return VendorOutcome::Done {
                result,
                entry: None,
                warnings,
            };
        }
    };
    if let Err(e) = atomic_write_bytes(&pom_xml_path, new_pom_xml.as_bytes()).await {
        let _ = remove_tree(&uuid_dir).await;
        result.success = false;
        result.error = Some(format!("failed to write {}: {e}", pom_xml_path.display()));
        return VendorOutcome::Done {
            result,
            entry: None,
            warnings,
        };
    }

    // ── marker + ledger entry ─────────────────────────────────────────────
    let base_purl = build_maven_purl(group_id, artifact_id, version);
    let mut vulnerabilities: Vec<String> = record.vulnerabilities.keys().cloned().collect();
    vulnerabilities.sort();
    let marker = VendorMarker {
        schema_version: MARKER_SCHEMA_VERSION,
        purl: base_purl.clone(),
        patch_uuid: record.uuid.clone(),
        ecosystem: "maven".to_string(),
        vulnerabilities,
        vendored_at: vendored_at.to_string(),
    };
    if let Err(e) = write_marker(&uuid_dir, &marker).await {
        // Informational only (state.json is the ledger of record) — a marker
        // failure must not fail an otherwise-wired vendor.
        warnings.push(VendorWarning::new(
            "vendor_marker_write_failed",
            format!("could not write {}: {e}", super::state::VENDOR_MARKER_FILE),
        ));
    }

    // The single wiring record is the authoritative revert record: it carries
    // the whole-file pre/post pom.xml snapshot. `Added` because we ADD a
    // <repository> (the pom.xml itself always pre-existed — a gradle-only /
    // pom-less project is refused above); revert restores the `original` bytes
    // when the live pom.xml still carries our repo id.
    let entry = VendorEntry {
        ecosystem: "maven".to_string(),
        base_purl,
        uuid: record.uuid.clone(),
        artifact: VendorArtifact {
            // A `.jar` is a single verifiable file; record its plain sha256 for
            // tooling (harvest re-derives per-entry git hashes from the zip, so
            // the vendored copy is self-describing without a network).
            path: jar_copy_rel,
            sha256: hex::encode(Sha256::digest(&jar_bytes)),
            size: Some(jar_bytes.len() as u64),
            platform_locked: None,
        },
        wiring: vec![WiringRecord {
            file: PROJECT_POM.to_string(),
            kind: REPO_WIRING_KIND.to_string(),
            action: WiringAction::Added,
            key: Some(repo_id),
            original: Some(Value::String(pom_xml_text)),
            new: Some(Value::String(new_pom_xml)),
        }],
        lock: None,
        took_over_go_patches: false,
        detached: false,
        record: None,
        flavor: None,
        uv: None,
        pnpm: None,
        poetry: None,
        pdm: None,
        pipenv: None,
    };

    VendorOutcome::Done {
        result,
        entry: Some(entry),
        warnings,
    }
}

/// Revert a Maven vendor entry: surgically remove our `<repository>` from
/// `pom.xml` (restoring the whole verbatim original only on the byte-identical
/// fast path — otherwise excising just our block so sibling patches and user
/// edits survive) and remove the validated uuid dir. A drifted live pom.xml —
/// our block already gone, a re-generated pom — is left alone with a
/// `vendor_lock_entry_drifted` warning.
pub async fn revert_maven(
    entry: &VendorEntry,
    project_root: &Path,
    dry_run: bool,
) -> RevertOutcome {
    // SECURITY: state.json is committed and tamper-able; the uuid keys the
    // directory we are about to delete. Anything but the canonical uuid grammar
    // is rejected fail-closed before any disk access.
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("maven", &entry.uuid) else {
        return RevertOutcome::failed(format!(
            "refusing revert: non-canonical patch uuid {:?}",
            entry.uuid
        ));
    };
    let uuid_dir = project_root.join(&uuid_dir_rel);
    let mut warnings = Vec::new();

    // One wiring record today; reverse-order iteration keeps parity with the
    // multi-record backends.
    for w in entry.wiring.iter().rev() {
        let restored = match w.kind.as_str() {
            REPO_WIRING_KIND => {
                revert_repo_record(&project_root.join(PROJECT_POM), w, &uuid_dir_rel, dry_run).await
            }
            _ => {
                warnings.push(VendorWarning::new(
                    "vendor_lock_entry_drifted",
                    format!("unrecognized wiring kind {:?}; fragment left alone", w.kind),
                ));
                continue;
            }
        };
        match restored {
            Ok(true) => {}
            Ok(false) => warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "{} no longer carries the vendored <repository> {}; left alone",
                    w.file,
                    w.key.as_deref().unwrap_or("<unknown>")
                ),
            )),
            Err(e) => {
                return RevertOutcome {
                    success: false,
                    warnings,
                    error: Some(e),
                };
            }
        }
    }

    if !dry_run {
        if let Err(e) = remove_tree(&uuid_dir).await {
            return RevertOutcome {
                success: false,
                warnings,
                error: Some(format!("failed to remove {}: {e}", uuid_dir.display())),
            };
        }
    }

    RevertOutcome {
        success: true,
        warnings,
        error: None,
    }
}

// ── materialisation (service download / local rebuild) ──────────────────────────

/// Produce the patched jar bytes + the real upstream pom, then write both (with
/// their `.sha1` sidecars) into the maven2 leaf dir. Returns `(jar_bytes,
/// ApplyResult)`, or a terminal [`VendorOutcome`] to bubble. On a non-fatal
/// rebuild failure the returned `ApplyResult.success` is false and the partial
/// uuid dir is cleaned up.
#[allow(clippy::too_many_arguments)]
async fn materialise_and_write(
    purl: &str,
    installed_dir: &Path,
    uuid_dir: &Path,
    leaf_dir: &Path,
    jar_leaf: &str,
    pom_leaf: &str,
    jar_path: &Path,
    group_id: &str,
    artifact_id: &str,
    version: &str,
    group_path: &str,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    force: bool,
    service: Option<&VendorServiceConfig>,
    warnings: &mut Vec<VendorWarning>,
) -> Result<(Vec<u8>, ApplyResult), Box<VendorOutcome>> {
    // The patched jar first (service Tier A, else local rebuild). A non-fatal
    // failure returns an un-successful ApplyResult with nothing written.
    let (jar_bytes, result) = match maven_service_copy(service, record, artifact_id, warnings).await
    {
        MavenServiceCopy::Used(bytes) => {
            let verified = record
                .files
                .keys()
                .map(|f| already_patched_verify(f))
                .collect();
            (
                bytes,
                synthesized_result(purl, jar_path, verified, true, None),
            )
        }
        MavenServiceCopy::HardFail(outcome) => return Err(outcome),
        MavenServiceCopy::FallBack => {
            match local_rebuild_jar(
                purl,
                installed_dir,
                jar_path,
                artifact_id,
                version,
                record,
                sources,
                force,
                warnings,
            )
            .await
            {
                Ok(pair) => pair,
                Err(outcome) => return Err(outcome),
            }
        }
    };
    if !result.success {
        // Local rebuild reported a failure; nothing on disk to clean up (the
        // jar is rebuilt in memory and only written below on success).
        return Ok((jar_bytes, result));
    }

    // The REAL upstream pom (transitive-deps correctness). A miss is terminal:
    // refuse rather than fabricate a minimal pom.
    let pom_bytes = match acquire_upstream_pom(
        installed_dir,
        group_id,
        artifact_id,
        version,
        group_path,
        service,
        warnings,
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(detail) => return Err(Box::new(refused("vendor_maven_pom_unavailable", detail))),
    };

    // Write jar + pom + their sha1 sidecars into the maven2 leaf dir.
    if let Err(e) = write_maven_artifact(leaf_dir, jar_leaf, &jar_bytes, pom_leaf, &pom_bytes).await
    {
        let _ = remove_tree(uuid_dir).await;
        return Ok((Vec::new(), failed_result(purl, jar_path, e)));
    }
    Ok((jar_bytes, result))
}

/// Local rebuild: locate the cached pristine `<a>-<v>.jar` in `installed_dir`,
/// extract it to a private stage, force-apply the patch, and re-zip
/// deterministically. Returns `(bytes, ApplyResult)`; a failure surfaces as an
/// un-successful `ApplyResult`, or a refusal to bubble.
#[allow(clippy::too_many_arguments)]
async fn local_rebuild_jar(
    purl: &str,
    installed_dir: &Path,
    jar_path: &Path,
    artifact_id: &str,
    version: &str,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    force: bool,
    warnings: &mut Vec<VendorWarning>,
) -> Result<(Vec<u8>, ApplyResult), Box<VendorOutcome>> {
    let src_jar = installed_dir.join(format!("{artifact_id}-{version}.jar"));
    if tokio::fs::metadata(&src_jar).await.is_err() {
        return Err(Box::new(refused(
            "vendor_maven_jar_not_found",
            format!(
                "no cached {} under {} to rebuild the patched artifact from (a vendored feed \
                 needs the pristine jar; re-resolve it or use --vendor-source=service)",
                src_jar
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                installed_dir.display()
            ),
        )));
    }
    let stage = match extract_jar_to_stage(&src_jar).await {
        Ok(stage) => stage,
        Err(e) => return Ok((Vec::new(), failed_result(purl, jar_path, e))),
    };

    let result = super::force_apply_staged(
        purl,
        stage.path(),
        record,
        sources,
        /*dry_run=*/ false,
        force,
        artifact_id,
        version,
        warnings,
    )
    .await;
    if !result.success {
        return Ok((Vec::new(), result));
    }

    // Deterministic re-zip of the patched stage (a jar is a plain zip; a
    // dependency resolve reads the central directory, so lexicographic entry
    // order + fixed timestamps yield stable bytes across re-runs).
    let stage_path = stage.path().to_path_buf();
    let rezip = tokio::task::spawn_blocking(move || rebuild_jar(&stage_path)).await;
    let jar_bytes = match rezip {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            return Ok((
                Vec::new(),
                failed_result(purl, jar_path, format!("jar re-zip failed: {e}")),
            ))
        }
        Err(e) => {
            return Ok((
                Vec::new(),
                failed_result(purl, jar_path, format!("jar re-zip task failed: {e}")),
            ))
        }
    };
    Ok((jar_bytes, result))
}

/// Outcome of attempting to materialise the jar from the patch service.
enum MavenServiceCopy {
    /// The prebuilt patched `.jar` bytes (write them verbatim).
    Used(Vec<u8>),
    /// Bubble this terminal outcome (boxed — `VendorOutcome` is large).
    HardFail(Box<VendorOutcome>),
    /// Fall back to the local rebuild.
    FallBack,
}

/// Download + integrity-verify the prebuilt patched `.jar` (Tier A: the verified
/// archive bytes ARE the vendored jar). Maps each service outcome onto the
/// `auto` / `service` fallback policy.
async fn maven_service_copy(
    service: Option<&VendorServiceConfig>,
    record: &PatchRecord,
    artifact_id: &str,
    warnings: &mut Vec<VendorWarning>,
) -> MavenServiceCopy {
    let Some(cfg) = service else {
        return MavenServiceCopy::FallBack;
    };
    if !cfg.service_enabled() {
        return MavenServiceCopy::FallBack;
    }
    fn hard(code: &'static str, detail: String) -> MavenServiceCopy {
        MavenServiceCopy::HardFail(Box::new(VendorOutcome::Refused { code, detail }))
    }
    let miss = |warnings: &mut Vec<VendorWarning>, code: &'static str, reason: String| {
        if cfg.source.requires_service() {
            hard("vendor_prebuilt_required", reason)
        } else {
            warnings.push(VendorWarning::new(
                code,
                format!("{reason}; building locally instead"),
            ));
            MavenServiceCopy::FallBack
        }
    };
    match fetch_verified_archive(cfg, &record.uuid, artifact_id).await {
        ServiceArtifact::Ready(archive) => {
            warnings.push(VendorWarning::new(
                "vendor_prebuilt_downloaded",
                format!(
                    "vendored {artifact_id} from the patch service ({})",
                    archive.source_url
                ),
            ));
            MavenServiceCopy::Used(archive.bytes)
        }
        ServiceArtifact::IntegrityMismatch(reason) => miss(
            warnings,
            "vendor_prebuilt_integrity_mismatch",
            format!("prebuilt .jar failed integrity ({reason})"),
        ),
        ServiceArtifact::Pending => miss(
            warnings,
            "vendor_prebuilt_pending",
            "prebuilt .jar is still building".to_string(),
        ),
        ServiceArtifact::Unavailable(reason) => {
            if cfg.source.requires_service() {
                hard(
                    "vendor_prebuilt_required",
                    format!("prebuilt .jar unavailable: {reason}"),
                )
            } else {
                MavenServiceCopy::FallBack
            }
        }
        ServiceArtifact::Failed(reason) => miss(
            warnings,
            "vendor_prebuilt_unavailable",
            format!("patch service request failed ({reason})"),
        ),
    }
}

/// Acquire the REAL upstream pom bytes: the cached `~/.m2` copy first (the
/// common case — the package was resolved locally), then a maven2 registry
/// download when the service is enabled. An `Err(detail)` maps to a
/// `vendor_maven_pom_unavailable` refusal — we NEVER author a minimal pom (it
/// would drop the artifact's transitive dependencies).
async fn acquire_upstream_pom(
    installed_dir: &Path,
    group_id: &str,
    artifact_id: &str,
    version: &str,
    group_path: &str,
    service: Option<&VendorServiceConfig>,
    warnings: &mut Vec<VendorWarning>,
) -> Result<Vec<u8>, String> {
    let local = installed_dir.join(format!("{artifact_id}-{version}.pom"));
    match tokio::fs::read(&local).await {
        Ok(bytes) => return Ok(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("unreadable local pom {}: {e}", local.display())),
    }

    // No local pom (fresh clone / service-sourced jar). Download it from the
    // maven2 registry when the service is enabled. A fresh reqwest client is
    // used (never the Socket API client) so no API token leaks to a third-party
    // registry — the pom is dependency metadata, trusted by transport, whereas
    // the security-critical jar was integrity-verified by the patch service.
    let can_fetch = service.is_some_and(|cfg| cfg.service_enabled());
    if !can_fetch {
        return Err(format!(
            "no upstream pom for {group_id}:{artifact_id}:{version} in the local Maven cache \
             and the vendoring service is disabled/offline; refusing to author a minimal pom \
             (it would drop transitive dependencies)"
        ));
    }
    let base = maven_registry_base();
    let url = format!("{base}/{group_path}/{artifact_id}/{version}/{artifact_id}-{version}.pom");
    match fetch_pom_bytes(&url).await {
        Ok(bytes) => {
            warnings.push(VendorWarning::new(
                "vendor_maven_pom_downloaded",
                format!("downloaded the upstream pom for {artifact_id}@{version} from {url}"),
            ));
            Ok(bytes)
        }
        Err(e) => Err(format!(
            "no local upstream pom and the maven2 registry fetch failed ({e}); refusing to \
             author a minimal pom (it would drop transitive dependencies)"
        )),
    }
}

/// Bounded HTTP GET of a pom from the maven2 registry.
async fn fetch_pom_bytes(url: &str) -> Result<Vec<u8>, String> {
    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| format!("build http client: {e}"))?;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("GET {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GET {url}: HTTP {}", resp.status()));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("read body of {url}: {e}"))?;
    if bytes.len() > MAX_POM_BYTES {
        return Err(format!(
            "pom at {url} is {} bytes (cap {MAX_POM_BYTES})",
            bytes.len()
        ));
    }
    Ok(bytes.to_vec())
}

/// Dry-run verify-only: extract the local jar to a private stage and run the
/// apply pipeline in preview mode. A missing local jar surfaces as a failed
/// result (the preview cannot predict a rebuild it cannot stage).
#[allow(clippy::too_many_arguments)]
async fn dry_run_verify(
    purl: &str,
    installed_dir: &Path,
    jar_path: &Path,
    artifact_id: &str,
    version: &str,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    force: bool,
    warnings: &mut Vec<VendorWarning>,
) -> ApplyResult {
    let src_jar = installed_dir.join(format!("{artifact_id}-{version}.jar"));
    if tokio::fs::metadata(&src_jar).await.is_err() {
        return failed_result(
            purl,
            jar_path,
            format!(
                "no cached {}-{}.jar under {} to preview the vendored artifact",
                artifact_id,
                version,
                installed_dir.display()
            ),
        );
    }
    let stage = match extract_jar_to_stage(&src_jar).await {
        Ok(stage) => stage,
        Err(e) => return failed_result(purl, jar_path, e),
    };
    let mut result = super::force_apply_staged(
        purl,
        stage.path(),
        record,
        sources,
        /*dry_run=*/ true,
        force,
        artifact_id,
        version,
        warnings,
    )
    .await;
    result.package_path = jar_path.display().to_string();
    result
}

// ── artifact helpers ─────────────────────────────────────────────────────────────

/// Extract a jar (a plain zip; content at the archive root — no strip) into a
/// fresh tempdir. `extract_zip` is traversal-guarded and refuses an escaping
/// entry fail-closed. Returns the live [`tempfile::TempDir`] (the caller holds
/// it for the stage's lifetime).
async fn extract_jar_to_stage(src_jar: &Path) -> Result<tempfile::TempDir, String> {
    let bytes = tokio::fs::read(src_jar)
        .await
        .map_err(|e| format!("cannot read {}: {e}", src_jar.display()))?;
    let stage = tempfile::tempdir().map_err(|e| format!("cannot create stage dir: {e}"))?;
    extract_zip(&bytes, stage.path(), /*strip_first=*/ false)
        .map_err(|e| format!("cannot extract {}: {e}", src_jar.display()))?;
    Ok(stage)
}

/// Re-zip the patched stage into a deterministic jar: entries sorted
/// lexicographically, a fixed timestamp, and a fixed deflate level so rebuilding
/// the same patched tree always yields identical bytes (churn-free commits +
/// a stable `.sha1`). A jar is a plain zip resolved via its central directory,
/// so entry order is free to be lexicographic.
fn rebuild_jar(stage: &Path) -> Result<Vec<u8>, String> {
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    for entry in walkdir::WalkDir::new(stage).follow_links(false) {
        let entry = entry.map_err(|e| format!("walk {}: {e}", stage.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(stage)
            .map_err(|e| format!("strip prefix: {e}"))?;
        let name = rel.to_string_lossy().replace('\\', "/");
        let bytes = std::fs::read(entry.path()).map_err(|e| format!("read {name}: {e}"))?;
        entries.push((name, bytes));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, bytes) in &entries {
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .compression_level(Some(6))
            .last_modified_time(zip::DateTime::default())
            .unix_permissions(0o644);
        writer
            .start_file(name, options)
            .map_err(|e| format!("zip start {name}: {e}"))?;
        writer
            .write_all(bytes)
            .map_err(|e| format!("zip write {name}: {e}"))?;
    }
    let cursor = writer.finish().map_err(|e| format!("zip finish: {e}"))?;
    Ok(cursor.into_inner())
}

/// Write the jar + pom + their `.sha1` sidecars into the maven2 leaf dir,
/// creating it. Errors are strings.
async fn write_maven_artifact(
    leaf_dir: &Path,
    jar_leaf: &str,
    jar_bytes: &[u8],
    pom_leaf: &str,
    pom_bytes: &[u8],
) -> Result<(), String> {
    tokio::fs::create_dir_all(leaf_dir)
        .await
        .map_err(|e| format!("cannot create {}: {e}", leaf_dir.display()))?;
    for (leaf, bytes) in [(jar_leaf, jar_bytes), (pom_leaf, pom_bytes)] {
        let path = leaf_dir.join(leaf);
        atomic_write_bytes(&path, bytes)
            .await
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        let sha1_path = leaf_dir.join(format!("{leaf}.sha1"));
        atomic_write_bytes(&sha1_path, sha1_hex(bytes).as_bytes())
            .await
            .map_err(|e| format!("cannot write {}: {e}", sha1_path.display()))?;
    }
    Ok(())
}

/// True when the committed jar/pom/sidecars are all present and consistent: the
/// jar's patched files hash to their `afterHash`es and each `.sha1` sidecar
/// matches its file's bytes (so `checksumPolicy=fail` stays satisfied).
async fn artifact_in_sync(
    leaf_dir: &Path,
    jar_leaf: &str,
    pom_leaf: &str,
    files: &HashMap<String, PatchFileInfo>,
) -> bool {
    let jar = leaf_dir.join(jar_leaf);
    if !jar_matches_after_hashes(&jar, files).await {
        return false;
    }
    // The pom + both sidecars must exist and match their bytes.
    sidecar_matches(&jar).await && sidecar_matches(&leaf_dir.join(pom_leaf)).await
}

/// True when `<file>.sha1` exists and equals the hex sha1 of `<file>`'s bytes.
async fn sidecar_matches(file: &Path) -> bool {
    let Ok(bytes) = tokio::fs::read(file).await else {
        return false;
    };
    let Ok(recorded) = tokio::fs::read_to_string(with_suffix(file, ".sha1")).await else {
        return false;
    };
    recorded.trim() == sha1_hex(&bytes)
}

/// Append a suffix to a path's file name (`foo.jar` + `.sha1` → `foo.jar.sha1`).
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    name.push_str(suffix);
    path.with_file_name(name)
}

/// True when the committed jar exists and every patched file in it already
/// hashes to its `afterHash` (the vendor twin of the NuGet feed's
/// `nupkg_matches_after_hashes`, reading the jar's zip entries).
async fn jar_matches_after_hashes(jar_path: &Path, files: &HashMap<String, PatchFileInfo>) -> bool {
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    let Ok(bytes) = tokio::fs::read(jar_path).await else {
        return false;
    };
    let Ok(mut archive) = zip::ZipArchive::new(std::io::Cursor::new(bytes)) else {
        return false;
    };
    for (file_name, info) in files {
        let normalized = normalize_file_path(file_name);
        // SECURITY: never look up a key that escapes the package dir — treat it
        // as out-of-sync (the full pipeline would refuse it anyway).
        if !is_safe_relative_subpath(normalized) {
            return false;
        }
        let Ok(mut entry) = archive.by_name(normalized) else {
            return false;
        };
        let mut content = Vec::with_capacity(entry.size() as usize);
        if entry.read_to_end(&mut content).is_err() {
            return false;
        }
        if compute_git_sha256_from_bytes(&content) != info.after_hash {
            return false;
        }
    }
    true
}

fn sha1_hex(bytes: &[u8]) -> String {
    hex::encode(Sha1::digest(bytes))
}

// ── pom.xml editing ──────────────────────────────────────────────────────────────

/// Build the wired `pom.xml` text: insert our `<repository>` into
/// `<repositories>` (or create the section before `</project>`). The pom is
/// edited by targeted string insertion so all other bytes — formatting,
/// comments, key order — are preserved and a later revert restores it
/// byte-identically.
fn build_repo_edit(original: &str, repo_id: &str, uuid_dir_rel: &str) -> Result<String, String> {
    let block = repository_block(repo_id, uuid_dir_rel);
    if original.contains("</repositories>") {
        insert_before(original, "</repositories>", &block).ok_or_else(|| {
            "could not locate </repositories> to insert the vendored <repository>".to_string()
        })
    } else if original.contains("</project>") {
        let section = format!("  <repositories>\n{block}  </repositories>\n");
        insert_before(original, "</project>", &section).ok_or_else(|| {
            "could not locate </project> to insert a <repositories> section".to_string()
        })
    } else {
        Err("pom.xml has no </project> to edit".to_string())
    }
}

/// The `<repository>` element served from the committed maven2 repo. The URL
/// uses `${project.basedir}` so it resolves relative to the pom on any checkout;
/// `checksumPolicy=fail` makes Maven hard-fail on a jar/pom that doesn't match
/// its `.sha1` sidecar; `<snapshots>` is disabled (the vendored GAV is a fixed
/// release).
fn repository_block(repo_id: &str, uuid_dir_rel: &str) -> String {
    format!(
        "    <repository>\n\
         \x20     <id>{repo_id}</id>\n\
         \x20     <url>file://${{project.basedir}}/{uuid_dir_rel}</url>\n\
         \x20     <releases>\n\
         \x20       <enabled>true</enabled>\n\
         \x20       <checksumPolicy>fail</checksumPolicy>\n\
         \x20     </releases>\n\
         \x20     <snapshots>\n\
         \x20       <enabled>false</enabled>\n\
         \x20     </snapshots>\n\
         \x20   </repository>\n"
    )
}

/// Insert `insertion` (already newline-terminated) immediately before the line
/// containing the first occurrence of `needle`. Returns `None` if `needle` is
/// absent.
fn insert_before(haystack: &str, needle: &str, insertion: &str) -> Option<String> {
    let idx = haystack.find(needle)?;
    // Back up to the start of the needle's line so the insertion lands on its
    // own line(s) directly above.
    let line_start = haystack[..idx].rfind('\n').map(|n| n + 1).unwrap_or(0);
    let mut out = String::with_capacity(haystack.len() + insertion.len());
    out.push_str(&haystack[..line_start]);
    out.push_str(insertion);
    out.push_str(&haystack[line_start..]);
    Some(out)
}

/// True when the pom declares a real (non-commented) `<modules>` element — an
/// aggregator/multi-module root. Comments are stripped first so a commented-out
/// `<modules>` never triggers a refusal, and the open tag is boundary-matched
/// so `<modulesInfo>` is not mistaken for it.
fn declares_modules(pom_text: &str) -> bool {
    let stripped = strip_xml_comments(pom_text);
    real_open_tag(&stripped, "modules")
}

/// Remove every `<!-- ... -->` span (comments do not nest in XML). Used before
/// tag detection so commented-out markup is never matched.
fn strip_xml_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        match rest.find("<!--") {
            Some(start) => {
                out.push_str(&rest[..start]);
                match rest[start..].find("-->") {
                    Some(end) => rest = &rest[start + end + 3..],
                    None => return out, // unterminated comment: drop the tail
                }
            }
            None => {
                out.push_str(rest);
                return out;
            }
        }
    }
}

/// True when `text` contains a real opening tag for `element` — `<element>`,
/// `<element ...>`, or `<element/>` — where the char after the name is a tag
/// boundary (`>`, `/`, or whitespace). Prefix matches (`<modulesInfo>`) do not
/// count. Mirrors the maven crawler's `opening_tag` boundary discipline.
fn real_open_tag(text: &str, element: &str) -> bool {
    let needle = format!("<{element}");
    let mut from = 0;
    while let Some(rel) = text[from..].find(&needle) {
        let pos = from + rel;
        let after = &text[pos + needle.len()..];
        match after.chars().next() {
            None => return true, // name runs to end of input
            Some(c) if c == '>' || c == '/' || c.is_whitespace() => return true,
            _ => from = pos + needle.len(),
        }
    }
    false
}

/// Whether the project root carries a Gradle build marker (used only to give a
/// gradle-only project the specific `vendor_gradle_unsupported` refusal).
async fn project_has_gradle(project_root: &Path) -> bool {
    for marker in [
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
    ] {
        if tokio::fs::metadata(project_root.join(marker)).await.is_ok() {
            return true;
        }
    }
    false
}

/// The always-on `vendor_maven_local_cache_shadow` advisory carrying the purge
/// one-liner.
fn local_cache_shadow_warning(
    group_id: &str,
    artifact_id: &str,
    version: &str,
    group_path: &str,
) -> VendorWarning {
    VendorWarning::new(
        "vendor_maven_local_cache_shadow",
        format!(
            "Maven resolves the local repository (~/.m2) BEFORE any configured <repository>, so a \
             warm ~/.m2 copy of {group_id}:{artifact_id}:{version} silently shadows the vendored \
             patched artifact. Purge it with: \
             mvn dependency:purge-local-repository -DmanualInclude={group_id}:{artifact_id} \
             (or delete ~/.m2/repository/{group_path}/{artifact_id}/{version})"
        ),
    )
}

/// Revert our `<repository>` wiring from `pom.xml`. `Ok(true)` = reverted (or
/// would be on dry run) / already gone; `Ok(false)` = drifted (the live pom no
/// longer carries our repository block), left alone; `Err` = a real I/O failure.
///
/// FRAGMENT-LEVEL: the whole-file `w.original` snapshot is only restored on the
/// provably-safe fast path where the live pom is still byte-identical to what we
/// wrote (`w.new`) — nothing has changed since vendoring. Otherwise — a sibling
/// patch added another `<repository>` into the same `<repositories>`, or the
/// user hand-edited the pom AFTER vendoring — we surgically excise ONLY the
/// exact `<repository>` block we authored (`build_repo_edit` renders it
/// deterministically, so we reproduce it verbatim from the repo id + uuid dir)
/// and leave every other byte (sibling wiring, user edits) intact. If we
/// created the `<repositories>` section and excising our block leaves it empty,
/// the now-empty section is removed too. A pom that no longer carries our exact
/// block is third-party state, left alone with a drift warning.
async fn revert_repo_record(
    pom_xml_path: &Path,
    w: &WiringRecord,
    uuid_dir_rel: &str,
    dry_run: bool,
) -> Result<bool, String> {
    let Some(repo_id) = w.key.as_deref() else {
        return Ok(false);
    };
    let Some(Value::String(original)) = &w.original else {
        return Ok(false);
    };
    let new = match &w.new {
        Some(Value::String(new)) => Some(new),
        _ => None,
    };
    let live = match tokio::fs::read_to_string(pom_xml_path).await {
        Ok(live) => live,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // The pom is gone (deleted by the user) — nothing to restore.
            return Ok(true);
        }
        Err(e) => return Err(format!("unreadable {}: {e}", pom_xml_path.display())),
    };

    // (a) Byte-identical to what we wrote → the whole-file restore is provably
    //     safe (nothing changed since vendoring). This also cheaply covers the
    //     lone-patch common case.
    if new.is_some_and(|n| &live == n) {
        if dry_run {
            return Ok(true);
        }
        atomic_write_bytes(pom_xml_path, original.as_bytes())
            .await
            .map_err(|e| format!("failed to restore {}: {e}", pom_xml_path.display()))?;
        return Ok(true);
    }

    // (b) The file diverged (a sibling vendor added another <repository>, or the
    //     user edited elsewhere) but our exact block is still present → excise
    //     ONLY our block, reproduced verbatim from the deterministic renderer.
    let block = repository_block(repo_id, uuid_dir_rel);
    if !live.contains(&block) {
        // (c) Our exact block is gone (already reverted, or edited) → drift,
        //     leave the file alone.
        return Ok(false);
    }
    if dry_run {
        return Ok(true);
    }
    let excised = strip_empty_repositories(&live.replacen(&block, "", 1));
    atomic_write_bytes(pom_xml_path, excised.as_bytes())
        .await
        .map_err(|e| {
            format!(
                "failed to excise the vendored <repository> from {}: {e}",
                pom_xml_path.display()
            )
        })?;
    Ok(true)
}

/// After excising our `<repository>`, drop a `<repositories>` section left with
/// no children (the section we created for the first vendored package). Matches
/// `build_repo_edit`'s `  <repositories>\n…  </repositories>\n` rendering so a
/// section it created is removed byte-for-byte; a section that still holds a
/// sibling `<repository>` is untouched (its inner bytes are non-whitespace).
fn strip_empty_repositories(pom: &str) -> String {
    let open = "  <repositories>\n";
    let close = "  </repositories>\n";
    let Some(open_at) = pom.find(open) else {
        return pom.to_string();
    };
    let inner_start = open_at + open.len();
    let Some(rel_close) = pom[inner_start..].find(close) else {
        return pom.to_string();
    };
    let inner = &pom[inner_start..inner_start + rel_close];
    if !inner.trim().is_empty() {
        // A sibling <repository> still lives here — keep the section.
        return pom.to_string();
    }
    let close_end = inner_start + rel_close + close.len();
    let mut out = String::with_capacity(pom.len());
    out.push_str(&pom[..open_at]);
    out.push_str(&pom[close_end..]);
    out
}

// ── shared helpers ────────────────────────────────────────────────────────────────

fn failed_result(purl: &str, jar_path: &Path, error: String) -> ApplyResult {
    synthesized_result(purl, jar_path, Vec::new(), false, Some(error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::patch::vendor::state::VENDOR_MARKER_FILE;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const PURL: &str = "pkg:maven/org.apache.commons/commons-text@1.10.0";
    const PRISTINE: &[u8] =
        b"Apache Commons Text\nCopyright 2014-2022 The Apache Software Foundation\n";
    const PATCHED: &[u8] =
        b"Apache Commons Text\n// SOCKET-PATCH-MARKER\nCopyright 2014-2022 The Apache Software Foundation\n";
    /// The real upstream pom, carrying a transitive dependency — proof that
    /// vendoring copies it verbatim (never a minimal stand-in).
    const UPSTREAM_POM: &[u8] = b"<project><modelVersion>4.0.0</modelVersion>\
        <groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId>\
        <version>1.10.0</version>\
        <dependencies><dependency><groupId>org.apache.commons</groupId>\
        <artifactId>commons-lang3</artifactId><version>3.12.0</version></dependency></dependencies>\
        </project>";
    /// The file inside the jar the marker patch targets.
    const JAR_FILE: &str = "META-INF/NOTICE.txt";

    fn leaf_rel() -> String {
        format!(".socket/vendor/maven/{UUID}/org/apache/commons/commons-text/1.10.0")
    }

    fn jar_rel() -> String {
        format!("{}/commons-text-1.10.0.jar", leaf_rel())
    }

    /// Build a jar (plain zip) with a MANIFEST + the NOTICE.txt patch target.
    fn make_jar(notice: &[u8]) -> Vec<u8> {
        let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        let files: &[(&str, &[u8])] = &[
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
            (JAR_FILE, notice),
            (
                "org/apache/commons/text/StringSubstitutor.class",
                b"\xca\xfe\xba\xbe-fake-class",
            ),
        ];
        for (name, bytes) in files {
            zw.start_file(*name, opts).unwrap();
            zw.write_all(bytes).unwrap();
        }
        zw.finish().unwrap().into_inner()
    }

    /// A minimal project pom.xml at the root (single-module, no <modules>).
    fn project_pom() -> &'static str {
        "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n\
         \x20 <modelVersion>4.0.0</modelVersion>\n\
         \x20 <groupId>com.example</groupId>\n\
         \x20 <artifactId>app</artifactId>\n\
         \x20 <version>1.0.0</version>\n\
         \x20 <dependencies>\n\
         \x20   <dependency>\n\
         \x20     <groupId>org.apache.commons</groupId>\n\
         \x20     <artifactId>commons-text</artifactId>\n\
         \x20     <version>1.10.0</version>\n\
         \x20   </dependency>\n\
         \x20 </dependencies>\n\
         </project>\n"
    }

    async fn fixture(
        pom_xml: Option<&str>,
        with_local_jar: bool,
        with_local_pom: bool,
    ) -> (tempfile::TempDir, PathBuf, PathBuf, PatchRecord) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // The crawler's version dir: ~/.m2/repository/<g>/<a>/<v>/ carrying the
        // cached jar + pom (NOT extracted files).
        let installed = root.join("m2/org/apache/commons/commons-text/1.10.0");
        tokio::fs::create_dir_all(&installed).await.unwrap();
        if with_local_jar {
            tokio::fs::write(
                installed.join("commons-text-1.10.0.jar"),
                make_jar(PRISTINE),
            )
            .await
            .unwrap();
        }
        if with_local_pom {
            tokio::fs::write(installed.join("commons-text-1.10.0.pom"), UPSTREAM_POM)
                .await
                .unwrap();
        }

        // Blob store carrying the patched NOTICE.txt.
        let after = compute_git_sha256_from_bytes(PATCHED);
        let blobs = root.join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        tokio::fs::write(blobs.join(&after), PATCHED).await.unwrap();

        if let Some(pom) = pom_xml {
            tokio::fs::write(root.join(PROJECT_POM), pom).await.unwrap();
        }

        let mut files = HashMap::new();
        files.insert(
            JAR_FILE.to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(PRISTINE),
                after_hash: after,
            },
        );
        let mut vulnerabilities = HashMap::new();
        vulnerabilities.insert(
            "GHSA-vend-maven-real".to_string(),
            crate::manifest::schema::VulnerabilityInfo {
                cves: Vec::new(),
                summary: String::new(),
                severity: String::new(),
                description: String::new(),
            },
        );
        let record = PatchRecord {
            uuid: UUID.to_string(),
            exported_at: "2026-06-09T00:00:00Z".to_string(),
            files,
            vulnerabilities,
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        };
        (dir, blobs, installed, record)
    }

    fn unwrap_done(o: VendorOutcome) -> (ApplyResult, Option<VendorEntry>, Vec<VendorWarning>) {
        match o {
            VendorOutcome::Done {
                result,
                entry,
                warnings,
            } => (result, entry, warnings),
            VendorOutcome::Refused { code, detail } => panic!("refused: {code}: {detail}"),
        }
    }

    fn unwrap_refused(o: VendorOutcome) -> (&'static str, String) {
        match o {
            VendorOutcome::Refused { code, detail } => (code, detail),
            VendorOutcome::Done { result, .. } => panic!("not refused: {result:?}"),
        }
    }

    async fn run_vendor(
        root: &Path,
        blobs: &Path,
        installed: &Path,
        record: &PatchRecord,
        dry_run: bool,
    ) -> VendorOutcome {
        let sources = PatchSources::blobs_only(blobs);
        vendor_maven(
            PURL,
            installed,
            root,
            record,
            &sources,
            "2026-06-09T00:00:00Z",
            dry_run,
            false,
            None,
        )
        .await
    }

    fn read_jar_entry(bytes: &[u8], name: &str) -> Option<Vec<u8>> {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).ok()?;
        let mut f = archive.by_name(name).ok()?;
        let mut out = Vec::new();
        f.read_to_end(&mut out).ok()?;
        Some(out)
    }

    #[tokio::test]
    async fn happy_path_wires_repo_jar_pom_sidecars() {
        let (dir, blobs, installed, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();

        let (result, entry, warnings) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);

        // Artifact: rebuilt jar with the patched NOTICE.txt at the maven2 leaf.
        let jar = tokio::fs::read(root.join(jar_rel())).await.unwrap();
        assert_eq!(read_jar_entry(&jar, JAR_FILE).as_deref(), Some(PATCHED));
        assert!(read_jar_entry(&jar, "META-INF/MANIFEST.MF").is_some());

        // Real upstream pom copied verbatim (carries the transitive dep).
        let pom = tokio::fs::read(root.join(format!("{}/commons-text-1.10.0.pom", leaf_rel())))
            .await
            .unwrap();
        assert_eq!(pom, UPSTREAM_POM);
        assert!(
            String::from_utf8_lossy(&pom).contains("commons-lang3"),
            "vendored pom keeps the transitive declaration"
        );

        // sha1 sidecars for both, matching the bytes.
        let jar_sha1 = tokio::fs::read_to_string(root.join(format!("{}.sha1", jar_rel())))
            .await
            .unwrap();
        assert_eq!(jar_sha1.trim(), sha1_hex(&jar));
        let pom_sha1 = tokio::fs::read_to_string(
            root.join(format!("{}/commons-text-1.10.0.pom.sha1", leaf_rel())),
        )
        .await
        .unwrap();
        assert_eq!(pom_sha1.trim(), sha1_hex(UPSTREAM_POM));

        // Marker present.
        assert!(root
            .join(format!(".socket/vendor/maven/{UUID}/{VENDOR_MARKER_FILE}"))
            .exists());

        // pom.xml wired with our <repository> (id + file:// url + checksumPolicy).
        let pom_xml = tokio::fs::read_to_string(root.join(PROJECT_POM))
            .await
            .unwrap();
        assert!(pom_xml.contains(&format!("<id>socket-patch-vendor-{UUID}</id>")));
        assert!(pom_xml.contains(&format!(
            "<url>file://${{project.basedir}}/.socket/vendor/maven/{UUID}</url>"
        )));
        assert!(pom_xml.contains("<checksumPolicy>fail</checksumPolicy>"));
        assert!(pom_xml.contains("<repositories>"));

        // The always-on shadow advisory fired.
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_maven_local_cache_shadow"),
            "shadow warning must always fire: {warnings:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_maven_local_cache_shadow"
                    && w.detail.contains("purge-local-repository")),
            "shadow warning carries the purge one-liner"
        );

        // Ledger entry shape.
        let entry = entry.expect("success carries a ledger entry");
        assert_eq!(entry.ecosystem, "maven");
        assert_eq!(entry.base_purl, PURL);
        assert_eq!(entry.artifact.path, jar_rel());
        assert_eq!(entry.wiring.len(), 1);
        assert_eq!(entry.wiring[0].kind, REPO_WIRING_KIND);
        assert_eq!(entry.wiring[0].action, WiringAction::Added);
        assert_eq!(
            entry.wiring[0].key.as_deref(),
            Some(format!("socket-patch-vendor-{UUID}").as_str())
        );
    }

    #[tokio::test]
    async fn rerun_is_idempotent_no_rerecord() {
        let (dir, blobs, installed, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();

        let (r1, e1, _) = unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
        assert!(r1.success);
        assert!(e1.is_some());
        let pom_xml1 = tokio::fs::read(root.join(PROJECT_POM)).await.unwrap();
        let jar1 = tokio::fs::read(root.join(jar_rel())).await.unwrap();

        let (r2, e2, w2) = unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
        assert!(r2.success);
        assert!(e2.is_none(), "in-sync rerun must not re-record the ledger");
        assert_eq!(
            tokio::fs::read(root.join(PROJECT_POM)).await.unwrap(),
            pom_xml1
        );
        assert_eq!(
            tokio::fs::read(root.join(jar_rel())).await.unwrap(),
            jar1,
            "re-zip is deterministic"
        );
        assert!(
            w2.iter()
                .any(|w| w.code == "vendor_maven_local_cache_shadow"),
            "shadow warning fires on the hot path too"
        );
    }

    #[tokio::test]
    async fn wired_missing_artifact_rebuilds_only() {
        let (dir, blobs, installed, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();

        let (r1, e1, _) = unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
        assert!(r1.success);
        assert!(e1.is_some());
        let pom_xml1 = tokio::fs::read(root.join(PROJECT_POM)).await.unwrap();
        let jar1 = tokio::fs::read(root.join(jar_rel())).await.unwrap();

        // Simulate the fresh-clone hole: the committed artifact is gone.
        remove_tree(&root.join(format!(".socket/vendor/maven/{UUID}")))
            .await
            .unwrap();

        let (r2, e2, w2) = unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
        assert!(r2.success, "{:?}", r2.error);
        assert!(
            e2.is_none(),
            "artifact-only rebuild must not re-record (would clobber the pre-vendor pom.xml)"
        );
        assert!(
            w2.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
            "rebuild is surfaced: {w2:?}"
        );
        assert_eq!(
            tokio::fs::read(root.join(jar_rel())).await.unwrap(),
            jar1,
            "rebuilt jar is byte-identical"
        );
        assert_eq!(
            tokio::fs::read(root.join(PROJECT_POM)).await.unwrap(),
            pom_xml1,
            "pom.xml untouched by the rebuild"
        );
    }

    #[tokio::test]
    async fn refuses_multimodule_root() {
        let multimodule = "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n\
             \x20 <modelVersion>4.0.0</modelVersion>\n\
             \x20 <groupId>com.example</groupId>\n\
             \x20 <artifactId>agg</artifactId>\n\
             \x20 <version>1.0.0</version>\n\
             \x20 <packaging>pom</packaging>\n\
             \x20 <modules>\n\
             \x20   <module>child</module>\n\
             \x20 </modules>\n\
             </project>\n";
        let (dir, blobs, installed, record) = fixture(Some(multimodule), true, true).await;
        let root = dir.path();
        let (code, _d) = unwrap_refused(run_vendor(root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "vendor_maven_multimodule_unsupported");
        assert!(!root.join(".socket").exists(), "refusal writes nothing");
    }

    #[tokio::test]
    async fn commented_modules_do_not_refuse() {
        // A commented-out <modules> must NOT trigger the aggregator refusal.
        let commented = "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n\
             \x20 <modelVersion>4.0.0</modelVersion>\n\
             \x20 <groupId>com.example</groupId>\n\
             \x20 <artifactId>app</artifactId>\n\
             \x20 <version>1.0.0</version>\n\
             \x20 <!-- <modules><module>old</module></modules> -->\n\
             </project>\n";
        let (dir, blobs, installed, record) = fixture(Some(commented), true, true).await;
        let root = dir.path();
        let (result, _e, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
        assert!(
            result.success,
            "commented <modules> must not refuse: {:?}",
            result.error
        );
    }

    #[tokio::test]
    async fn refuses_gradle_only_project() {
        // build.gradle but no pom.xml → gradle-only.
        let (dir, blobs, installed, record) = fixture(None, true, true).await;
        let root = dir.path();
        tokio::fs::write(root.join("build.gradle"), b"plugins { id 'java' }\n")
            .await
            .unwrap();
        let (code, _d) = unwrap_refused(run_vendor(root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "vendor_gradle_unsupported");
        assert!(!root.join(".socket").exists());
    }

    #[tokio::test]
    async fn refuses_pom_unavailable() {
        // pom.xml present, local jar present, but NO upstream pom (and no
        // service) → refuse rather than author a minimal pom.
        let (dir, blobs, installed, record) =
            fixture(Some(project_pom()), true, /*with_local_pom=*/ false).await;
        let root = dir.path();
        let (code, detail) =
            unwrap_refused(run_vendor(root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "vendor_maven_pom_unavailable");
        assert!(
            detail.contains("minimal pom"),
            "refusal explains why: {detail}"
        );
        assert!(
            !root.join(format!(".socket/vendor/maven/{UUID}")).exists(),
            "a partial artifact must be cleaned up on the pom refusal"
        );
        // pom.xml never wired.
        let pom_xml = tokio::fs::read_to_string(root.join(PROJECT_POM))
            .await
            .unwrap();
        assert!(!pom_xml.contains("socket-patch-vendor"));
    }

    #[tokio::test]
    async fn refuses_missing_local_jar() {
        // pom.xml + upstream pom present, but the cached jar is gone and no
        // service is configured → nothing to rebuild from.
        let (dir, blobs, installed, record) =
            fixture(Some(project_pom()), /*with_local_jar=*/ false, true).await;
        let root = dir.path();
        let (code, _d) = unwrap_refused(run_vendor(root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "vendor_maven_jar_not_found");
        assert!(!root.join(".socket").exists());
    }

    #[tokio::test]
    async fn refuses_unsafe_coordinates() {
        let (dir, blobs, installed, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let mut bad = record.clone();
        bad.uuid = "../../escape".to_string();
        let (code, _d) = unwrap_refused(run_vendor(root, &blobs, &installed, &bad, false).await);
        assert_eq!(code, "unsafe_coordinates");
        assert!(!root.join(".socket").exists(), "refusal writes nothing");

        // A traversal in the coordinate group is refused too.
        let sources = PatchSources::blobs_only(&blobs);
        let (code, _d) = unwrap_refused(
            vendor_maven(
                "pkg:maven/../evil/x@1.0.0",
                &installed,
                root,
                &record,
                &sources,
                "t",
                false,
                false,
                None,
            )
            .await,
        );
        assert_eq!(code, "unsafe_coordinates");
    }

    #[tokio::test]
    async fn dry_run_writes_nothing() {
        let (dir, blobs, installed, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let pom_before = tokio::fs::read(root.join(PROJECT_POM)).await.unwrap();

        let (result, entry, warnings) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, true).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_none(), "dry run records nothing");
        assert!(!root.join(".socket").exists(), "no artifact created");
        assert_eq!(
            tokio::fs::read(root.join(PROJECT_POM)).await.unwrap(),
            pom_before
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_maven_local_cache_shadow"),
            "dry run predicts the shadow advisory"
        );
    }

    #[tokio::test]
    async fn revert_restores_pom_byte_identical() {
        let (dir, blobs, installed, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();
        let pom_before = tokio::fs::read(root.join(PROJECT_POM)).await.unwrap();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
        assert!(result.success);
        let entry = entry.unwrap();
        assert_ne!(
            tokio::fs::read(root.join(PROJECT_POM)).await.unwrap(),
            pom_before,
            "vendor rewired pom.xml"
        );

        let outcome = revert_maven(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "clean revert must not report drift: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read(root.join(PROJECT_POM)).await.unwrap(),
            pom_before,
            "pom.xml restored byte-identically"
        );
        assert!(
            !root.join(format!(".socket/vendor/maven/{UUID}")).exists(),
            "uuid dir removed"
        );
    }

    #[tokio::test]
    async fn revert_drift_leaves_pom_alone() {
        let (dir, blobs, installed, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
        assert!(result.success);
        let entry = entry.unwrap();

        // Third-party drift: the user regenerated pom.xml without our repo.
        tokio::fs::write(root.join(PROJECT_POM), project_pom())
            .await
            .unwrap();
        let drifted = tokio::fs::read(root.join(PROJECT_POM)).await.unwrap();

        let outcome = revert_maven(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "drift must be reported: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read(root.join(PROJECT_POM)).await.unwrap(),
            drifted,
            "drifted pom.xml left alone"
        );
        assert!(
            !root.join(format!(".socket/vendor/maven/{UUID}")).exists(),
            "uuid dir still removed"
        );
    }

    #[tokio::test]
    async fn revert_excises_only_our_block_preserving_sibling() {
        // Vendor creates the <repositories> section with OUR block. Then a
        // sibling vendor run inserts ANOTHER <repository> into that same
        // section (simulated by inserting before </repositories>). Reverting
        // us must excise ONLY our block and keep the sibling's wiring intact —
        // the old whole-file restore would have wiped it.
        let (dir, blobs, installed, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
        assert!(result.success);
        let entry = entry.unwrap();

        // A sibling patch's <repository> lands in the section we created.
        let wired = tokio::fs::read_to_string(root.join(PROJECT_POM))
            .await
            .unwrap();
        let sibling = "    <repository>\n      <id>socket-patch-vendor-SIBLING</id>\n      <url>file://${project.basedir}/.socket/vendor/maven/SIBLING</url>\n    </repository>\n";
        let with_sibling = wired.replacen(
            "  </repositories>\n",
            &format!("{sibling}  </repositories>\n"),
            1,
        );
        assert_ne!(with_sibling, wired, "sibling block inserted");
        tokio::fs::write(root.join(PROJECT_POM), &with_sibling)
            .await
            .unwrap();

        let outcome = revert_maven(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "excising our block is not drift: {:?}",
            outcome.warnings
        );
        let after = tokio::fs::read_to_string(root.join(PROJECT_POM))
            .await
            .unwrap();
        assert!(
            !after.contains(&format!("socket-patch-vendor-{UUID}")),
            "our <repository> excised"
        );
        assert!(
            after.contains("socket-patch-vendor-SIBLING"),
            "sibling <repository> preserved: {after}"
        );
        // The section stays (a sibling still lives in it).
        assert_eq!(after.matches("<repositories>").count(), 1);
    }

    #[tokio::test]
    async fn revert_preserves_user_edit_made_after_vendoring() {
        // The user edits the pom AFTER vendoring (adds a <properties> block).
        // Revert must remove our <repository> (and the section we created) yet
        // keep the user's edit — the whole-file restore would have discarded it.
        let (dir, blobs, installed, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
        assert!(result.success);
        let entry = entry.unwrap();

        let wired = tokio::fs::read_to_string(root.join(PROJECT_POM))
            .await
            .unwrap();
        let user_edit = "  <properties>\n    <maven.compiler.release>17</maven.compiler.release>\n  </properties>\n";
        let edited = wired.replacen("</project>", &format!("{user_edit}</project>"), 1);
        tokio::fs::write(root.join(PROJECT_POM), &edited)
            .await
            .unwrap();

        let outcome = revert_maven(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "excising our block is not drift: {:?}",
            outcome.warnings
        );
        let after = tokio::fs::read_to_string(root.join(PROJECT_POM))
            .await
            .unwrap();
        assert!(
            !after.contains("socket-patch-vendor"),
            "our <repository> excised"
        );
        assert!(
            !after.contains("<repositories>"),
            "the section we created is removed once empty: {after}"
        );
        assert!(
            after.contains("<maven.compiler.release>17</maven.compiler.release>"),
            "user edit after vendoring preserved: {after}"
        );
    }

    #[tokio::test]
    async fn revert_warns_when_our_block_already_gone() {
        // The user regenerated the pom, dropping our block but keeping a
        // hand-written <repositories>. Our exact block is absent → drift, and
        // we must NOT touch their section.
        let (dir, blobs, installed, record) = fixture(Some(project_pom()), true, true).await;
        let root = dir.path();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
        assert!(result.success);
        let entry = entry.unwrap();

        let regenerated = "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n\
             \x20 <modelVersion>4.0.0</modelVersion>\n\
             \x20 <repositories>\n\
             \x20   <repository><id>corp</id><url>https://corp/repo</url></repository>\n\
             \x20 </repositories>\n\
             </project>\n";
        tokio::fs::write(root.join(PROJECT_POM), regenerated)
            .await
            .unwrap();

        let outcome = revert_maven(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "our block gone → drift must be reported: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(PROJECT_POM))
                .await
                .unwrap(),
            regenerated,
            "the user's regenerated pom is left alone"
        );
    }

    #[test]
    fn strip_empty_repositories_removes_created_section_only() {
        // A section left empty after excision is removed.
        let empty = "<project>\n  <repositories>\n  </repositories>\n</project>\n";
        assert_eq!(
            strip_empty_repositories(empty),
            "<project>\n</project>\n",
            "empty created section removed"
        );
        // A section still holding a sibling is kept verbatim.
        let with_sibling =
            "<project>\n  <repositories>\n    <repository><id>corp</id></repository>\n  </repositories>\n</project>\n";
        assert_eq!(
            strip_empty_repositories(with_sibling),
            with_sibling,
            "non-empty section untouched"
        );
    }

    #[test]
    fn declares_modules_boundary_and_comment_discipline() {
        assert!(declares_modules(
            "<project><modules><module>a</module></modules></project>"
        ));
        assert!(declares_modules(
            "<project>\n<modules>\n</modules>\n</project>"
        ));
        // Prefix decoy: <modulesInfo> is not <modules>.
        assert!(!declares_modules(
            "<project><modulesInfo>x</modulesInfo></project>"
        ));
        // Commented-out modules must not count.
        assert!(!declares_modules(
            "<project><!-- <modules><module>a</module></modules> --></project>"
        ));
    }

    #[test]
    fn repo_edit_extends_existing_repositories() {
        let orig = "<project>\n  <repositories>\n    <repository><id>corp</id></repository>\n  </repositories>\n</project>\n";
        let out = build_repo_edit(orig, "socket-patch-vendor-x", ".socket/vendor/maven/x").unwrap();
        // Original corp repo survives, ours added before </repositories>.
        assert!(out.contains("<id>corp</id>"));
        assert!(out.contains("<id>socket-patch-vendor-x</id>"));
        assert_eq!(out.matches("</repositories>").count(), 1);
    }

    #[test]
    fn repo_edit_creates_repositories_section() {
        let orig = "<project>\n  <artifactId>app</artifactId>\n</project>\n";
        let out = build_repo_edit(orig, "socket-patch-vendor-x", ".socket/vendor/maven/x").unwrap();
        assert!(out.contains("<repositories>"));
        assert!(out.contains("</repositories>"));
        assert!(out.contains("<id>socket-patch-vendor-x</id>"));
        assert!(out.trim_end().ends_with("</project>"));
    }

    #[test]
    fn group_id_path_and_safety() {
        assert_eq!(group_id_to_path("org.apache.commons"), "org/apache/commons");
        assert!(is_safe_group_id("org.apache.commons"));
        assert!(!is_safe_group_id(""));
        assert!(!is_safe_group_id(".org"));
        assert!(!is_safe_group_id("org."));
        assert!(!is_safe_group_id("a..b"));
        assert!(!is_safe_group_id("a/b"));
        assert!(!is_safe_group_id("a:b"));
    }
}
