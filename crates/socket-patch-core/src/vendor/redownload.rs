use std::path::Path;

use sha2::{Digest, Sha256};

use crate::manifest::schema::PatchRecord;
use crate::utils::purl::{
    parse_cargo_purl, parse_composer_purl, parse_gem_purl, parse_golang_purl, parse_maven_purl,
};

use super::common::{copy_matches_after_hashes, swap_stage_into_place};
use super::jvm::layout;
use super::service_fetch::{fetch_verified_archive, ServicePolicy, VerifiedArchive};
use super::state::VendorEntry;
use super::{VendorOutcome, VendorServiceConfig, VendorWarning};

fn detail(outcome: VendorOutcome) -> String {
    match outcome {
        VendorOutcome::Refused { code, detail } => format!("{code}: {detail}"),
        VendorOutcome::Done { result, .. } => result
            .error
            .unwrap_or_else(|| "artifact download failed".into()),
    }
}

async fn download_archive(
    service: &VendorServiceConfig,
    record: &PatchRecord,
    noun: &str,
    subject: &str,
) -> Result<VerifiedArchive, String> {
    ServicePolicy::Refused
        .settle(
            fetch_verified_archive(service, &record.uuid).await,
            noun,
            subject,
        )
        .map_err(|outcome| detail(*outcome))
}

// Without the ledger's fingerprint no download can be proven to be the
// recorded artifact. A dir copy with no inventory is rebuilt from a fresh
// verified download by re-running the vendoring command; a file artifact
// with no SHA-256 needs a revert first (it reverts every vendored package),
// so the next vendoring run downloads afresh and records a new fingerprint.
fn no_archive_sha256() -> String {
    format!(
        "the ledger has no archive SHA-256; restore it from version control, or {}",
        super::common::REVERT_ALL_AND_REVENDOR
    )
}
const NO_FILE_INVENTORY: &str = "the ledger has no complete file inventory; restore it from \
     version control, or re-run the vendoring command (`socket-patch vendor`, or `scan --mode \
     vendored`) to rebuild it from a verified download";

/// Restore only the recorded artifact. Project wiring and ledger are never written.
pub async fn restore(
    root: &Path,
    entry: &VendorEntry,
    record: &PatchRecord,
    service: &VendorServiceConfig,
) -> Result<Vec<VendorWarning>, String> {
    let ecosystem = super::ecosystem_dir_for_purl(&entry.base_purl);
    if ecosystem != Some(layout::ledger_ecosystem(&entry.ecosystem)) {
        return Err("ledger package identity does not match its artifact ecosystem".into());
    }
    // The download would land in (and repair would vouch for) a store this
    // project does not own; see `path::vendor_dir_symlink`.
    if let Some(link) = super::path::vendor_dir_symlink(root, &entry.ecosystem, Some(&entry.uuid)) {
        return Err(format!(
            "vendor_dir_symlink_unsupported: {}",
            super::path::vendor_dir_symlink_detail(&link)
        ));
    }
    if let Some(outcome) = super::common::service_offline_conflict(Some(service)) {
        return Err(detail(outcome));
    }
    // A JVM tree belongs to its build root: repairing from a subproject
    // would restore it where the real build never looks (#428).
    if entry.ecosystem == layout::LEDGER_ECOSYSTEM {
        if let Some(detail) = super::maven_repo::not_build_root(root) {
            return Err(format!("vendor_jvm_shape_unsupported: {detail}"));
        }
    }
    let artifact = match super::verify::checked_artifact_path(root, entry, record) {
        Ok(path) => path,
        Err(reason)
            if entry.ecosystem == layout::LEDGER_ECOSYSTEM
                && matches!(
                    reason.as_str(),
                    "vendor_artifact_missing" | "vendor_artifact_unreadable"
                ) =>
        {
            root.join(super::jvm::apply::checked_tree_jar_path(
                root,
                entry,
                &record.uuid,
            )?)
        }
        Err(reason) => return Err(reason),
    };
    if crate::utils::containment::linked_level(root, &root.join(&entry.artifact.path)).is_some() {
        return Err("vendor_path_unsafe: artifact path contains a symlink".into());
    }
    let file_shaped = !super::verify::is_vlt_dir_entry(entry)
        && super::verify::artifact_is_file_shaped(&entry.artifact.path);
    if file_shaped && entry.artifact.sha256.is_empty() {
        return Err(no_archive_sha256());
    }
    if !file_shaped && entry.artifact.file_inventory.is_none() {
        return Err(NO_FILE_INVENTORY.into());
    }
    let socket = root.join(".socket");
    tokio::fs::create_dir_all(&socket)
        .await
        .map_err(|e| e.to_string())?;
    let temporary = tempfile::Builder::new()
        .prefix(".artifact-download-")
        .tempdir_in(&socket)
        .map_err(|e| e.to_string())?;
    let stage = temporary.path().join(&entry.artifact.path);
    let uuid_dir = stage.parent().ok_or("artifact has no parent")?;
    let mut warnings = Vec::new();
    // The JVM tree directories the stage holds besides the artifact's own.
    let mut jvm_trees: Vec<String> = Vec::new();
    if file_shaped {
        let archive = download_archive(
            service,
            record,
            "archive",
            &format!("archive for {}", entry.base_purl),
        )
        .await?;
        if entry.artifact.sha256.is_empty()
            || !hex::encode(Sha256::digest(&archive.bytes))
                .eq_ignore_ascii_case(&entry.artifact.sha256)
        {
            return Err("the downloaded artifact does not match the recorded SHA-256; the existing artifact, lockfiles and ledger were preserved".into());
        }
        if entry
            .artifact
            .size
            .is_some_and(|size| size != archive.bytes.len() as u64)
        {
            return Err("the downloaded artifact does not match the recorded size".into());
        }
        let members = if entry.ecosystem == "pypi" {
            super::pypi_distribution::read_members(&archive.bytes, &entry.artifact.path)?
        } else if entry.artifact.path.ends_with(".tgz") || entry.artifact.path.ends_with(".tar.gz")
        {
            crate::patch::package::read_archive_bytes_to_map_strict(&archive.bytes)
                .map_err(|e| e.to_string())?
        } else {
            super::verify::read_zip_bytes_to_map_strict(&archive.bytes)?
        };
        if entry.ecosystem == "pypi" {
            super::pypi_distribution::verify_members(&members, &entry.artifact.path, record)?;
        } else {
            super::verify::verify_member_map(&members, record)?;
        }
        tokio::fs::create_dir_all(uuid_dir)
            .await
            .map_err(|e| e.to_string())?;
        crate::utils::fs::atomic_write_artifact(&stage, &archive.bytes)
            .await
            .map_err(|e| e.to_string())?;
        if layout::ledger_ecosystem(&entry.ecosystem) == "maven" {
            jvm_trees = restore_maven_metadata(
                root,
                temporary.path(),
                entry,
                record,
                &archive.bytes,
                service,
            )
            .await?;
        }
    } else {
        match entry.ecosystem.as_str() {
            "cargo" => {
                let (name, version) =
                    parse_cargo_purl(&entry.base_purl).ok_or("invalid cargo coordinates")?;
                super::cargo::cargo_service_copy(
                    Some(service),
                    record,
                    &name,
                    &version,
                    &stage,
                    uuid_dir,
                    &mut warnings,
                )
                .await
                .map_err(|outcome| detail(*outcome))?;
            }
            "composer" => {
                let ((namespace, name), _) =
                    parse_composer_purl(&entry.base_purl).ok_or("invalid composer coordinates")?;
                let package = format!("{namespace}/{name}");
                super::composer_lock::composer_service_copy(
                    Some(service),
                    record,
                    &package,
                    &stage,
                    uuid_dir,
                    &mut warnings,
                )
                .await
                .map_err(|outcome| detail(*outcome))?;
                super::composer_lock::mirror_filters::neutralize_or_conflict(
                    &stage,
                    record,
                    &package,
                    &mut warnings,
                )
                .await?;
            }
            "gem" => {
                let (name, _) =
                    parse_gem_purl(&entry.base_purl).ok_or("invalid gem coordinates")?;
                super::gem::gem_service_copy(
                    Some(service),
                    record,
                    &name,
                    &stage,
                    uuid_dir,
                    true,
                    &mut warnings,
                )
                .await
                .map_err(|outcome| detail(*outcome))?;
            }
            "npm" => {
                let (name, version) = super::npm_common::parse_npm_purl(&entry.base_purl)
                    .ok_or("invalid npm coordinates")?;
                super::npm_dir::try_service_dir(
                    &entry.base_purl,
                    record,
                    service,
                    &stage,
                    &name,
                    &version,
                    &mut warnings,
                )
                .await
                .map_err(|outcome| detail(*outcome))?;
                super::npm_dir::apply_transforms(&stage, &name, &version)
                    .await
                    .map_err(|outcome| detail(*outcome))?;
            }
            "golang" => {
                let (module, version) =
                    parse_golang_purl(&entry.base_purl).ok_or("invalid Go coordinates")?;
                let archive = download_archive(
                    service,
                    record,
                    "module zip",
                    &format!("module zip for {module}"),
                )
                .await?;
                let prefix = format!("{module}@{version}/");
                tokio::fs::create_dir_all(&stage)
                    .await
                    .map_err(|e| e.to_string())?;
                super::registry_fetch::extract_on_blocking_pool(
                    archive.bytes,
                    &stage,
                    move |bytes, dest| {
                        super::registry_fetch::extract_zip_with_prefix(bytes, dest, &prefix)
                    },
                )
                .await?;
                crate::patch::redirect::golang_local::ensure_module_go_mod(&stage, &module)
                    .await
                    .map_err(|e| e.to_string())?;
                if !copy_matches_after_hashes(&stage, &record.files).await {
                    return Err("server module does not carry the patched files".into());
                }
            }
            _ => {
                return Err(format!(
                    "unsupported artifact ecosystem {}",
                    entry.ecosystem
                ))
            }
        }
        {
            let inventory = entry
                .artifact
                .file_inventory
                .as_ref()
                .ok_or(NO_FILE_INVENTORY)?;
            let uuid = (entry.ecosystem == "cargo").then_some(entry.uuid.as_str());
            super::verify::verify_dir_inventory(&stage, inventory, uuid).await?;
        }
    }
    if layout::ledger_ecosystem(&entry.ecosystem) == "maven" {
        let target = artifact.parent().ok_or("artifact has no parent")?;
        tokio::fs::create_dir_all(target.parent().ok_or("artifact tree has no parent")?)
            .await
            .map_err(|e| e.to_string())?;
        swap_stage_into_place(uuid_dir, target)
            .await
            .map_err(|e| e.to_string())?;
        // A mixed root's other tree (the Gradle one beside the Maven jar).
        for rel in &jvm_trees {
            let (stage_dir, target) = (temporary.path().join(rel), root.join(rel));
            if stage_dir == uuid_dir || !stage_dir.is_dir() {
                continue;
            }
            // Same guard as the artifact's own path: never swap a tree
            // reached through a link (the swap deletes what it replaces).
            if crate::utils::containment::linked_level(root, &root.join(rel)).is_some() {
                return Err("vendor_path_unsafe: artifact path contains a symlink".into());
            }
            tokio::fs::create_dir_all(target.parent().ok_or("tree has no parent")?)
                .await
                .map_err(|e| e.to_string())?;
            swap_stage_into_place(&stage_dir, &target)
                .await
                .map_err(|e| e.to_string())?;
        }
        if entry.ecosystem == layout::LEDGER_ECOSYSTEM {
            restore_jvm_owned_files(root, entry).await?;
        }
    } else {
        if let Some(parent) = artifact.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| e.to_string())?;
        }
        let original_uuid =
            super::path::vendor_uuid_dir_rel("npm", &entry.uuid).map(|rel| root.join(rel));
        if let Some(original) = &original_uuid {
            if let Some(warning) =
                super::vlt_lock::keep_vlt_links(entry, original, temporary.path()).await
            {
                warnings.push(warning);
            }
        }
        let swapped = if file_shaped {
            let result = tokio::fs::rename(&stage, &artifact).await;
            if result.is_ok() {
                crate::utils::durability::moved(&stage, &artifact);
            }
            result
        } else {
            swap_stage_into_place(&stage, &artifact).await
        };
        if let Err(error) = swapped {
            if let Some(rel) = super::path::vendor_uuid_dir_rel("npm", &entry.uuid) {
                let _ =
                    super::vlt_lock::keep_vlt_links(entry, &temporary.path().join(rel), root).await;
            }
            return Err(error.to_string());
        }
    }
    if super::verify::is_vlt_dir_entry(entry) {
        super::vlt_lock::restore_vlt_uuid_metadata(entry, root)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(warnings)
}

/// Stage the entry's whole recorded JVM tree under `stage_root` from the
/// verified jar and freshly downloaded, checksum-verified upstream files,
/// re-planned through the project's builds (both halves of a mixed root).
/// Returns the staged tree directories (project-relative).
async fn restore_maven_metadata(
    root: &Path,
    stage_root: &Path,
    entry: &VendorEntry,
    record: &PatchRecord,
    jar: &[u8],
    service: &VendorServiceConfig,
) -> Result<Vec<String>, String> {
    let (group, artifact, version) =
        parse_maven_purl(&entry.base_purl).ok_or("invalid Maven coordinates")?;
    let empty_cache = stage_root.join("upstream");
    let pom = super::maven_repo::acquire_jvm_metadata(
        &empty_cache,
        &group,
        &artifact,
        &version,
        "pom",
        Some(service),
    )
    .await?;
    let target = stage_root.join(&entry.artifact.path);
    if entry.ecosystem == "maven" {
        super::maven_repo::write_maven_artifact(
            target.parent().ok_or("artifact has no parent")?,
            &format!("{artifact}-{version}.jar"),
            jar,
            &format!("{artifact}-{version}.pom"),
            &pom,
        )
        .await?;
        return Ok(Vec::new());
    }
    let module = if entry
        .wiring
        .iter()
        .any(|w| w.kind == super::jvm::TREE_KIND && w.file.ends_with(".module"))
    {
        Some(
            super::maven_repo::acquire_jvm_metadata(
                &empty_cache,
                &group,
                &artifact,
                &version,
                "module",
                Some(service),
            )
            .await?,
        )
    } else {
        None
    };
    // The classifier artifacts the tree recorded (#533), downloaded again
    // and checked against their upstream checksums.
    let mut extras = Vec::new();
    let gradle_tree = format!("{}/", super::jvm::layout::GRADLE_TREE);
    for w in entry
        .wiring
        .iter()
        .filter(|w| w.kind == super::jvm::TREE_KIND && w.file.starts_with(&gradle_tree))
    {
        let name = w.file.rsplit('/').next().unwrap_or_default();
        let Some(rest) = name.strip_prefix(&format!("{artifact}-{version}-")) else {
            continue;
        };
        let Some((classifier, extension)) = rest.rsplit_once('.') else {
            continue;
        };
        if extras
            .iter()
            .any(|x: &super::jvm::ExtraArtifact| x.classifier == classifier)
        {
            continue;
        }
        let gav = (group.to_string(), artifact.to_string(), version.to_string());
        let bytes = super::maven_repo::acquire_jvm_artifact(
            &super::maven_repo::LocalSources::none(),
            &gav,
            Some(classifier),
            extension,
            Some(service),
        )
        .await?;
        extras.push(super::jvm::ExtraArtifact {
            classifier: classifier.to_string(),
            extension: extension.to_string(),
            bytes,
        });
    }
    let patched: Vec<String> = record.files.keys().cloned().collect();
    let patch = super::jvm::JvmPatch {
        group_id: &group,
        artifact_id: &artifact,
        version: &version,
        uuid: &record.uuid,
        jar,
        upstream_pom: &pom,
        upstream_module: module.as_deref(),
        extra_artifacts: &extras,
        patched_members: &patched,
    };
    let reader = super::jvm::apply::ProjectReader::new(root);
    let read = |rel: &str| {
        if rel.starts_with(".socket/vendor/") {
            None
        } else {
            reader.read(rel)
        }
    };
    let list = |dir: &str| reader.list(dir);
    // Re-planned through every build the root holds (#395).
    let shape = super::jvm::detect(&read);
    let enabled = !entry
        .wiring
        .iter()
        .any(|w| super::jvm::op_of(w) == "config_none");
    let plan =
        super::jvm::plan_with_config(shape, &read, &list, &patch, enabled).map_err(|e| e.detail)?;
    if reader.escaped().is_some() {
        return Err("Maven project path escapes the checkout".into());
    }
    let tree: Vec<_> = plan.writes.into_iter().filter(|w| w.tree).collect();
    let mut dirs: Vec<String> = tree
        .iter()
        .filter_map(|w| w.rel.rsplit_once('/').map(|(d, _)| d.to_string()))
        .collect();
    dirs.sort();
    dirs.dedup();
    if tree.len()
        != entry
            .wiring
            .iter()
            .filter(|w| w.kind == super::jvm::TREE_KIND)
            .count()
    {
        return Err("download did not reproduce the complete recorded JVM tree".into());
    }
    for write in tree {
        let expected = entry
            .wiring
            .iter()
            .find(|w| w.kind == super::jvm::TREE_KIND && w.file == write.rel)
            .and_then(|w| w.new.as_ref())
            .and_then(serde_json::Value::as_str)
            .ok_or("download produced an unrecorded JVM tree file")?;
        if hex::encode(Sha256::digest(&write.bytes)) != expected {
            return Err("downloaded JVM metadata does not match the recorded tree".into());
        }
        let path = stage_root.join(&write.rel);
        tokio::fs::create_dir_all(path.parent().ok_or("tree file has no parent")?)
            .await
            .map_err(|e| e.to_string())?;
        crate::utils::fs::atomic_write_artifact(&path, &write.bytes)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(dirs)
}

/// The owned files a Gradle tree needs beside its directory: the derived
/// `maven-metadata.xml` (recomputed from the committed index) and the
/// `.gitattributes` the entry created, rewritten when missing. Needs no
/// download, so `repair` also runs it for a healthy entry.
pub async fn restore_jvm_owned_files(root: &Path, entry: &VendorEntry) -> Result<(), String> {
    use super::jvm::gradle;
    let Some((group, artifact, _)) = parse_maven_purl(&entry.base_purl) else {
        return Ok(());
    };
    let reader = super::jvm::apply::ProjectReader::new(root);
    let read = |rel: &str| reader.read(rel);
    let mut wanted: Vec<(String, String)> = Vec::new();
    if entry
        .wiring
        .iter()
        .any(|w| w.kind == super::jvm::DERIVED_METADATA_KIND)
    {
        if let Some(text) = gradle::derived_metadata_of(&read, &group, &artifact) {
            wanted.push((gradle::derived_metadata_rel(&group, &artifact), text));
        }
    }
    let created = |rel: &str| {
        entry.wiring.iter().any(|w| {
            w.kind == super::jvm::OWNED_FILE_KIND
                && w.file == rel
                && super::jvm::op_of(w) == "create"
        })
    };
    for rel in [gradle::GITATTRIBUTES_REL, gradle::SCRIPT_GITATTRIBUTES_REL] {
        if created(rel) {
            wanted.push((rel.to_string(), "* -text\n".to_string()));
        }
    }
    if created(gradle::VENDOR_GITATTRIBUTES_REL) {
        wanted.push((
            gradle::VENDOR_GITATTRIBUTES_REL.to_string(),
            format!("{}\n", gradle::VENDOR_GITATTRIBUTES_LINE),
        ));
    }
    for (rel, text) in wanted {
        let current = read(&rel);
        if current
            .as_deref()
            .is_some_and(|c| crate::utils::line_endings::eol_eq(c, text.as_bytes()))
        {
            continue;
        }
        // Only a missing file is ours to write; an edited one stays.
        if current.is_some() || reader.escaped().is_some() {
            continue;
        }
        let path = root.join(&rel);
        tokio::fs::create_dir_all(path.parent().ok_or("owned file has no parent")?)
            .await
            .map_err(|e| e.to_string())?;
        crate::utils::fs::atomic_write_bytes_preserving_mode(&path, text.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::vendor::state::VendorArtifact;
    use crate::vendor::test_support::{mount_granted, service_cfg, tree_snapshot};
    use crate::vendor::VendorSource;
    use std::collections::HashMap;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    fn record() -> PatchRecord {
        serde_json::from_value(serde_json::json!({
            "uuid": UUID, "exportedAt": "2026-09-30T00:00:00Z",
            "files": {"index.js": {"beforeHash": "before", "afterHash": compute_git_sha256_from_bytes(b"patched")}},
            "vulnerabilities": {}, "description": "", "license": "", "tier": ""
        })).unwrap()
    }

    fn tgz(prefix: &str, extra: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut tar = tar::Builder::new(Vec::new());
        for (name, bytes) in [("index.js", b"patched".as_slice()), ("extra", extra)] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, format!("{prefix}/{name}"), bytes)
                .unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar.into_inner().unwrap()).unwrap();
        gz.finish().unwrap()
    }

    fn entry(bytes: &[u8]) -> VendorEntry {
        VendorEntry {
            detached: true,
            record: Some(record()),
            flavor: Some("npm".into()),
            ..VendorEntry::new(
                "npm".into(),
                "pkg:npm/example@1.0.0".into(),
                UUID.into(),
                VendorArtifact {
                    path: format!(".socket/vendor/npm/{UUID}/example-1.0.0.tgz"),
                    sha256: hex::encode(Sha256::digest(bytes)),
                    size: Some(bytes.len() as u64),
                    platform_locked: None,
                    file_inventory: None,
                    yarn_berry10c0: None,
                },
                Vec::new(),
            )
        }
    }

    #[tokio::test]
    async fn repair_redownloads_exact_bytes_without_changing_wiring_or_ledger() {
        let root = tempfile::tempdir().unwrap();
        let bytes = tgz("package", b"original unpatched member");
        let entry = entry(&bytes);
        let path = root.path().join(&entry.artifact.path);
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&path, b"corrupt").await.unwrap();
        tokio::fs::write(root.path().join("package-lock.json"), b"original lock")
            .await
            .unwrap();
        tokio::fs::write(
            root.path().join(".socket/vendor/state.json"),
            serde_json::to_vec(&entry).unwrap(),
        )
        .await
        .unwrap();
        let server = wiremock::MockServer::start().await;
        mount_granted(&server, UUID, "example-1.0.0.tgz", &bytes).await;
        let cfg = service_cfg(&server.uri(), VendorSource::Service, false);
        restore(root.path(), &entry, &record(), &cfg).await.unwrap();
        assert_eq!(tokio::fs::read(&path).await.unwrap(), bytes);
        assert_eq!(
            tokio::fs::read(root.path().join("package-lock.json"))
                .await
                .unwrap(),
            b"original lock"
        );
        assert_eq!(
            tokio::fs::read(root.path().join(".socket/vendor/state.json"))
                .await
                .unwrap(),
            serde_json::to_vec(&entry).unwrap()
        );
        tokio::fs::remove_file(&path).await.unwrap();
        restore(root.path(), &entry, &record(), &cfg).await.unwrap();
        assert_eq!(tokio::fs::read(path).await.unwrap(), bytes);
    }

    /// #664: repair never downloads into a linked eco dir, whose target
    /// may be another project's vendor store.
    #[cfg(unix)]
    #[tokio::test]
    async fn linked_vendor_dir_refuses_without_downloading() {
        let root = tempfile::tempdir().unwrap();
        let shared = tempfile::tempdir().unwrap();
        let bytes = tgz("package", b"pinned");
        let entry = entry(&bytes);
        tokio::fs::create_dir_all(root.path().join(".socket/vendor"))
            .await
            .unwrap();
        std::os::unix::fs::symlink(shared.path(), root.path().join(".socket/vendor/npm")).unwrap();
        let server = wiremock::MockServer::start().await;
        mount_granted(&server, UUID, "example-1.0.0.tgz", &bytes).await;
        let cfg = service_cfg(&server.uri(), VendorSource::Service, false);
        let error = restore(root.path(), &entry, &record(), &cfg)
            .await
            .unwrap_err();
        assert!(
            error.starts_with("vendor_dir_symlink_unsupported"),
            "{error}"
        );
        assert!(server.received_requests().await.unwrap().is_empty());
        assert_eq!(std::fs::read_dir(shared.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn missing_archive_digest_refuses_without_downloading_or_mutating() {
        let root = tempfile::tempdir().unwrap();
        let bytes = tgz("package", b"pinned");
        let mut entry = entry(&bytes);
        entry.artifact.sha256.clear();
        let path = root.path().join(&entry.artifact.path);
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&path, b"existing").await.unwrap();
        let before = tree_snapshot(root.path());
        let server = wiremock::MockServer::start().await;
        mount_granted(&server, UUID, "example-1.0.0.tgz", &bytes).await;
        let cfg = service_cfg(&server.uri(), VendorSource::Service, false);
        let error = restore(root.path(), &entry, &record(), &cfg)
            .await
            .unwrap_err();
        assert!(error.contains("no archive SHA-256"), "{error}");
        assert!(
            error.contains(super::super::common::REVERT_ALL_AND_REVENDOR),
            "the refusal names the remedy that records a new fingerprint: {error}"
        );
        assert!(server.received_requests().await.unwrap().is_empty());
        assert_eq!(tree_snapshot(root.path()), before);
    }

    #[tokio::test]
    async fn changed_archive_and_missing_service_preserve_the_existing_tree() {
        let root = tempfile::tempdir().unwrap();
        let bytes = tgz("package", b"pinned");
        let entry = entry(&bytes);
        let path = root.path().join(&entry.artifact.path);
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(path, b"corrupt but recoverable")
            .await
            .unwrap();
        let before = tree_snapshot(root.path());
        let server = wiremock::MockServer::start().await;
        mount_granted(
            &server,
            UUID,
            "example-1.0.0.tgz",
            &tgz("package", b"different unpatched content"),
        )
        .await;
        let cfg = service_cfg(&server.uri(), VendorSource::Service, false);
        assert!(restore(root.path(), &entry, &record(), &cfg)
            .await
            .unwrap_err()
            .contains("recorded SHA-256"));
        assert_eq!(tree_snapshot(root.path()), before);
        server.reset().await;
        crate::vendor::test_support::mount_503(&server).await;
        assert!(restore(root.path(), &entry, &record(), &cfg).await.is_err());
        assert_eq!(tree_snapshot(root.path()), before);
        let offline = service_cfg(&server.uri(), VendorSource::Service, true);
        server.reset().await;
        assert!(restore(root.path(), &entry, &record(), &offline)
            .await
            .is_err());
        assert!(server.received_requests().await.unwrap().is_empty());
        assert_eq!(tree_snapshot(root.path()), before);
    }

    #[tokio::test]
    async fn recorded_digest_cannot_override_patch_member_verification() {
        let root = tempfile::tempdir().unwrap();
        let bytes = tgz("package", b"pinned");
        let entry = entry(&bytes);
        let mut record = record();
        record.files.get_mut("index.js").unwrap().after_hash =
            compute_git_sha256_from_bytes(b"different patch");
        let server = wiremock::MockServer::start().await;
        mount_granted(&server, UUID, "example-1.0.0.tgz", &bytes).await;
        assert!(restore(
            root.path(),
            &entry,
            &record,
            &service_cfg(&server.uri(), VendorSource::Service, false)
        )
        .await
        .unwrap_err()
        .contains("hash_mismatch"));
        assert!(!root.path().join(&entry.artifact.path).exists());
    }

    #[tokio::test]
    async fn directory_repair_keeps_the_recorded_inventory() {
        let root = tempfile::tempdir().unwrap();
        let bytes = tgz("package", b"pinned");
        let mut entry = entry(&bytes);
        entry.ecosystem = "composer".into();
        entry.base_purl = "pkg:composer/example/library@1.0.0".into();
        entry.flavor = None;
        entry.artifact.path = format!(".socket/vendor/composer/{UUID}/example-library");
        entry.artifact.sha256.clear();
        entry.artifact.size = None;
        entry.artifact.file_inventory = Some(
            HashMap::from([
                ("index.js".into(), hex::encode(Sha256::digest(b"patched"))),
                ("extra".into(), hex::encode(Sha256::digest(b"pinned"))),
            ])
            .into_iter()
            .collect(),
        );
        let path = root.path().join(&entry.artifact.path);
        tokio::fs::create_dir_all(&path).await.unwrap();
        tokio::fs::write(path.join("index.js"), b"broken")
            .await
            .unwrap();
        let before = tree_snapshot(root.path());
        let server = wiremock::MockServer::start().await;
        for (extra, expected_ok) in [(b"changed".as_slice(), false), (b"pinned".as_slice(), true)] {
            server.reset().await;
            let archive = super::super::common::write_zip_entries(&[
                ("package/index.js".into(), b"patched".to_vec(), 0o644),
                ("package/extra".into(), extra.to_vec(), 0o644),
            ])
            .unwrap();
            mount_granted(&server, UUID, "dist.zip", &archive).await;
            let result = restore(
                root.path(),
                &entry,
                &record(),
                &service_cfg(&server.uri(), VendorSource::Service, false),
            )
            .await;
            assert_eq!(result.is_ok(), expected_ok, "{result:?}");
            if !expected_ok {
                assert_eq!(tree_snapshot(root.path()), before);
            }
        }
        assert_eq!(
            tokio::fs::read(path.join("extra")).await.unwrap(),
            b"pinned"
        );
        let before = tree_snapshot(root.path());
        entry.artifact.file_inventory = None;
        server.reset().await;
        let error = restore(
            root.path(),
            &entry,
            &record(),
            &service_cfg(&server.uri(), VendorSource::Service, false),
        )
        .await
        .unwrap_err();
        assert!(error.contains("no complete file inventory"), "{error}");
        assert!(
            error.contains("re-run the vendoring command"),
            "the refusal names the remedy that rebuilds the copy: {error}"
        );
        assert!(
            !error.contains("--revert"),
            "no revert is needed for a dir copy: {error}"
        );
        assert!(server.received_requests().await.unwrap().is_empty());
        assert_eq!(tree_snapshot(root.path()), before);
        entry.ecosystem = "npm".into();
        assert!(restore(
            root.path(),
            &entry,
            &record(),
            &service_cfg(&server.uri(), VendorSource::Service, false)
        )
        .await
        .unwrap_err()
        .contains("identity"));
        assert_eq!(tree_snapshot(root.path()), before);
    }
    #[tokio::test]
    async fn go_restore_uses_shared_service_policy_without_mutating_the_tree() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let root = tempfile::tempdir().unwrap();
        let mut entry = entry(b"unused");
        entry.ecosystem = "golang".into();
        entry.base_purl = "pkg:golang/example.com/library@v1.0.0".into();
        entry.flavor = None;
        entry.artifact.path = format!(".socket/vendor/golang/{UUID}/example.com/library@v1.0.0");
        entry.artifact.sha256.clear();
        entry.artifact.size = None;
        entry.artifact.file_inventory = Some(Default::default());
        let copy = root.path().join(&entry.artifact.path);
        tokio::fs::create_dir_all(&copy).await.unwrap();
        tokio::fs::write(copy.join("index.js"), b"existing bytes")
            .await
            .unwrap();
        tokio::fs::write(root.path().join("go.mod"), b"module consumer\n")
            .await
            .unwrap();
        let before = tree_snapshot(root.path());
        let server = wiremock::MockServer::start().await;
        let cfg = service_cfg(&server.uri(), VendorSource::Service, false);
        for (status, expected) in [
            (
                "pending_build",
                "vendor_prebuilt_required: prebuilt module zip is still building",
            ),
            (
                "not_found",
                "vendor_prebuilt_required: prebuilt module zip unavailable",
            ),
            (
                "transport",
                "vendor_prebuilt_required: patch service request failed",
            ),
            ("tampered", "vendor_prebuilt_integrity_mismatch"),
        ] {
            server.reset().await;
            if status == "transport" {
                crate::vendor::test_support::mount_503(&server).await;
            } else if status == "tampered" {
                mount_granted(&server, UUID, "v1.0.0.zip", b"promised bytes").await;
                Mock::given(method("GET"))
                    .and(path(format!("/serve/{UUID}/v1.0.0.zip")))
                    .respond_with(
                        ResponseTemplate::new(200).set_body_bytes(b"different bytes".to_vec()),
                    )
                    .with_priority(1)
                    .mount(&server)
                    .await;
            } else {
                Mock::given(method("POST"))
                    .and(path(crate::vendor::test_support::PACKAGE_PATH))
                    .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "results": { UUID: { "status": status } }
                    })))
                    .mount(&server)
                    .await;
            }
            let error = restore(root.path(), &entry, &record(), &cfg)
                .await
                .unwrap_err();
            assert!(error.contains(expected), "{status}: {error}");
            assert_eq!(tree_snapshot(root.path()), before, "{status}");
        }
    }
}
