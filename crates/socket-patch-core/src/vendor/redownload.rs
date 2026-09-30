use std::path::Path;

use sha2::{Digest, Sha256};

use crate::manifest::schema::PatchRecord;
use crate::utils::purl::{
    parse_cargo_purl, parse_composer_purl, parse_gem_purl, parse_golang_purl, parse_maven_purl,
};

use super::common::{copy_matches_after_hashes, swap_stage_into_place};
use super::service_fetch::{fetch_verified_archive, ServiceArtifact, ServiceAttempt};
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

fn used<T>(attempt: ServiceAttempt<T>) -> Result<T, String> {
    match attempt {
        ServiceAttempt::Used(value) => Ok(value),
        ServiceAttempt::HardFail(outcome) => Err(detail(*outcome)),
    }
}

/// Restore only the recorded artifact. Project wiring and ledger are never written.
pub async fn restore(
    root: &Path,
    entry: &VendorEntry,
    record: &PatchRecord,
    service: &VendorServiceConfig,
) -> Result<Vec<VendorWarning>, String> {
    let ecosystem = super::ecosystem_dir_for_purl(&entry.base_purl);
    if ecosystem != Some(entry.ecosystem.as_str())
        && !(ecosystem == Some("maven") && entry.ecosystem == "jvm")
    {
        return Err("ledger package identity does not match its artifact ecosystem".into());
    }
    if let Some(outcome) = super::common::service_offline_conflict(Some(service)) {
        return Err(detail(outcome));
    }
    let artifact = match super::verify::checked_artifact_path(root, entry, record) {
        Ok(path) => path,
        Err(reason)
            if entry.ecosystem == "jvm"
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
    let mut cursor = root.to_path_buf();
    for part in entry.artifact.path.split('/') {
        cursor.push(part);
        if tokio::fs::symlink_metadata(&cursor)
            .await
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            return Err("vendor_path_unsafe: artifact path contains a symlink".into());
        }
    }
    let file_shaped = !super::verify::is_vlt_dir_entry(entry)
        && super::verify::artifact_is_file_shaped(&entry.artifact.path);
    if file_shaped && entry.artifact.sha256.is_empty() {
        return Err("the ledger has no archive SHA-256; restore from version control or explicitly re-vendor".into());
    }
    if !file_shaped && entry.artifact.file_inventory.is_none() {
        return Err("the ledger has no complete file inventory; restore from version control or explicitly re-vendor".into());
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
    if file_shaped {
        let archive = match fetch_verified_archive(service, &record.uuid).await {
            ServiceArtifact::Ready(archive) => archive,
            ServiceArtifact::Pending => {
                return Err("the server artifact is still building; retry once it is ready".into())
            }
            ServiceArtifact::Unavailable(reason)
            | ServiceArtifact::Failed(reason)
            | ServiceArtifact::IntegrityMismatch(reason) => return Err(reason),
        };
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
        if entry.ecosystem == "maven" || entry.ecosystem == "jvm" {
            restore_maven_metadata(
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
                used(
                    super::cargo::cargo_service_copy(
                        Some(service),
                        record,
                        &name,
                        &version,
                        &stage,
                        uuid_dir,
                        &mut warnings,
                    )
                    .await,
                )?;
            }
            "composer" => {
                let ((namespace, name), _) =
                    parse_composer_purl(&entry.base_purl).ok_or("invalid composer coordinates")?;
                let package = format!("{namespace}/{name}");
                used(
                    super::composer_lock::composer_service_copy(
                        Some(service),
                        record,
                        &package,
                        &stage,
                        uuid_dir,
                        &mut warnings,
                    )
                    .await,
                )?;
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
                match super::gem::gem_service_copy(
                    Some(service),
                    record,
                    &name,
                    &stage,
                    uuid_dir,
                    true,
                    &mut warnings,
                )
                .await
                {
                    super::gem::GemServiceCopy::Used => {}
                    super::gem::GemServiceCopy::HardFail(outcome) => return Err(detail(*outcome)),
                }
            }
            "npm" => {
                let (name, version) = super::npm_common::parse_npm_purl(&entry.base_purl)
                    .ok_or("invalid npm coordinates")?;
                used(
                    super::npm_dir::try_service_dir(
                        &entry.base_purl,
                        record,
                        service,
                        &stage,
                        &name,
                        &version,
                        &mut warnings,
                    )
                    .await,
                )?;
                super::npm_dir::apply_transforms(&stage, &name, &version)
                    .await
                    .map_err(|outcome| detail(*outcome))?;
            }
            "golang" => {
                let (module, version) =
                    parse_golang_purl(&entry.base_purl).ok_or("invalid Go coordinates")?;
                let archive = match fetch_verified_archive(service, &record.uuid).await {
                    ServiceArtifact::Ready(archive) => archive,
                    other => return Err(format!("server module unavailable: {other:?}")),
                };
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
            let inventory = entry.artifact.file_inventory.as_ref().ok_or("the ledger has no complete file inventory; restore from version control or explicitly re-vendor")?;
            let uuid = (entry.ecosystem == "cargo").then_some(entry.uuid.as_str());
            super::verify::verify_dir_inventory(&stage, inventory, uuid).await?;
        }
    }
    if entry.ecosystem == "maven" || entry.ecosystem == "jvm" {
        let target = artifact.parent().ok_or("artifact has no parent")?;
        tokio::fs::create_dir_all(target.parent().ok_or("artifact tree has no parent")?)
            .await
            .map_err(|e| e.to_string())?;
        swap_stage_into_place(uuid_dir, target)
            .await
            .map_err(|e| e.to_string())?;
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

async fn restore_maven_metadata(
    root: &Path,
    stage_root: &Path,
    entry: &VendorEntry,
    record: &PatchRecord,
    jar: &[u8],
    service: &VendorServiceConfig,
) -> Result<(), String> {
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
        return super::maven_repo::write_maven_artifact(
            target.parent().ok_or("artifact has no parent")?,
            &format!("{artifact}-{version}.jar"),
            jar,
            &format!("{artifact}-{version}.pom"),
            &pom,
        )
        .await;
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
    let patch = super::jvm::JvmPatch {
        group_id: &group,
        artifact_id: &artifact,
        version: &version,
        uuid: &record.uuid,
        jar,
        upstream_pom: &pom,
        upstream_module: module.as_deref(),
    };
    let reader = super::jvm::apply::ProjectReader::new(root);
    let read = |rel: &str| {
        if rel.starts_with(".socket/vendor/") {
            None
        } else {
            reader.read(rel)
        }
    };
    let shape = super::jvm::detect(&read);
    let plan = if shape == super::jvm::Shape::MavenReactor {
        let enabled = !entry
            .wiring
            .iter()
            .any(|w| super::jvm::op_of(w) == "config_none");
        super::jvm::maven_reactor::plan_with_config(&read, &patch, enabled)
    } else {
        super::jvm::plan(shape, &read, &patch)
    }
    .map_err(|e| e.detail)?;
    if reader.escaped().is_some() {
        return Err("Maven project path escapes the checkout".into());
    }
    let tree: Vec<_> = plan.writes.into_iter().filter(|w| w.tree).collect();
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
            ecosystem: "npm".into(),
            base_purl: "pkg:npm/example@1.0.0".into(),
            uuid: UUID.into(),
            artifact: VendorArtifact {
                path: format!(".socket/vendor/npm/{UUID}/example-1.0.0.tgz"),
                sha256: hex::encode(Sha256::digest(bytes)),
                size: Some(bytes.len() as u64),
                platform_locked: None,
                file_inventory: None,
                yarn_berry10c0: None,
            },
            wiring: Vec::new(),
            lock: None,
            took_over_go_patches: false,
            detached: true,
            record: Some(record()),
            flavor: Some("npm".into()),
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
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
        assert!(restore(
            root.path(),
            &entry,
            &record(),
            &service_cfg(&server.uri(), VendorSource::Service, false)
        )
        .await
        .unwrap_err()
        .contains("no complete file inventory"));
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
}
