//! Integrity and repair for Bun's member-relative binary-lock tarballs.
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::bun_binary::{prune_mirror_parents, undo_mirrors, validate_mirror_path};
use super::bun_lockb::BunLockb;
use super::path::parse_vendor_path;
use super::state::{VendorEntry, WiringAction, WiringRecord};
use crate::utils::fs::{atomic_write_bytes_preserving_mode, read_regular_to_bytes_sync};

const KIND: &str = "bun_lockb_workspace_artifact";

fn required_mirrors(
    root: &Path,
    entry: &VendorEntry,
) -> Result<Vec<(String, String, PathBuf)>, String> {
    if entry.ecosystem != "npm"
        || entry.flavor.as_deref() != Some("bun")
        || root.join("bun.lock").exists()
    {
        return Ok(Vec::new());
    }
    let bytes = match read_regular_to_bytes_sync(&root.join("bun.lockb")) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("cannot read bun.lockb: {e}")),
    };
    let lock = BunLockb::parse(&bytes)?;
    let canonical =
        parse_vendor_path(&entry.artifact.path).ok_or("unsafe canonical artifact path")?;
    let (name, version) = super::npm_common::parse_npm_purl(&entry.base_purl)
        .ok_or("invalid package coordinates for workspace tarballs")?;
    let expected_leaf = super::npm_common::tgz_rel_leaf(&name, &version);
    if canonical.eco != "npm"
        || canonical.uuid != entry.uuid
        || canonical.leaf != expected_leaf
        || entry.artifact.path != format!(".socket/vendor/npm/{}/{}", entry.uuid, canonical.leaf)
    {
        return Err("unsafe canonical artifact path".into());
    }
    if !lock.packages()?.iter().any(|p| {
        parse_vendor_path(&p.resolution).is_some_and(|path| {
            path.eco == "npm" && path.uuid == entry.uuid && path.leaf == canonical.leaf
        })
    }) {
        return Ok(Vec::new());
    }
    lock.workspace_paths()?
        .into_iter()
        .map(|workspace| {
            let rel = format!(
                "{}/{}",
                workspace.trim_start_matches("./"),
                entry.artifact.path
            );
            let path = validate_mirror_path(root, &rel)?;
            Ok((workspace, rel, path))
        })
        .collect()
}

/// Check every location an older Bun workspace reader can install from.
pub(super) async fn verify(root: &Path, entry: &VendorEntry) -> Result<(), String> {
    let mirrors = required_mirrors(root, entry).map_err(|_| "vendor_workspace_artifact_invalid")?;
    if mirrors.is_empty() {
        return Ok(());
    }
    let expected = super::verify::file_sha256_hex(&root.join(&entry.artifact.path))
        .await
        .ok_or("vendor_artifact_unreadable")?;
    for (_, _, path) in mirrors {
        match super::verify::file_sha256_hex(&path).await {
            Some(actual) if actual == expected => {}
            Some(_) => return Err("vendor_workspace_artifact_corrupt".into()),
            None if !path.exists() => return Err("vendor_workspace_artifact_missing".into()),
            None => return Err("vendor_workspace_artifact_corrupt".into()),
        }
    }
    Ok(())
}

/// Copy only a fingerprint-verified canonical artifact, including in offline
/// repair. Return the mirror ownership records and whether bytes need changing.
pub(super) async fn repair(
    root: &Path,
    entry: &VendorEntry,
    dry_run: bool,
) -> Result<(Vec<WiringRecord>, bool), String> {
    let mirrors = required_mirrors(root, entry)?;
    if mirrors.is_empty() {
        return Ok((Vec::new(), false));
    }
    let bytes = read_regular_to_bytes_sync(&root.join(&entry.artifact.path))
        .map_err(|e| format!("cannot read canonical vendor tarball: {e}"))?;
    let digest = hex::encode(Sha256::digest(&bytes));
    if entry.artifact.sha256.is_empty() || !digest.eq_ignore_ascii_case(&entry.artifact.sha256) {
        return Err("canonical vendor tarball does not match its recorded fingerprint".into());
    }
    let mut updates = Vec::new();
    let mut wiring = Vec::new();
    for (workspace, rel, path) in mirrors {
        let before = match read_regular_to_bytes_sync(&path) {
            Ok(before) => Some(before),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("cannot read workspace tarball {rel}: {e}")),
        };
        if before.as_deref() != Some(bytes.as_slice()) {
            updates.push((path, before));
        }
        wiring.push(WiringRecord {
            file: rel,
            kind: KIND.into(),
            action: WiringAction::Added,
            key: Some(workspace),
            original: None,
            new: Some(serde_json::Value::String(digest.clone())),
        });
    }
    if !dry_run {
        let mut written = Vec::new();
        for (path, before) in &updates {
            let result = async {
                tokio::fs::create_dir_all(path.parent().ok_or("workspace tarball has no parent")?)
                    .await
                    .map_err(|e| format!("cannot create workspace vendor directory: {e}"))?;
                atomic_write_bytes_preserving_mode(path, &bytes)
                    .await
                    .map_err(|e| format!("cannot write workspace tarball: {e}"))
            }
            .await;
            if let Err(e) = result {
                undo_mirrors(&written).await;
                return Err(e);
            }
            written.push((path.clone(), before.clone()));
        }
    }
    Ok((wiring, !updates.is_empty()))
}

/// Preserve both existing and missing member copies before a rebuild whose
/// source still has to be checked against the lockfile's trust anchor.
pub(super) fn snapshot(
    root: &Path,
    entry: &VendorEntry,
) -> Result<super::bun_lock::BinaryWorkspaceArtifactSnapshot, String> {
    required_mirrors(root, entry)?
        .into_iter()
        .map(|(_, rel, path)| {
            let before = match read_regular_to_bytes_sync(&path) {
                Ok(bytes) => Some(bytes),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(format!("cannot snapshot workspace tarball {rel}: {e}")),
            };
            Ok((path, before))
        })
        .collect()
}

/// Remove superseded mirrors only when every recorded artifact remains ours.
/// Validate the entire set before removing any file.
pub(super) async fn cleanup(root: &Path, entry: &VendorEntry, dry_run: bool) -> Result<(), String> {
    if !entry.wiring.iter().any(|r| r.kind == KIND) {
        return Ok(());
    }
    let (name, version) = super::npm_common::parse_npm_purl(&entry.base_purl)
        .ok_or("invalid package coordinates for workspace tarballs")?;
    let leaf = super::npm_common::tgz_rel_leaf(&name, &version);
    let mut paths = Vec::new();
    for rec in entry.wiring.iter().filter(|r| r.kind == KIND) {
        let path = validate_mirror_path(root, &rec.file)?;
        let artifact = rec
            .file
            .rsplit_once("/.socket/vendor/npm/")
            .ok_or("invalid workspace tarball path")?
            .1;
        if artifact != format!("{}/{leaf}", entry.uuid) {
            return Err("workspace tarball does not match its ledger entry".into());
        }
        let expected = rec
            .new
            .as_ref()
            .and_then(serde_json::Value::as_str)
            .ok_or("missing workspace tarball fingerprint")?;
        match read_regular_to_bytes_sync(&path) {
            Ok(bytes) if hex::encode(Sha256::digest(&bytes)) == expected => paths.push(path),
            Ok(_) => return Err("workspace tarball changed; superseded artifacts kept".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("cannot read workspace tarball: {e}")),
        }
    }
    if !dry_run {
        for path in paths {
            tokio::fs::remove_file(&path)
                .await
                .map_err(|e| format!("cannot remove workspace tarball: {e}"))?;
            prune_mirror_parents(&path).await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    const UUID: &str = "11111111-1111-4111-8111-111111111111";

    fn fixture() -> (tempfile::TempDir, VendorEntry, Vec<u8>) {
        let root = tempfile::tempdir().unwrap();
        let artifact = format!(".socket/vendor/npm/{UUID}/minimist-1.2.2.tgz");
        let bytes = b"the fingerprint-verified committed tarball".to_vec();
        std::fs::create_dir_all(root.path().join(&artifact).parent().unwrap()).unwrap();
        std::fs::write(root.path().join(&artifact), &bytes).unwrap();
        let mut lock = BunLockb::parse(include_bytes!(
            "../../tests/fixtures/bun-lockb/1.1.45-extensions/bun.lockb"
        ))
        .unwrap();
        let package = lock
            .packages()
            .unwrap()
            .into_iter()
            .find(|p| p.name == "minimist")
            .unwrap();
        let sri = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(&bytes))
        );
        lock.set_package(package.id, &artifact, &sri).unwrap();
        assert!(!lock.workspace_paths().unwrap().is_empty());
        std::fs::write(root.path().join("bun.lockb"), lock.bytes()).unwrap();
        let entry = serde_json::from_value(serde_json::json!({
            "ecosystem": "npm", "basePurl": "pkg:npm/minimist@1.2.2", "uuid": UUID,
            "artifact": { "path": artifact, "sha256": hex::encode(Sha256::digest(&bytes)) },
            "flavor": "bun", "wiring": [],
        }))
        .unwrap();
        (root, entry, bytes)
    }

    #[tokio::test]
    async fn missing_and_corrupt_workspace_copies_repair_without_repacking() {
        let (root, mut entry, bytes) = fixture();
        let lock_before = std::fs::read(root.path().join("bun.lockb")).unwrap();
        assert_eq!(
            verify(root.path(), &entry).await.unwrap_err(),
            "vendor_workspace_artifact_missing"
        );
        let (wiring, changed) = repair(root.path(), &entry, true).await.unwrap();
        assert!(changed);
        assert!(wiring.iter().all(|r| !root.path().join(&r.file).exists()));
        let (wiring, changed) = repair(root.path(), &entry, false).await.unwrap();
        assert!(changed);
        assert!(!wiring.is_empty());
        entry.wiring = wiring;
        verify(root.path(), &entry).await.unwrap();
        for rec in &entry.wiring {
            assert_eq!(std::fs::read(root.path().join(&rec.file)).unwrap(), bytes);
        }
        assert!(!repair(root.path(), &entry, false).await.unwrap().1);
        std::fs::write(root.path().join(&entry.wiring[0].file), b"corrupt").unwrap();
        assert_eq!(
            verify(root.path(), &entry).await.unwrap_err(),
            "vendor_workspace_artifact_corrupt"
        );
        assert!(repair(root.path(), &entry, false).await.unwrap().1);
        verify(root.path(), &entry).await.unwrap();
        assert_eq!(
            std::fs::read(root.path().join("bun.lockb")).unwrap(),
            lock_before
        );
        cleanup(root.path(), &entry, true).await.unwrap();
        assert!(root.path().join(&entry.wiring[0].file).exists());
        cleanup(root.path(), &entry, false).await.unwrap();
        assert!(entry
            .wiring
            .iter()
            .all(|r| !root.path().join(&r.file).exists()));
        assert_eq!(
            std::fs::read(root.path().join(&entry.artifact.path)).unwrap(),
            bytes
        );
    }

    #[tokio::test]
    async fn mirror_repairs_require_canonical_fingerprint_and_cleanup_checks_uuid() {
        let (root, mut entry, bytes) = fixture();
        entry.wiring = repair(root.path(), &entry, false).await.unwrap().0;
        let mirror = root.path().join(&entry.wiring[0].file);
        std::fs::write(root.path().join(&entry.artifact.path), b"corrupt canonical").unwrap();
        std::fs::remove_file(&mirror).unwrap();
        assert!(repair(root.path(), &entry, false)
            .await
            .unwrap_err()
            .contains("fingerprint"));
        assert!(!mirror.exists());
        std::fs::write(root.path().join(&entry.artifact.path), &bytes).unwrap();
        repair(root.path(), &entry, false).await.unwrap();
        let foreign = "22222222-2222-4222-8222-222222222222";
        let foreign_rel = entry.wiring[0].file.replace(UUID, foreign);
        std::fs::create_dir_all(root.path().join(&foreign_rel).parent().unwrap()).unwrap();
        std::fs::write(root.path().join(&foreign_rel), &bytes).unwrap();
        let mut poisoned = entry.clone();
        poisoned.wiring[0].file = foreign_rel.clone();
        assert!(cleanup(root.path(), &poisoned, false)
            .await
            .unwrap_err()
            .contains("ledger entry"));
        assert!(mirror.exists());
        assert_eq!(std::fs::read(root.path().join(foreign_rel)).unwrap(), bytes);
        std::fs::write(&mirror, b"drifted").unwrap();
        assert!(cleanup(root.path(), &entry, false)
            .await
            .unwrap_err()
            .contains("changed"));
        assert_eq!(std::fs::read(mirror).unwrap(), b"drifted");
    }

    #[tokio::test]
    async fn mirror_only_reconstructed_ledger_never_deletes_active_artifacts_on_revert() {
        let (root, mut entry, bytes) = fixture();
        entry.wiring = repair(root.path(), &entry, false).await.unwrap().0;
        let binary_before = std::fs::read(root.path().join("bun.lockb")).unwrap();
        for dry_run in [true, false] {
            let outcome = super::super::bun_lock::revert_bun_opts(
                &entry,
                root.path(),
                super::super::RevertOpts::new(dry_run),
            )
            .await;
            assert!(!outcome.success);
            assert!(outcome
                .error
                .unwrap()
                .contains("original wiring is missing"));
            assert_eq!(
                std::fs::read(root.path().join(&entry.artifact.path)).unwrap(),
                bytes
            );
            assert_eq!(
                std::fs::read(root.path().join("bun.lockb")).unwrap(),
                binary_before
            );
            for record in &entry.wiring {
                assert_eq!(
                    std::fs::read(root.path().join(&record.file)).unwrap(),
                    bytes
                );
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn mirror_symlinks_are_never_followed_for_verify_repair_or_cleanup() {
        let (root, mut entry, bytes) = fixture();
        entry.wiring = repair(root.path(), &entry, false).await.unwrap().0;
        let mirror = root.path().join(&entry.wiring[0].file);
        let external = tempfile::tempdir().unwrap();
        let target = external.path().join("external.tgz");
        std::fs::write(&target, &bytes).unwrap();
        std::fs::remove_file(&mirror).unwrap();
        std::os::unix::fs::symlink(&target, &mirror).unwrap();
        assert_eq!(
            verify(root.path(), &entry).await.unwrap_err(),
            "vendor_workspace_artifact_invalid"
        );
        assert!(repair(root.path(), &entry, false).await.is_err());
        assert!(cleanup(root.path(), &entry, false).await.is_err());
        assert_eq!(std::fs::read_link(mirror).unwrap(), target);
        assert_eq!(std::fs::read(target).unwrap(), bytes);
    }

    #[tokio::test]
    async fn scoped_workspace_tarballs_validate_and_cleanup_through_scope_directory() {
        let root = tempfile::tempdir().unwrap();
        let bytes = b"scoped tarball";
        let rel = format!("packages/consumer/.socket/vendor/npm/{UUID}/@scope/pkg-1.0.0.tgz");
        let path = validate_mirror_path(root.path(), &rel).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        let entry = serde_json::from_value(serde_json::json!({
            "ecosystem":"npm", "basePurl":"pkg:npm/%40scope/pkg@1.0.0", "uuid":UUID,
            "artifact":{"path":format!(".socket/vendor/npm/{UUID}/@scope/pkg-1.0.0.tgz"), "sha256":""},
            "flavor":"bun", "wiring":[{
                "file":rel, "kind":KIND, "action":"added", "key":"packages/consumer",
                "new":hex::encode(Sha256::digest(bytes)),
            }],
        })).unwrap();
        cleanup(root.path(), &entry, false).await.unwrap();
        assert!(!path.exists());
        assert!(!root.path().join("packages/consumer/.socket").exists());
        assert!(root.path().join("packages/consumer").is_dir());
        assert!(validate_mirror_path(
            root.path(),
            &format!("packages/consumer/.socket/vendor/npm/{UUID}/@scope/nested/pkg-1.0.0.tgz")
        )
        .is_err());
    }
}
