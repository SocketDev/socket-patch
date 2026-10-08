//! Native binary Bun vendoring. Package records are edited without re-resolving
//! dependencies or requiring a Bun executable.
use super::bun_lockb::{BinaryPackage, BunLockb};
use super::common::refused;
use super::npm_common::{
    gate_packages, guard_revert_uuid_dir, refusal_code, tgz_rel_leaf, NpmCommit, NpmCoords,
    NpmLockBackend, NpmStagedPack, WireCx,
};
use super::path::parse_vendor_path;
use super::state::{VendorEntry, WiringAction, WiringRecord};
use super::{RevertOpts, RevertOutcome, VendorOutcome, VendorWarning};
use crate::manifest::schema::PatchRecord;
#[cfg(test)]
use crate::patch::apply::PatchSources;
use crate::utils::fs::{atomic_write_bytes_preserving_mode, read_regular_to_bytes_sync};
use std::path::{Path, PathBuf};

pub(crate) const LOCK: &str = "bun.lockb";
pub(crate) const KIND: &str = "bun_lockb_package";
const MIRROR_KIND: &str = "bun_lockb_workspace_artifact";

fn is_ours(package: &BinaryPackage, name: &str, leaf: &str) -> bool {
    package.name == name
        && parse_vendor_path(&package.resolution).is_some_and(|p| p.eco == "npm")
        && package.resolution.ends_with(&format!("/{leaf}"))
}

/// [`BunBinaryBackend`] through the shared driver, under the signature the
/// suite below calls it by.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn vendor(
    purl: &str,
    installed_dir: super::source::PackageSource<'_>,
    root: &Path,
    record: &PatchRecord,
    sources: &crate::patch::apply::PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
    service: Option<&super::VendorServiceConfig>,
) -> VendorOutcome {
    super::npm_common::vendor_npm_family(
        &BunBinaryBackend,
        super::npm_common::NpmVendorRequest {
            purl,
            installed_dir,
            project_root: root,
            record,
            sources,
            vendored_at,
            dry_run,
            force,
            service,
        },
    )
    .await
}

/// The `bun.lockb` half of [`super::bun_lock::vendor_bun`], for a project
/// whose installs the binary lock drives (driven by
/// [`super::npm_common::vendor_npm_family`]).
pub(super) struct BunBinaryBackend;

/// [`BunBinaryBackend`]'s pre-flight product: the parsed lock and the
/// records and workspace mirrors to rewrite.
pub(super) struct BunBinaryPlan {
    lock: BunLockb,
    leaf: String,
    matches: Vec<BinaryPackage>,
    mirrors: Vec<(String, String)>,
}

impl NpmLockBackend for BunBinaryBackend {
    type Plan = BunBinaryPlan;

    fn flavor(&self) -> Option<&'static str> {
        Some("bun")
    }

    async fn preflight(
        &self,
        root: &Path,
        coords: &NpmCoords,
        warnings: &mut Vec<VendorWarning>,
    ) -> Result<BunBinaryPlan, Box<VendorOutcome>> {
        let project = read_project(root).await?;
        let leaf = tgz_rel_leaf(&coords.name, &coords.version);
        let BinaryTargets {
            matches,
            mirrors,
            bundled,
        } = preflight_package(&project, root, coords, &leaf)?;
        for package in bundled {
            // LOUD: this copy ships inside its PARENT's tarball, which we do
            // not repack — it stays the unpatched bytes after vendor (#469).
            warnings.push(VendorWarning::new(
                "vendor_bundled_instance_skipped",
                format!(
                    "{LOCK} package #{} ({}@{}) is {}bundled inside its parent's tarball and \
                     CANNOT be rewritten there — that copy stays UNPATCHED; vendor or update the \
                     bundling parent to cover it",
                    package.id,
                    coords.name,
                    coords.version,
                    if package.bundled_only { "" } else { "also " },
                ),
            ));
        }
        let BinaryProject { lock, .. } = project;
        Ok(BunBinaryPlan {
            lock,
            leaf,
            matches,
            mirrors,
        })
    }

    async fn wire(
        &self,
        plan: BunBinaryPlan,
        cx: &WireCx<'_>,
        staged: &mut NpmStagedPack,
        _warnings: &mut Vec<VendorWarning>,
    ) -> Result<Option<NpmCommit>, String> {
        let BunBinaryPlan {
            mut lock,
            leaf,
            matches,
            mirrors,
        } = plan;
        let (root, coords) = (cx.project_root, cx.coords);
        let mut wiring = Vec::new();
        for package in matches {
            if package.resolution == staged.rel_tgz
                && package.integrity.as_deref() == Some(&staged.packed.integrity)
            {
                continue;
            }
            let original = lock.snapshot(package.id)?;
            lock.set_package(package.id, &staged.rel_tgz, &staged.packed.integrity)?;
            let mut new = lock.snapshot(package.id)?;
            if is_ours(&package, &coords.name, &leaf) {
                // Bun may renumber packages on re-save. Preserve the semantic
                // predecessor so ledger carry-forward can recover the correct
                // pristine original even after the numeric key has changed.
                new["previous"] = serde_json::json!({
                    "name": original["name"], "version": original["version"],
                    "resolution": original["resolution"], "integrity": original["integrity"],
                });
            }
            wiring.push(WiringRecord {
                file: LOCK.into(),
                kind: KIND.into(),
                action: WiringAction::Rewritten,
                key: Some(package.id.to_string()),
                original: if is_ours(&package, &coords.name, &leaf) {
                    None
                } else {
                    Some(original)
                },
                new: Some(new),
            });
        }
        // Bun 0.5.9–1.3 resolves workspace local tarballs relative to the
        // declaring member. Preserve the same portable resolution for every
        // consumer by committing identical tarballs at those member-relative
        // locations as well as the canonical root artifact.
        let artifact = read_regular_to_bytes_sync(&root.join(&staged.rel_tgz))
            .map_err(|e| format!("cannot read staged tarball: {e}"))?;
        let lock_changed = !wiring.is_empty();
        let mut mirror_backups: Vec<(PathBuf, Option<Vec<u8>>)> = Vec::new();
        for (workspace, rel) in &mirrors {
            let path = root.join(rel);
            let before = match read_regular_to_bytes_sync(&path) {
                Ok(bytes) => Some(bytes),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => {
                    undo_mirrors(&mirror_backups).await;
                    return Err(format!("cannot read workspace tarball {rel}: {e}"));
                }
            };
            wiring.push(WiringRecord {
                file: rel.clone(),
                kind: MIRROR_KIND.into(),
                action: WiringAction::Added,
                key: Some(workspace.clone()),
                original: None,
                new: Some(serde_json::Value::String(staged.packed.sha256_hex.clone())),
            });
            if before.as_deref() == Some(artifact.as_slice()) {
                continue;
            }
            if let Err(e) = tokio::fs::create_dir_all(path.parent().expect("mirror parent")).await {
                undo_mirrors(&mirror_backups).await;
                return Err(format!("cannot create workspace vendor directory: {e}"));
            }
            if let Err(e) = atomic_write_bytes_preserving_mode(&path, &artifact).await {
                undo_mirrors(&mirror_backups).await;
                return Err(format!("cannot write workspace tarball {rel}: {e}"));
            }
            mirror_backups.push((path, before));
        }
        if !lock_changed && mirror_backups.is_empty() {
            return Ok(None);
        }
        if let Err(e) = atomic_write_bytes_preserving_mode(&root.join(LOCK), &lock.bytes()).await {
            undo_mirrors(&mirror_backups).await;
            return Err(format!("cannot write {LOCK}: {e}"));
        }
        Ok(Some(NpmCommit {
            wiring,
            ..NpmCommit::default()
        }))
    }

    fn manifest_warning(&self, _name: &str, _version: &str) -> VendorWarning {
        VendorWarning::new(
            "vendor_dep_manifest_stale",
            format!(
                "the patch changes package.json; {LOCK} dependency edges were preserved — run \
                 bun install if dependency ranges changed"
            ),
        )
    }
}

/// The binary lock, parsed and validated for mutation before any write,
/// with its package records. [`vendor`] reads it per package; the vendor
/// loop's download plan reads it once and gates every package against the
/// same parse ([`preflight_packages`]).
pub(super) struct BinaryProject {
    lock: BunLockb,
    packages: Vec<BinaryPackage>,
    /// The project's own `patchedDependencies` keys (#367).
    user_patched: Vec<String>,
}

/// Read the lock, refusing (before any write) a symlinked, unreadable,
/// unparseable or non-rewritable one.
pub(super) async fn read_project(root: &Path) -> Result<BinaryProject, Box<VendorOutcome>> {
    if crate::utils::fs::is_symlink(&root.join(LOCK)).await {
        return Err(Box::new(refused(
            "vendor_bun_lockb_invalid",
            "bun.lockb is a symbolic link; replace it with a regular file before vendoring",
        )));
    }
    let lock = match read_regular_to_bytes_sync(&root.join(LOCK))
        .map_err(|e| e.to_string())
        .and_then(|b| BunLockb::parse(&b))
    {
        Ok(v) => v,
        Err(e) => return Err(Box::new(refused("vendor_bun_lockb_invalid", e))),
    };
    if let Err(e) = lock.validate_mutation() {
        return Err(Box::new(refused("vendor_bun_lockb_invalid", e)));
    }
    let packages = match lock.packages() {
        Ok(v) => v,
        Err(e) => return Err(Box::new(refused("vendor_bun_lockb_invalid", e))),
    };
    let user_patched = super::bun_lock::read_user_patched(root, None).await;
    Ok(BinaryProject {
        lock,
        packages,
        user_patched,
    })
}

/// What the per-package pre-flight hands the vendoring: the records to
/// rewrite and the validated `(workspace, artifact path)` mirrors.
pub(super) struct BinaryTargets {
    matches: Vec<BinaryPackage>,
    mirrors: Vec<(String, String)>,
    /// Matching records some bundled edge reaches (#469): each one's
    /// bundled copy stays unpatched, which vendoring reports loudly.
    bundled: Vec<BinaryPackage>,
}

/// The per-package pre-flight against an already-read lock: the records
/// to rewrite (the exact `name@version`, plus our own tuples for it), and
/// the workspace mirror paths validated. Nothing here reads the package's
/// source or asks the service, so the download plan evaluates it ahead of
/// the loop.
pub(super) fn preflight_package(
    project: &BinaryProject,
    root: &Path,
    coords: &NpmCoords,
    leaf: &str,
) -> Result<BinaryTargets, Box<VendorOutcome>> {
    super::bun_lock::refuse_user_patched(&project.user_patched, &coords.name, &coords.version)?;
    let (bundled_only, matches): (Vec<_>, Vec<_>) = project
        .packages
        .iter()
        .filter(|p| {
            (p.name == coords.name && p.version.as_deref() == Some(&coords.version))
                || is_ours(p, &coords.name, leaf)
        })
        .cloned()
        .partition(|p| p.bundled_only);
    let bundled: Vec<_> = matches
        .iter()
        .filter(|p| p.bundled)
        .chain(&bundled_only)
        .cloned()
        .collect();
    if matches.is_empty() && !bundled_only.is_empty() {
        // Only a bundled edge reaches the record: Bun unpacks that copy
        // from the parent's tarball, so rewiring the record installs
        // nothing, and "run `bun install`" would not help either.
        return Err(Box::new(refused(
            "vendor_lock_entry_not_rewritable",
            format!(
                "every {LOCK} record for {}@{} is bundled inside a parent's tarball and \
                 cannot be rewritten — those copies stay UNPATCHED and `bun install` will not \
                 help; vendor or update the bundling parent to cover them",
                coords.name, coords.version
            ),
        )));
    }
    if matches.is_empty() {
        return Err(Box::new(refused(
            "vendor_lock_entry_not_found",
            format!(
                "{LOCK} has no registry entry for {}@{}",
                coords.name, coords.version
            ),
        )));
    }
    let mirrors = match project.lock.workspace_paths().and_then(|paths| {
        paths
            .into_iter()
            .map(|workspace| {
                let rel = format!(
                    "{}/{}/{}",
                    workspace.trim_start_matches("./"),
                    coords.uuid_dir_rel,
                    leaf
                );
                validate_mirror_path(root, &rel)?;
                Ok((workspace, rel))
            })
            .collect::<Result<Vec<_>, String>>()
    }) {
        Ok(v) => v,
        Err(e) => return Err(Box::new(refused("vendor_bun_lockb_invalid", e))),
    };
    Ok(BinaryTargets {
        matches,
        mirrors,
        bundled,
    })
}

/// Which of `packages` [`vendor`] would refuse before its first service
/// call, from one read of the lock; see
/// [`super::npm_flavor::preflight_packages`].
pub(super) async fn preflight_packages(
    root: &Path,
    packages: &[(&str, &PatchRecord)],
) -> Vec<Result<(), &'static str>> {
    gate_packages(
        read_project(root).await.map_err(|o| refusal_code(&o)),
        packages,
        |project, coords| {
            let leaf = tgz_rel_leaf(&coords.name, &coords.version);
            preflight_package(project, root, coords, &leaf)
                .map(drop)
                .map_err(|o| refusal_code(&o))
        },
    )
}

/// Validate and stage every inverse before changing the lock or removing its
/// artifact. Dry runs perform the same drift checks as real mode switches.
pub(crate) async fn revert(entry: &VendorEntry, root: &Path, opts: RevertOpts) -> RevertOutcome {
    let dir = match guard_revert_uuid_dir(&entry.uuid) {
        Ok(v) => v,
        Err(o) => return o,
    };
    if crate::utils::fs::is_symlink(&root.join(LOCK)).await {
        return RevertOutcome::failed(
            "bun.lockb is a symbolic link; replace it with a regular file before reverting",
        );
    }
    let mut outcome = RevertOutcome::ok();
    let original_bytes = match read_regular_to_bytes_sync(&root.join(LOCK)) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if entry.wiring.is_empty() && opts.keep_artifact {
                return outcome;
            }
            return RevertOutcome::failed(format!(
                "{LOCK} is missing; cannot safely revert the binary lock"
            ));
        }
        Err(e) => return RevertOutcome::failed(format!("cannot read {LOCK}: {e}")),
    };
    let mut lock = match BunLockb::parse(&original_bytes) {
        Ok(v) => v,
        Err(e) => return RevertOutcome::failed(e),
    };
    if !entry.wiring.iter().any(|rec| rec.kind == KIND) && !opts.keep_artifact {
        match lock.packages() {
            Ok(packages)
                if !packages.iter().any(|p| {
                    parse_vendor_path(&p.resolution).is_some_and(|p| p.uuid == entry.uuid)
                }) => {}
            _ => {
                return RevertOutcome::failed(format!(
                    "{LOCK} still references {} but the original wiring is missing",
                    entry.uuid
                ))
            }
        }
    }
    // REMOVED, not drift (#1132): `bun remove <pkg>` (or an upgrade off the
    // patched version) leaves neither snapshot in the lock. When no package
    // resolves through this uuid dir any more, there is nothing to restore
    // and nothing an install needs the artifact for. Probed once, before any
    // record is restored; an unreadable package table fails closed (drift).
    let uuid_lower = entry.uuid.to_ascii_lowercase();
    let unreferenced = lock.packages().is_ok_and(|packages| {
        !packages
            .iter()
            .any(|p| p.resolution.to_ascii_lowercase().contains(&uuid_lower))
    });
    let mut mirrors_to_remove = Vec::new();
    for rec in entry.wiring.iter().rev() {
        if rec.kind == MIRROR_KIND {
            if opts.keep_artifact {
                continue;
            }
            let check = (|| {
                let path = validate_mirror_path(root, &rec.file)?;
                let artifact = rec
                    .file
                    .rsplit_once("/.socket/vendor/npm/")
                    .ok_or("invalid workspace tarball path")?
                    .1;
                let parsed = parse_vendor_path(&format!(".socket/vendor/npm/{artifact}"))
                    .ok_or("invalid workspace vendor artifact")?;
                if parsed.uuid != entry.uuid {
                    return Err("workspace tarball UUID does not match its ledger entry".into());
                }
                let (name, version) = super::npm_common::parse_npm_purl(&entry.base_purl)
                    .ok_or("invalid package coordinates for workspace tarball")?;
                if !rec
                    .file
                    .ends_with(&format!("/{}", tgz_rel_leaf(&name, &version)))
                {
                    return Err("workspace tarball does not match vendored package".into());
                }
                let expected = rec
                    .new
                    .as_ref()
                    .and_then(serde_json::Value::as_str)
                    .ok_or("missing workspace tarball fingerprint")?;
                match read_regular_to_bytes_sync(&path) {
                    Ok(bytes) if crate::utils::digest::sha256_hex_of(&bytes) == expected => {
                        Ok(Some(path))
                    }
                    Ok(_) => Err("workspace tarball has changed; left alone".into()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(format!("cannot read workspace tarball: {e}")),
                }
            })();
            match check {
                Ok(Some(path)) => mirrors_to_remove.push(path),
                Ok(None) => {}
                Err(e) => outcome
                    .warnings
                    .push(VendorWarning::new("vendor_lock_entry_drifted", e)),
            }
            continue;
        }
        // `Ok(true)`: the record left the lock (see `unreferenced`).
        let restore = (|| {
            if rec.file != LOCK || rec.kind != KIND {
                return Err("unexpected binary wiring file or kind".to_string());
            }
            let id = rec
                .key
                .as_deref()
                .and_then(|s| s.parse().ok())
                .ok_or("invalid binary package ID")?;
            let original = rec
                .original
                .as_ref()
                .ok_or("missing pre-vendor binary package snapshot")?;
            let new = rec
                .new
                .as_ref()
                .ok_or("missing rewritten binary package snapshot")?;
            // A preceding inverse may already have restored an identical
            // duplicate. Prefer the active vendor snapshot so that sibling
            // original never makes this record appear already reverted.
            let id = match lock.find_snapshot_id(id, new)? {
                Some(id) => id,
                None if lock.find_snapshot_id(id, original)?.is_some() => return Ok(false),
                None if unreferenced => return Ok(true),
                None => return Err("binary package resolution has drifted".into()),
            };
            lock.restore(id, original).map(|()| false)
        })();
        match restore {
            Ok(true) => outcome.warnings.push(VendorWarning::new(
                super::LOCK_ENTRY_REMOVED_CODE,
                format!(
                    "{LOCK} no longer resolves {} through {dir} (the dependency was removed or \
                     re-resolved); nothing to restore",
                    entry.base_purl
                ),
            )),
            Ok(false) => {}
            Err(e) => outcome
                .warnings
                .push(VendorWarning::new("vendor_lock_entry_drifted", e)),
        }
    }
    if outcome.drift_skipped() {
        outcome.keep_artifact(&dir);
        return outcome;
    }
    if opts.dry_run {
        return outcome;
    }
    let bytes = lock.bytes();
    if bytes != original_bytes {
        if let Err(e) = atomic_write_bytes_preserving_mode(&root.join(LOCK), &bytes).await {
            return RevertOutcome::failed(format!("cannot write {LOCK}: {e}"));
        }
    }
    if !opts.keep_artifact {
        for mirror in mirrors_to_remove {
            if let Err(e) = remove_mirror(&mirror).await {
                return RevertOutcome::failed(format!(
                    "cannot remove workspace tarball {}: {e}",
                    mirror.display()
                ));
            }
        }
        // The last npm-family entry leaves `.socket/vendor/npm/` (and
        // `.socket/vendor/`) empty: the shared helper prunes them so a
        // reverted project carries no vendor residue (non-recursive:
        // siblings keep them).
        let uuid_dir = root.join(&dir);
        if let Err(e) = crate::utils::socket_dir::remove_tree_and_prune(
            &uuid_dir,
            &root.join(crate::constants::SOCKET_DIR),
        )
        .await
        {
            return RevertOutcome::failed(format!("cannot remove {dir}: {e}"));
        }
    }
    outcome
}

/// Mirrors are confined to a workspace's own Socket artifact directory.
/// Check every existing component so a workspace symlink cannot redirect a
/// write or deletion outside the project.
pub(super) fn validate_mirror_path(root: &Path, rel: &str) -> Result<PathBuf, String> {
    let (workspace, artifact) = rel
        .rsplit_once("/.socket/vendor/npm/")
        .ok_or("invalid workspace tarball path")?;
    if workspace.is_empty()
        || artifact.is_empty()
        || rel.contains('\\')
        || Path::new(rel)
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err("unsafe workspace tarball path".into());
    }
    let parsed = parse_vendor_path(&format!(".socket/vendor/npm/{artifact}"))
        .ok_or("invalid workspace vendor artifact")?;
    let valid_leaf = match parsed.leaf.split_once('/') {
        None => true,
        Some((scope, bare)) => {
            scope.starts_with('@') && scope.len() > 1 && !bare.is_empty() && !bare.contains('/')
        }
    };
    if parsed.eco != "npm" || !valid_leaf || !parsed.leaf.ends_with(".tgz") {
        return Err("invalid workspace tarball leaf".into());
    }
    let mut path = root.to_path_buf();
    for component in Path::new(rel).components() {
        path.push(component);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(format!(
                    "workspace tarball path {} contains a symbolic link",
                    path.display()
                ))
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("cannot inspect workspace tarball path: {e}")),
        }
    }
    Ok(path)
}

/// Remove a reverted workspace tarball and prune its emptied parents
/// through the workspace's `.socket/`, or queue both for after the commit
/// of a staged hosted takeover (see `group_commit::defer_removal`).
pub(super) async fn remove_mirror(path: &Path) -> std::io::Result<()> {
    let bound = path
        .ancestors()
        .skip(1)
        .take(5)
        .find(|dir| dir.file_name().is_some_and(|name| name == ".socket"))
        .unwrap_or(path);
    if crate::utils::group_commit::defer_removal(path, bound) {
        return Ok(());
    }
    tokio::fs::remove_file(path).await?;
    prune_mirror_parents(path).await;
    Ok(())
}

pub(super) async fn prune_mirror_parents(path: &Path) {
    // Only empty directories through the workspace's .socket, never the member.
    let mut parent = path.parent();
    for _ in 0..5 {
        let Some(dir) = parent else { break };
        if tokio::fs::remove_dir(dir).await.is_err() {
            break;
        }
        if dir.file_name().is_some_and(|name| name == ".socket") {
            break;
        }
        parent = dir.parent();
    }
}

pub(super) async fn undo_mirrors(backups: &[(PathBuf, Option<Vec<u8>>)]) {
    for (path, before) in backups.iter().rev() {
        if let Some(bytes) = before {
            let _ = atomic_write_bytes_preserving_mode(path, bytes).await;
        } else {
            let _ = tokio::fs::remove_file(path).await;
            prune_mirror_parents(path).await;
        }
    }
}

#[cfg(all(test, unix))]
mod symlink_tests {
    use super::*;

    #[tokio::test]
    async fn symlink_vendor_and_revert_refuse_before_artifact_or_lock_changes() {
        let root = tempfile::tempdir().unwrap();
        let original = include_bytes!("../../tests/fixtures/bun-lockb/1.1.45/bun.lockb");
        let target = root.path().join("shared.lockb");
        std::fs::write(&target, original).unwrap();
        std::os::unix::fs::symlink("shared.lockb", root.path().join(LOCK)).unwrap();
        let uuid = "11111111-1111-4111-8111-111111111111";
        let record: PatchRecord = serde_json::from_value(serde_json::json!({
            "uuid": uuid, "exportedAt": "", "files": {}, "vulnerabilities": {},
            "description": "", "license": "MIT", "tier": "free",
        }))
        .unwrap();
        let purl = "pkg:npm/minimist@1.2.2";
        for dry_run in [true, false] {
            let preflight = super::super::bun_lock::preflight_vendor(root.path())
                .await
                .unwrap_err();
            assert_eq!(preflight.0, "vendor_bun_lockb_invalid");
            assert!(preflight.1.contains("symbolic link"));
            let outcome = vendor(
                purl,
                (&root.path().join("node_modules/minimist")).into(),
                root.path(),
                &record,
                &PatchSources::blobs_only(root.path()),
                "",
                dry_run,
                false,
                None,
            )
            .await;
            assert!(matches!(
                outcome,
                VendorOutcome::Refused {
                    code: "vendor_bun_lockb_invalid",
                    ..
                }
            ));
            assert!(
                !root.path().join(".socket").exists(),
                "refusal must precede staging"
            );
        }
        let artifact = format!(".socket/vendor/npm/{uuid}/minimist-1.2.2.tgz");
        std::fs::create_dir_all(root.path().join(&artifact).parent().unwrap()).unwrap();
        std::fs::write(root.path().join(&artifact), b"keep me").unwrap();
        let entry: VendorEntry = serde_json::from_value(serde_json::json!({
            "ecosystem": "npm", "basePurl": purl, "uuid": uuid,
            "artifact": { "path": artifact, "sha256": "" }, "wiring": [], "flavor": "bun",
        }))
        .unwrap();
        for dry_run in [true, false] {
            let outcome = revert(&entry, root.path(), RevertOpts::new(dry_run)).await;
            assert!(!outcome.success);
            assert!(outcome.error.as_deref().unwrap().contains("symbolic link"));
            assert_eq!(
                std::fs::read(root.path().join(&artifact)).unwrap(),
                b"keep me"
            );
            assert_eq!(std::fs::read(&target).unwrap(), original);
            assert_eq!(
                std::fs::read_link(root.path().join(LOCK)).unwrap(),
                Path::new("shared.lockb")
            );
        }
    }
}

#[cfg(test)]
mod rebuild_tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::vendor::state::carry_forward_wiring;
    use crate::vendor::test_support as ts;
    use crate::vendor::{VendorServiceConfig, VendorSource};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const UUID: &str = "11111111-1111-4111-8111-111111111111";
    const PURL: &str = "pkg:npm/minimist@1.2.2";
    const BEFORE: &[u8] = b"module.exports = 'original';\n";
    const AFTER: &[u8] = b"module.exports = 'patched';\n";
    const PACKAGE: &[u8] = br#"{"name":"minimist","version":"1.2.2"}"#;
    const ORIGINAL: &[u8] =
        include_bytes!("../../tests/fixtures/bun-lockb/1.1.45-extensions/bun.lockb");

    pub(super) struct Fixture {
        tmp: tempfile::TempDir,
        record: PatchRecord,
    }

    impl Fixture {
        fn root(&self) -> &Path {
            self.tmp.path()
        }
        fn installed(&self) -> PathBuf {
            self.root().join("node_modules/minimist")
        }
    }

    impl ts::FlipFixture for Fixture {
        fn flip_root(&self) -> &Path {
            self.root()
        }
        fn flip_key(&self) -> String {
            PURL.to_string()
        }
        fn flip_uuid(&self) -> String {
            UUID.to_string()
        }
        fn flip_artifact_rel(&self) -> String {
            format!(".socket/vendor/npm/{UUID}/minimist-1.2.2.tgz")
        }
        /// The lock plus every workspace mirror the ledger records.
        fn flip_files(&self) -> Vec<String> {
            let mut files = vec![LOCK.to_string()];
            if let Ok(bytes) = std::fs::read(self.root().join(".socket/vendor/state.json")) {
                let state: crate::vendor::state::VendorState =
                    serde_json::from_slice(&bytes).unwrap();
                for entry in state.entries.values() {
                    for rec in entry.wiring.iter().filter(|r| r.kind == MIRROR_KIND) {
                        files.push(rec.file.clone());
                    }
                }
            }
            files.sort();
            files.dedup();
            files
        }
    }

    pub(super) async fn flip_fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join(LOCK), ORIGINAL).unwrap();
        let installed = root.join("node_modules/minimist");
        std::fs::create_dir_all(&installed).unwrap();
        std::fs::write(installed.join("package.json"), PACKAGE).unwrap();
        std::fs::write(installed.join("index.js"), BEFORE).unwrap();
        let blobs = root.join(".socket/blobs");
        std::fs::create_dir_all(&blobs).unwrap();
        let after_hash = compute_git_sha256_from_bytes(AFTER);
        std::fs::write(blobs.join(&after_hash), AFTER).unwrap();
        let record: PatchRecord = serde_json::from_value(serde_json::json!({
            "uuid": UUID, "exportedAt": "", "files": {"package/index.js": {
                "beforeHash": compute_git_sha256_from_bytes(BEFORE), "afterHash": after_hash,
            }}, "vulnerabilities": {}, "description": "", "license": "MIT", "tier": "free",
        }))
        .unwrap();
        Fixture { tmp, record }
    }

    pub(super) async fn flip_run(fx: &Fixture, cfg: Option<&VendorServiceConfig>) -> VendorOutcome {
        let blobs = fx.root().join(".socket/blobs");
        crate::vendor::test_support::vendor_bun(
            PURL,
            &fx.installed(),
            fx.root(),
            &fx.record,
            &PatchSources::blobs_only(&blobs),
            "",
            false,
            false,
            cfg,
        )
        .await
    }

    ts::npm_flip_suite!(flip_suite, Fixture, flip_fixture, flip_run);

    // ── download-plan pre-flight parity ───────────────────────────────────

    /// `(the plan's verdict, the loop's own outcome)` for `purl` with
    /// `record`, both through the text backend's router — which hands a
    /// `bun.lockb`-only project to this backend exactly as the vendoring is
    /// routed — the pre-flight first, since a successful vendor rewrites
    /// the lock it would then read.
    async fn preflight_then_vendor(
        fx: &Fixture,
        purl: &str,
        record: &PatchRecord,
    ) -> (Result<(), &'static str>, Result<(), &'static str>) {
        let planned = super::super::bun_lock::preflight_packages(fx.root(), &[(purl, record)])
            .await
            .remove(0);
        let blobs = fx.root().join(".socket/blobs");
        let looped = match crate::vendor::test_support::vendor_bun(
            purl,
            &fx.installed(),
            fx.root(),
            record,
            &PatchSources::blobs_only(&blobs),
            "",
            false,
            false,
            None,
        )
        .await
        {
            VendorOutcome::Refused { code, .. } => Err(code),
            VendorOutcome::Done { .. } => Ok(()),
        };
        (planned, looped)
    }

    /// The vendor loop's download plan gates each package with this
    /// backend's own pre-flight (`preflight_packages`, reached through the
    /// text backend's `bun.lockb` routing): the lock read, parsed and
    /// validated once, then the record and workspace-mirror gates per
    /// package. Same code wherever the loop refuses, admitted wherever it
    /// vendors — and the coordinates guarded first, ahead of the read, as
    /// the loop guards them.
    #[tokio::test]
    async fn preflight_agrees_with_the_loop_on_every_pre_service_refusal() {
        let fx = flip_fixture().await;
        let (planned, looped) = preflight_then_vendor(&fx, PURL, &fx.record).await;
        assert_eq!(
            (planned, looped),
            (Ok(()), Ok(())),
            "the plain fixture vendors"
        );

        // The name is in the lock (at 1.2.2), this version is not.
        let fx = flip_fixture().await;
        let (planned, looped) =
            preflight_then_vendor(&fx, "pkg:npm/minimist@9.9.9", &fx.record).await;
        assert_eq!(looped, Err("vendor_lock_entry_not_found"), "absent entry");
        assert_eq!(
            planned, looped,
            "absent entry: the plan refuses as the loop does"
        );

        let unparseable: Vec<(&str, Vec<u8>)> = vec![
            ("not a binary lock", b"not a bun.lockb".to_vec()),
            ("truncated lock", ORIGINAL[..ORIGINAL.len() / 2].to_vec()),
        ];
        for (label, bytes) in unparseable {
            let fx = flip_fixture().await;
            std::fs::write(fx.root().join(LOCK), &bytes).unwrap();
            let (planned, looped) = preflight_then_vendor(&fx, PURL, &fx.record).await;
            assert_eq!(looped, Err("vendor_bun_lockb_invalid"), "{label}");
            assert_eq!(
                planned, looped,
                "{label}: the plan refuses as the loop does"
            );

            // A malformed record refuses on its coordinates before the lock
            // is read, in the plan as in the loop.
            let bad_uuid = PatchRecord {
                uuid: "not-a-uuid".to_string(),
                ..fx.record.clone()
            };
            let (planned, looped) = preflight_then_vendor(&fx, PURL, &bad_uuid).await;
            assert_eq!(
                looped,
                Err("unsafe_coordinates"),
                "{label}, malformed record"
            );
            assert_eq!(
                planned, looped,
                "{label}, malformed record: guarded before the read"
            );
        }

        #[cfg(unix)]
        {
            let fx = flip_fixture().await;
            std::fs::rename(fx.root().join(LOCK), fx.root().join("shared.lockb")).unwrap();
            std::os::unix::fs::symlink("shared.lockb", fx.root().join(LOCK)).unwrap();
            let (planned, looped) = preflight_then_vendor(&fx, PURL, &fx.record).await;
            assert_eq!(looped, Err("vendor_bun_lockb_invalid"), "symlinked lock");
            assert_eq!(
                planned, looped,
                "symlinked lock: the plan refuses as the loop does"
            );
        }

        // No binary lock at all: the router hands both the plan and the
        // vendoring to the text backend, which finds no lock either.
        let fx = flip_fixture().await;
        std::fs::remove_file(fx.root().join(LOCK)).unwrap();
        let (planned, looped) = preflight_then_vendor(&fx, PURL, &fx.record).await;
        assert_eq!(looped, Err("vendor_lockfile_missing"), "no lock");
        assert_eq!(planned, looped, "no lock: routed alike");
    }

    fn prebuilt_archive() -> Vec<u8> {
        let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (name, bytes) in [("package.json", PACKAGE), ("index.js", AFTER)] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(123);
            header.set_cksum();
            tar.append_data(&mut header, format!("package/{name}"), bytes)
                .unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap()
    }

    async fn mount_403(server: &MockServer) {
        server.reset().await;
        Mock::given(method("POST"))
            .and(path(ts::PACKAGE_PATH))
            .respond_with(ResponseTemplate::new(403))
            .mount(server)
            .await;
    }

    /// A service outage (here a 403) after a prebuilt vendor: the committed
    /// prebuilt archive is anchored by the ledger, so the re-run reuses it —
    /// entry `None`, bun.lockb and every workspace mirror byte-unchanged, no
    /// request.
    #[tokio::test]
    async fn same_uuid_prebuilt_then_outage_reuses_the_committed_archive() {
        let archive = prebuilt_archive();
        let server = MockServer::start().await;
        ts::mount_granted(&server, UUID, "minimist-1.2.2.tgz", &archive).await;
        let fx = flip_fixture().await;
        let config = ts::service_cfg(&server.uri(), VendorSource::Service, false);
        let (result, entry, warnings) = ts::expect_done(flip_run(&fx, Some(&config)).await);
        assert!(result.success, "{result:?}");
        assert!(ts::has_warning(&warnings, "vendor_prebuilt_downloaded"));
        ts::persist(fx.root(), PURL, entry.unwrap()).await;
        let before = ts::snapshot(&fx).await;
        assert!(
            before.len() > 2,
            "fixture wires workspace mirrors: {:?}",
            before.iter().map(|b| &b.0).collect::<Vec<_>>()
        );

        mount_403(&server).await;
        let (result, entry, warnings) = ts::expect_done(flip_run(&fx, Some(&config)).await);
        assert!(result.success, "{result:?}");
        assert!(entry.is_none(), "in sync: nothing re-pinned");
        assert!(
            warnings
                .iter()
                .all(|w| w.code == "vendor_prebuilt_downloaded"),
            "{warnings:?}"
        );
        assert_eq!(ts::snapshot(&fx).await, before);
        assert_eq!(ts::request_count(&server).await, 0);
    }

    /// #1132: once `bun remove minimist` (or `bun add minimist@1.2.8`)
    /// moves the vendored record off its vendored resolution, neither the
    /// rewritten nor the pre-vendor snapshot is in bun.lockb and nothing
    /// resolves through the uuid dir. There is nothing to restore, so the
    /// revert warns `vendor_lock_entry_removed` and finishes; reading it as
    /// drift kept the tarball and ledger entry forever and looped
    /// `vendor --check` → `scan --prune`.
    #[tokio::test]
    async fn revert_after_package_left_the_lock_is_not_drift() {
        use base64::Engine as _;
        let fx = flip_fixture().await;
        let root = fx.root();
        let VendorOutcome::Done {
            result,
            entry: Some(entry),
            ..
        } = flip_run(&fx, None).await
        else {
            panic!("vendoring must wire the binary lock");
        };
        assert!(result.success, "{result:?}");
        let binary = entry.wiring.iter().find(|r| r.kind == KIND).unwrap();
        let id: usize = binary.key.as_ref().unwrap().parse().unwrap();
        let mut lock = BunLockb::parse(&std::fs::read(root.join(LOCK)).unwrap()).unwrap();
        let integrity = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode([7u8; 64])
        );
        lock.set_registry_package(
            id,
            "1.2.8",
            "https://registry.npmjs.org/minimist/-/minimist-1.2.8.tgz",
            &integrity,
        )
        .unwrap();
        let relocked = lock.bytes();
        assert!(!lock
            .packages()
            .unwrap()
            .iter()
            .any(|p| p.resolution.contains(UUID)));
        std::fs::write(root.join(LOCK), &relocked).unwrap();

        let outcome = revert(&entry, root, RevertOpts::new(false)).await;
        assert!(outcome.success, "{outcome:?}");
        assert!(!outcome.drift_skipped(), "{outcome:?}");
        assert!(outcome.lock_entry_removed(), "{outcome:?}");
        assert!(!outcome.kept_artifact, "{outcome:?}");
        assert_eq!(std::fs::read(root.join(LOCK)).unwrap(), relocked);
        assert!(!root.join(&entry.artifact.path).exists());
    }

    /// With the canonical tarball GONE, an outage switches the same UUID
    /// from a prebuilt archive to a locally packed one. Different archive
    /// bytes must advance the integrity snapshot without losing the pristine
    /// registry predecessor, and revert must restore everything exactly.
    #[tokio::test]
    async fn same_uuid_redownload_reverts_exact_binary_and_mirrors() {
        let archive = prebuilt_archive();
        let server = MockServer::start().await;
        ts::mount_granted(&server, UUID, "minimist-1.2.2.tgz", &archive).await;
        let fx = flip_fixture().await;
        let root = fx.tmp.path();
        let config = ts::service_cfg(&server.uri(), VendorSource::Service, false);
        let mut prior: Option<VendorEntry> = None;
        for prebuilt in [true, false] {
            if !prebuilt {
                server.reset().await;
                ts::mount_granted(&server, UUID, "minimist-1.2.2.tgz", &ts::regzip(&archive)).await;
                // The committed artifact is missing (deleted, never
                // committed): reuse cannot apply, so acquisition runs.
                std::fs::remove_file(
                    root.join(format!(".socket/vendor/npm/{UUID}/minimist-1.2.2.tgz")),
                )
                .unwrap();
            }
            let VendorOutcome::Done {
                result,
                entry: Some(mut entry),
                warnings,
            } = flip_run(&fx, Some(&config)).await
            else {
                panic!("vendoring must write a new binary snapshot");
            };
            assert!(result.success, "{result:?}");
            assert!(warnings.iter().any(|w| w.code
                == if prebuilt {
                    "vendor_prebuilt_downloaded"
                } else {
                    "vendor_prebuilt_downloaded"
                }));
            if let Some(previous) = prior.as_ref() {
                assert_ne!(entry.artifact.sha256, previous.artifact.sha256);
                carry_forward_wiring(previous, &mut entry);
                let binary: Vec<_> = entry.wiring.iter().filter(|r| r.kind == KIND).collect();
                assert_eq!(binary.len(), 1, "discard the superseded integrity snapshot");
                assert_eq!(binary[0].original, previous.wiring[0].original);
            }
            let lock = BunLockb::parse(&std::fs::read(root.join(LOCK)).unwrap()).unwrap();
            let binary = entry.wiring.iter().find(|r| r.kind == KIND).unwrap();
            let id = binary.key.as_ref().unwrap().parse().unwrap();
            assert!(lock
                .matches_snapshot(id, binary.new.as_ref().unwrap())
                .unwrap());
            let bytes = std::fs::read(root.join(&entry.artifact.path)).unwrap();
            assert_eq!(bytes == archive, prebuilt);
            for mirror in entry.wiring.iter().filter(|r| r.kind == MIRROR_KIND) {
                assert_eq!(std::fs::read(root.join(&mirror.file)).unwrap(), bytes);
            }
            ts::persist(root, PURL, entry.clone()).await;
            prior = Some(entry);
        }
        let entry = prior.unwrap();
        let outcome = revert(&entry, root, RevertOpts::new(false)).await;
        assert!(outcome.success, "{outcome:?}");
        assert!(outcome.warnings.is_empty(), "{outcome:?}");
        assert_eq!(std::fs::read(root.join(LOCK)).unwrap(), ORIGINAL);
        assert!(!root.join(&entry.artifact.path).exists());
        for mirror in entry.wiring.iter().filter(|r| r.kind == MIRROR_KIND) {
            assert!(!root.join(&mirror.file).exists());
        }
    }

    /// #920: the `package.json` advisory is emitted once, by the run that
    /// wires — an in-sync re-run of a manifest-rewriting patch is a quiet
    /// AlreadyPatched (and the run that wires says it once).
    #[tokio::test]
    async fn manifest_rewriting_rerun_is_in_sync_without_the_manifest_warning() {
        let mut fx = flip_fixture().await;
        let patched: &[u8] = br#"{"name":"minimist","version":"1.2.2","sideEffects":false}"#;
        let after_hash = compute_git_sha256_from_bytes(patched);
        std::fs::write(fx.root().join(".socket/blobs").join(&after_hash), patched).unwrap();
        fx.record.files.insert(
            "package/package.json".to_string(),
            crate::manifest::schema::PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(PACKAGE),
                after_hash,
            },
        );
        let manifest_warnings = |w: &[VendorWarning]| {
            w.iter()
                .filter(|w| w.code.starts_with("vendor_dep_manifest"))
                .count()
        };
        let VendorOutcome::Done {
            result,
            entry: Some(entry),
            warnings,
        } = flip_run(&fx, None).await
        else {
            panic!("the first run wires");
        };
        assert!(result.success, "{result:?}");
        assert_eq!(manifest_warnings(&warnings), 1, "{warnings:?}");
        ts::persist(fx.root(), PURL, entry).await;

        let VendorOutcome::Done {
            result,
            entry,
            warnings,
        } = flip_run(&fx, None).await
        else {
            panic!("expected Done");
        };
        assert!(result.success && entry.is_none(), "{result:?}");
        assert_eq!(manifest_warnings(&warnings), 0, "{warnings:?}");
    }
}
