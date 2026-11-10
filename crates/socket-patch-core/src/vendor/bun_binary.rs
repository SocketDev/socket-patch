//! Native binary Bun vendoring. Package records are edited without re-resolving
//! dependencies or requiring a Bun executable.
use super::bun_lock_text::{
    decode_json_string, packages_bounds, parse_entry_line, split_name_spec, user_tarball_version,
};
use super::bun_lockb::{BinaryPackage, BunLockb, Origin};
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
use crate::utils::fs::{
    atomic_write_bytes_preserving_mode, read_regular_to_bytes_sync, read_regular_to_string,
};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

pub(crate) const LOCK: &str = "bun.lockb";
pub(crate) const KIND: &str = "bun_lockb_package";
const MIRROR_KIND: &str = "bun_lockb_workspace_artifact";
const TEXT_LOCK: &str = "bun.lock";

fn is_ours(package: &BinaryPackage, name: &str, leaf: &str) -> bool {
    package.name == name
        && parse_vendor_path(&package.resolution).is_some_and(|p| p.eco == "npm")
        && package.resolution.ends_with(&format!("/{leaf}"))
}

/// A record vendoring `coords` rewires: the exact `name@version`, or one of
/// our own tarballs for it.
fn is_target(package: &BinaryPackage, coords: &NpmCoords, leaf: &str) -> bool {
    (package.name == coords.name && package.version.as_deref() == Some(&coords.version))
        || is_ours(package, &coords.name, leaf)
}

/// Bun's writer keeps one package record per resolution, but after a project
/// is vendored a new dependent of the package (a member added later, `bun
/// add` in a member) gets a second, nested registry record of the same
/// `name@version`, because the hoisted one is a local tarball now. Rewiring
/// it to the same tarball gives two records one isolated store directory,
/// and frozen installs then fail intermittently with `EEXIST` (#861). So
/// such records are folded into ONE kept record (the one already at
/// `target`, else one of ours, else the first), as Bun's own re-save
/// would, whether or not the package has dependencies of its own. A record
/// some bundled edge reaches is left to the rewrite: its parent's tarball
/// ships that copy. Where the records cannot fold exactly
/// ([`BunLockb::merge_packages`]: their dependencies resolve differently,
/// or the lock's hoisting is not one this codec reproduces) they are all
/// rewritten as before, with a warning. Returns the records left to
/// rewrite, re-read after renumbering, and whether the lock changed.
fn merge_duplicates(
    lock: &mut BunLockb,
    matches: Vec<BinaryPackage>,
    target: &str,
    coords: &NpmCoords,
    leaf: &str,
    warnings: &mut Vec<VendorWarning>,
) -> Result<(Vec<BinaryPackage>, bool), String> {
    let mut candidates: Vec<_> = matches.iter().filter(|p| !p.bundled).collect();
    candidates.sort_by_key(|p| {
        (
            p.resolution != target,
            !is_ours(p, &coords.name, leaf),
            p.id,
        )
    });
    let Some((kept, duplicates)) = candidates.split_first() else {
        return Ok((matches, false));
    };
    if duplicates.is_empty() {
        return Ok((matches, false));
    }
    let duplicates: Vec<usize> = duplicates.iter().map(|p| p.id).collect();
    if !lock.merge_packages(kept.id, &duplicates)? {
        warnings.push(VendorWarning::new(
            "vendor_bun_lockb_duplicate_records",
            format!(
                "{LOCK} has {} records of {}@{} that cannot be folded into one, so each is \
                 rewired to the same tarball; Bun's isolated linker can fail to install two \
                 records with one tarball (EEXIST); the hoisted linker \
                 (`[install] linker = \"hoisted\"` in bunfig.toml) installs it",
                duplicates.len() + 1,
                coords.name,
                coords.version
            ),
        ));
        return Ok((matches, false));
    }
    let matches = lock
        .packages()?
        .into_iter()
        .filter(|p| is_target(p, coords, leaf) && !p.bundled_only)
        .collect();
    Ok((matches, true))
}

/// [`BunBinaryBackend`] through the shared driver, under the signature the
/// suite below calls it by.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn vendor(
    purl: &str,
    _installed_dir: super::source::PackageSource<'_>,
    root: &Path,
    record: &PatchRecord,
    _sources: &crate::patch::apply::PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    _force: bool,
    service: Option<&super::VendorServiceConfig>,
) -> VendorOutcome {
    super::npm_common::vendor_npm_family(
        &BunBinaryBackend,
        super::npm_common::NpmVendorRequest {
            purl,
            project_root: root,
            record,
            vendored_at,
            dry_run,
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
            user_tarballs,
        } = preflight_package(&project, root, coords, &leaf)?;
        refuse_ignored_mirrors(root, &mirrors).await?;
        warnings.extend(super::bun_lock::default_trust_warning(
            project.manifest.as_deref(),
            None,
            &coords.name,
            &coords.version,
        ));
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
        for package in user_tarballs {
            // LOUD: bun installs this copy from its own URL / `file:`
            // resolution, which vendoring does not touch (#497).
            warnings.push(VendorWarning::new(
                "vendor_non_registry_entry_skipped",
                super::bun_lock::user_tarball_detail(
                    &format!("{LOCK} package #{}", package.id),
                    &coords.name,
                    &coords.version,
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
        warnings: &mut Vec<VendorWarning>,
    ) -> Result<Option<NpmCommit>, String> {
        let BunBinaryPlan {
            mut lock,
            leaf,
            matches,
            mirrors,
        } = plan;
        let (root, coords) = (cx.project_root, cx.coords);
        let mut wiring = Vec::new();
        let (matches, merged) =
            merge_duplicates(&mut lock, matches, &staged.rel_tgz, coords, &leaf, warnings)?;
        // The lock every record snapshot of this run restores toward, read
        // off the lock before its first edit.
        let mut origin = None;
        for package in matches {
            if package.resolution == staged.rel_tgz
                && package.integrity.as_deref() == Some(&staged.packed.integrity)
            {
                continue;
            }
            if origin.is_none() {
                origin = Some(unvendored_lock(root, &lock).await);
            }
            let origin = origin.as_ref().expect("set just above");
            let original = lock.snapshot_toward(package.id, origin)?;
            lock.set_package(package.id, &staged.rel_tgz, &staged.packed.integrity)?;
            let mut new = lock.rewritten_snapshot(package.id)?;
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
        // consumer by committing identical tarballs at the member-relative
        // locations of the members that depend on the package, as well as
        // the canonical root artifact.
        let artifact = read_regular_to_bytes_sync(&root.join(&staged.rel_tgz))
            .map_err(|e| format!("cannot read staged tarball: {e}"))?;
        let lock_changed = merged || !wiring.is_empty();
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
            if before.as_deref() != Some(artifact.as_slice()) {
                if let Err(e) =
                    tokio::fs::create_dir_all(path.parent().expect("mirror parent")).await
                {
                    undo_mirrors(&mirror_backups).await;
                    return Err(format!("cannot create workspace vendor directory: {e}"));
                }
                if let Err(e) = atomic_write_bytes_preserving_mode(&path, &artifact).await {
                    undo_mirrors(&mirror_backups).await;
                    return Err(format!("cannot write workspace tarball {rel}: {e}"));
                }
                mirror_backups.push((path, before));
            }
            if let Err(e) = restore_mirror_metadata(root, rel).await {
                undo_mirrors(&mirror_backups).await;
                return Err(e);
            }
        }
        if let Err(e) = probe_mirrors(root, &mirrors, warnings).await {
            undo_mirrors(&mirror_backups).await;
            return Err(e);
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

/// `lock` with every package the ledger records as vendored into it
/// restored: the lock a full revert would leave now, which each snapshot
/// taken of `lock` records as its origin ([`BunLockb::snapshot_toward`]),
/// so the packages of one lock all restore toward the same one. A record
/// that no longer matches the lock, or cannot be restored, stays as it is,
/// as it would in that revert.
async fn unvendored_lock(root: &Path, lock: &BunLockb) -> BunLockb {
    let mut origin = lock.clone();
    let Ok(state) = super::state::load_state(root).await else {
        return origin;
    };
    let mut earlier = Origin::default();
    let records = state
        .entries
        .values()
        .flat_map(|entry| entry.wiring.iter().rev())
        .filter(|rec| rec.file == LOCK && rec.kind == KIND);
    for rec in records {
        let (Some(original), Some(new)) = (&rec.original, &rec.new) else {
            continue;
        };
        let Some(id) = rec.key.as_deref().and_then(|key| key.parse().ok()) else {
            continue;
        };
        let Ok(Some(id)) = origin.find_snapshot_id(id, new) else {
            continue;
        };
        if origin.restore_toward(id, original, &earlier).is_ok() {
            earlier.merge(&Origin::of(original));
        }
    }
    origin
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
    /// The root `package.json` text, `None` when unreadable.
    manifest: Option<String>,
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
    let manifest = super::bun_lock::read_manifest(root).await;
    let user_patched = super::bun_lock_text::patched_dependency_keys(manifest.as_deref(), None);
    Ok(BinaryProject {
        lock,
        packages,
        user_patched,
        manifest,
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
    /// User URL / `file:` tarball records of the same version (#497): bun
    /// installs them from their own resolution, so they stay unpatched.
    user_tarballs: Vec<BinaryPackage>,
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
    super::bun_lock::refuse_user_patched(&project.user_patched, coords)?;
    let (bundled_only, matches): (Vec<_>, Vec<_>) = project
        .packages
        .iter()
        .filter(|p| is_target(p, coords, leaf))
        .cloned()
        .partition(|p| p.bundled_only);
    let bundled: Vec<_> = matches
        .iter()
        .filter(|p| p.bundled)
        .chain(&bundled_only)
        .cloned()
        .collect();
    let user_tarballs: Vec<_> = project
        .packages
        .iter()
        .filter(|p| {
            p.name == coords.name
                && p.version.is_none()
                && !p.bundled_only
                && user_tarball_version(&coords.name, &p.resolution)
                    == Some(coords.version.as_str())
        })
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
    if matches.is_empty() && !user_tarballs.is_empty() {
        // The package IS locked, from a URL / `file:` resolution bun
        // installs as written (#497): "run `bun install`" would not help.
        let ids: Vec<String> = user_tarballs.iter().map(|p| format!("#{}", p.id)).collect();
        return Err(Box::new(refused(
            "vendor_lock_entry_not_rewritable",
            format!(
                "every {LOCK} record for {}@{} ({}) installs it from a URL or local tarball, \
                 not the registry, and cannot be rewritten — those copies stay UNPATCHED and \
                 `bun install` will not help; depend on the registry release to vendor it",
                coords.name,
                coords.version,
                ids.join(", ")
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
    let targets: Vec<usize> = matches.iter().map(|p| p.id).collect();
    let mirrors = match project
        .lock
        .workspace_paths_reaching(&targets)
        .and_then(|paths| {
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
        user_tarballs,
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

/// The [`Origin`] of the `bun.lockb` at each project root, as the entries
/// reverted there so far in this process recorded it. A revert undoes one
/// ledger entry, and the caller drops that entry before it asks for the
/// next. A ledger written before every snapshot recorded the lock's one
/// origin holds the pre-vendor lock in the entry vendored first only; when
/// that entry is not the last one reverted, this is how the last one still
/// gets it. Forgotten once the lock holds no vendored package.
static REVERTED_ORIGINS: Mutex<Vec<(PathBuf, Origin)>> = Mutex::new(Vec::new());

fn reverted_origin(root: &Path) -> Origin {
    let origins = REVERTED_ORIGINS
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let known = origins.iter().find(|(known, _)| known == root);
    known.map(|(_, origin)| origin.clone()).unwrap_or_default()
}

fn remember_reverted_origin(root: &Path, origin: Option<Origin>) {
    let mut origins = REVERTED_ORIGINS
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    origins.retain(|(known, _)| known != root);
    if let Some(origin) = origin {
        origins.push((root.to_path_buf(), origin));
    }
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
    let (mut lock, original_bytes) = match read_regular_to_bytes_sync(&root.join(LOCK)) {
        Ok(bytes) => match BunLockb::parse(&bytes) {
            Ok(v) => (RevertLock::Binary(v), bytes),
            Err(e) => return RevertOutcome::failed(e),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if entry.wiring.is_empty() && opts.keep_artifact {
                return outcome;
            }
            // `bun install --save-text-lockfile` deletes bun.lockb and
            // carries the vendored tuples into bun.lock (#784): restore the
            // recorded registry packages there instead.
            match read_regular_to_string(&root.join(TEXT_LOCK)).await {
                Ok(text) => (
                    RevertLock::Migrated(text.split('\n').map(str::to_string).collect()),
                    text.into_bytes(),
                ),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return RevertOutcome::failed(format!(
                        "{LOCK} is missing; cannot safely revert the binary lock"
                    ));
                }
                Err(e) => return RevertOutcome::failed(format!("cannot read {TEXT_LOCK}: {e}")),
            }
        }
        Err(e) => return RevertOutcome::failed(format!("cannot read {LOCK}: {e}")),
    };
    if !entry.wiring.iter().any(|rec| rec.kind == KIND) && !opts.keep_artifact {
        let referenced = match &lock {
            RevertLock::Binary(lock) => lock.packages().map(|packages| {
                packages
                    .iter()
                    .any(|p| parse_vendor_path(&p.resolution).is_some_and(|p| p.uuid == entry.uuid))
            }),
            RevertLock::Migrated(lines) => Ok(lines
                .iter()
                .any(|line| migrated_vendor_uuid(line).as_deref() == Some(entry.uuid.as_str()))),
        };
        if referenced != Ok(false) {
            return RevertOutcome::failed(format!(
                "{} still references {} but the original wiring is missing",
                lock.file(),
                entry.uuid
            ));
        }
    }
    // Several binary records can carry different registry originals, which
    // the migration collapsed into the same text entries: never guess which
    // one each entry had.
    let originals: Vec<_> = entry
        .wiring
        .iter()
        .filter(|rec| rec.kind == KIND)
        .filter_map(|rec| rec.original.as_ref())
        .collect();
    let ambiguous_migration = matches!(lock, RevertLock::Migrated(_))
        && originals.windows(2).any(|pair| {
            ["name", "version", "resolution", "integrity"]
                .iter()
                .any(|key| pair[0].get(key) != pair[1].get(key))
        });
    // REMOVED, not drift (#1132): `bun remove <pkg>` (or an upgrade off the
    // patched version) leaves neither snapshot in the lock. When no package
    // resolves through this uuid dir any more, there is nothing to restore
    // and nothing an install needs the artifact for. Probed once, before any
    // record is restored; an unreadable package table fails closed (drift).
    let uuid_lower = entry.uuid.to_ascii_lowercase();
    let unreferenced = match &lock {
        RevertLock::Binary(lock) => lock.packages().is_ok_and(|packages| {
            !packages
                .iter()
                .any(|p| p.resolution.to_ascii_lowercase().contains(&uuid_lower))
        }),
        RevertLock::Migrated(_) => false,
    };
    let earlier = reverted_origin(root);
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
                    // Gone already: its `<uuid>/.gitignore` still goes.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Some(path)),
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
            // A same-uuid re-vendor on the migrated bun.lock re-pins our own
            // tuple as a text record next to the binary records it carried
            // forward (#784): restore it like the text revert does.
            if let RevertLock::Migrated(lines) = &mut lock {
                if rec.file == TEXT_LOCK && rec.kind == super::bun_lock::KIND_LOCK_PACKAGE {
                    let mut dirty = false;
                    // `false`: bun.lockb migrations stay outside the #1155
                    // upgrade path, so a moved default-registry tuple keeps
                    // its drift verdict here.
                    super::bun_lock::revert_one_record(
                        lines,
                        rec,
                        &entry.uuid,
                        false,
                        &mut dirty,
                        &mut outcome.warnings,
                    );
                    return Ok(false);
                }
            }
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
            let lock = match &mut lock {
                RevertLock::Binary(lock) => lock,
                RevertLock::Migrated(_) if ambiguous_migration => {
                    return Err(format!(
                        "binary package #{id} has a different registry original than another \
                         record of this package, and {TEXT_LOCK} no longer tells them apart"
                    ));
                }
                RevertLock::Migrated(lines) => {
                    if !restore_migrated(lines, original, &entry.uuid)? {
                        outcome.warnings.push(VendorWarning::new(
                            super::LOCK_ENTRY_REMOVED_CODE,
                            format!(
                                "{TEXT_LOCK} has no entry for binary package #{id}; nothing to \
                                 restore"
                            ),
                        ));
                    }
                    return Ok(false);
                }
            };
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
            lock.restore_toward(id, original, &earlier).map(|()| false)
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
    // The artifact goes only when no record still installs from it: one the
    // ledger has no record of wiring keeps it (and its member copies), with
    // the recorded ones restored. Checked on a dry run too.
    if let (RevertLock::Binary(lock), false) = (&lock, opts.keep_artifact) {
        let wired = lock.packages().map(|packages| {
            packages.into_iter().find(|p| {
                parse_vendor_path(&p.resolution)
                    .is_some_and(|path| path.eco == "npm" && path.uuid == entry.uuid)
            })
        });
        let unrecorded = match wired {
            Ok(None) => None,
            Ok(Some(package)) => Some(format!("package #{} ({})", package.id, package.name)),
            Err(e) => Some(format!("package table ({e})")),
        };
        if let Some(what) = unrecorded {
            outcome.warnings.push(VendorWarning::new(
                super::RESIDUAL_REFERENCE_CODE,
                format!(
                    "{LOCK} {what} still installs from {dir} and the vendor ledger has no \
                     record of wiring it; point it back at the registry release (`bun install` \
                     after restoring the dependency's version) and re-run the revert"
                ),
            ));
            outcome.keep_artifact_for_reference(&dir);
        }
    }
    if opts.dry_run {
        return outcome;
    }
    let bytes = match &lock {
        RevertLock::Binary(lock) => lock.bytes(),
        RevertLock::Migrated(lines) => lines.join("\n").into_bytes(),
    };
    if bytes != original_bytes {
        if let Err(e) = atomic_write_bytes_preserving_mode(&root.join(lock.file()), &bytes).await {
            return RevertOutcome::failed(format!("cannot write {}: {e}", lock.file()));
        }
    }
    if let RevertLock::Binary(lock) = &lock {
        let mut origin = earlier;
        for original in entry.wiring.iter().filter(|rec| rec.kind == KIND) {
            if let Some(original) = &original.original {
                origin.merge(&Origin::of(original));
            }
        }
        let still_vendored = lock.packages().is_ok_and(|packages| {
            packages
                .iter()
                .any(|p| parse_vendor_path(&p.resolution).is_some())
        });
        remember_reverted_origin(root, still_vendored.then_some(origin));
    }
    if !opts.keep_artifact && !outcome.kept_artifact {
        if matches!(lock, RevertLock::Migrated(_))
            && super::npm_flavor::keep_artifact_while_lock_references_it(
                &mut outcome,
                root,
                &[TEXT_LOCK],
                &entry.uuid,
                &dir,
            )
            .await
        {
            return outcome;
        }
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

/// The lock a binary entry's wiring is reverted in.
enum RevertLock {
    Binary(BunLockb),
    /// The `bun.lock` Bun migrated the binary lock to, as lines (#784).
    Migrated(Vec<String>),
}

impl RevertLock {
    fn file(&self) -> &'static str {
        match self {
            RevertLock::Binary(_) => LOCK,
            RevertLock::Migrated(_) => TEXT_LOCK,
        }
    }
}

/// The vendor uuid a `bun.lock` package line's local tarball tuple points
/// into, if it is one.
fn migrated_vendor_uuid(line: &str) -> Option<String> {
    let entry = parse_entry_line(line).ok()?;
    if !matches!(entry.elems.len(), 2 | 3) || !entry.elems[1].starts_with('{') {
        return None;
    }
    let spec = decode_json_string(&entry.elems[0])?;
    let vendored = parse_vendor_path(split_name_spec(&spec)?.1)?;
    (vendored.eco == "npm").then_some(vendored.uuid)
}

/// The registry tuple Bun writes in `bun.lock` for the binary `original`
/// snapshot, in place of `line`: that package's vendored tuple in a
/// `bun.lock` Bun migrated from the binary lock (#784). The key, indent,
/// dependency object and trailing comma stay verbatim, as Bun carried them
/// over. Bun leaves the registry slot empty for a tarball under its default
/// registry and writes the full URL for any other.
pub(crate) fn migrated_registry_line(line: &str, original: &serde_json::Value) -> Option<String> {
    let entry = parse_entry_line(line).ok()?;
    if !matches!(entry.elems.len(), 2 | 3) || !entry.elems[1].starts_with('{') {
        return None;
    }
    let field = |key| original.get(key).and_then(serde_json::Value::as_str);
    let (name, version) = (field("name")?, field("version")?);
    let (resolution, integrity) = (field("resolution")?, field("integrity")?);
    let spec = decode_json_string(&entry.elems[0])?;
    let (spec_name, path) = split_name_spec(&spec)?;
    let vendored = parse_vendor_path(path)?;
    if spec_name != name || vendored.eco != "npm" || vendored.leaf != tgz_rel_leaf(name, version) {
        return None;
    }
    let slot = if resolution.starts_with("https://registry.npmjs.org") {
        ""
    } else {
        resolution
    };
    let json = |s: &str| serde_json::to_string(s).expect("a str serializes to JSON");
    Some(format!(
        "{indent}{key}: [{spec}, {slot}, {deps}, {integrity}]{comma}{cr}",
        indent = entry.indent,
        key = entry.key_raw,
        spec = json(&format!("{name}@{version}")),
        slot = json(slot),
        deps = entry.elems[1],
        integrity = json(integrity),
        comma = if entry.trailing_comma { "," } else { "" },
        cr = if line.ends_with('\r') { "\r" } else { "" },
    ))
}

/// Put `original` back over every migrated `bun.lock` entry that still
/// resolves into `uuid`'s artifact. `false` when no entry does and none
/// already holds the restored tuple either (Bun dropped the package).
fn restore_migrated(
    lines: &mut [String],
    original: &serde_json::Value,
    uuid: &str,
) -> Result<bool, String> {
    let (start, end) =
        packages_bounds(lines).ok_or(format!("{TEXT_LOCK} has no packages section"))?;
    let restored = |line: &str| {
        let entry = parse_entry_line(line).ok()?;
        let integrity = original.get("integrity")?.as_str()?;
        let spec = format!(
            "{}@{}",
            original.get("name")?.as_str()?,
            original.get("version")?.as_str()?
        );
        (entry.elems.len() == 4
            && decode_json_string(&entry.elems[0]) == Some(spec)
            && decode_json_string(&entry.elems[3]).as_deref() == Some(integrity))
        .then_some(())
    };
    let mut found = false;
    for line in &mut lines[start + 1..end] {
        if migrated_vendor_uuid(line).as_deref() == Some(uuid) {
            *line = migrated_registry_line(line, original).ok_or_else(|| {
                format!("{TEXT_LOCK} entry for {uuid} no longer matches its binary original")
            })?;
            found = true;
        } else if restored(line).is_some() {
            found = true;
        }
    }
    Ok(found)
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

/// `<member>/.socket/vendor/npm/<uuid>`, the directory a workspace mirror
/// path (as [`validate_mirror_path`] accepts it) lives in.
fn mirror_uuid_dir_rel(rel: &str) -> Option<String> {
    let (workspace, artifact) = rel.rsplit_once("/.socket/vendor/npm/")?;
    let (uuid, _) = artifact.split_once('/')?;
    Some(format!("{workspace}/.socket/vendor/npm/{uuid}"))
}

/// The member uuid dirs (`<member>/.socket/vendor/npm/<uuid>`) a
/// `bun.lockb` workspace may mirror `uuid`'s tarball into: every member's,
/// since only the package (which this caller does not have) says which of
/// them depend on it, as the backend's own pre-flight asks. Empty when no
/// readable binary lock drives the installs.
pub(crate) fn workspace_mirror_dirs(root: &Path, uuid: &str) -> Vec<String> {
    if super::lock_inventory::bun_text_lock_drives(&super::lock_inventory::ProjectView::Disk(root))
    {
        return Vec::new();
    }
    read_regular_to_bytes_sync(&root.join(LOCK))
        .map_err(|e| e.to_string())
        .and_then(|bytes| BunLockb::parse(&bytes))
        .and_then(|lock| lock.workspace_paths())
        .map(|paths| {
            paths
                .iter()
                .map(|ws| format!("{}/.socket/vendor/npm/{uuid}", ws.trim_start_matches("./")))
                .collect()
        })
        .unwrap_or_default()
}

/// Refuse `vendor_artifact_gitignored` before anything is written when git
/// ignores a workspace mirror's uuid dir as a directory (a member's
/// `.socket/` rule, a root `packages/*/.socket/`): no `.gitignore` inside
/// it can re-include the mirror, so it would never reach the commit and a
/// fresh checkout's older Bun cannot install from it (#1116). File rules
/// such as `*.tgz` are left to the mirror's own `<uuid>/.gitignore`.
async fn refuse_ignored_mirrors(
    root: &Path,
    mirrors: &[(String, String)],
) -> Result<(), Box<VendorOutcome>> {
    let dirs: Vec<String> = mirrors
        .iter()
        .filter_map(|(_, rel)| mirror_uuid_dir_rel(rel))
        .map(|dir| format!("{dir}/"))
        .collect();
    if dirs.is_empty() {
        return Ok(());
    }
    match super::npm_dir::gitignored(root, &dirs).await {
        Some(rules) => Err(Box::new(refused(
            super::npm_dir::GITIGNORED,
            super::npm_dir::gitignored_detail(&first_ignored(&rules, &dirs[0]), &rules),
        ))),
        None => Ok(()),
    }
}

/// Write the root artifact's `<uuid>/.gitignore` and `<uuid>/.gitattributes`
/// (#837) beside the workspace mirror `rel`; returns that uuid dir.
pub(super) async fn restore_mirror_metadata(root: &Path, rel: &str) -> Result<String, String> {
    let dir_rel = mirror_uuid_dir_rel(rel).ok_or("invalid workspace tarball path")?;
    super::npm_dir::restore_uuid_metadata(&root.join(&dir_rel))
        .await
        .map_err(|e| format!("cannot write {dir_rel}/.gitignore: {e}"))?;
    Ok(dir_rel)
}

/// Ask git, in one probe, whether it would commit every written workspace
/// mirror and the `<uuid>/.gitignore` and `<uuid>/.gitattributes` beside
/// it ([`restore_mirror_metadata`], which overrides file rules such as
/// Node.gitignore's `*.tgz`, #1116). Still ignored is an error (the caller
/// unwinds); git failing to answer is only a warning.
async fn probe_mirrors(
    root: &Path,
    mirrors: &[(String, String)],
    warnings: &mut Vec<VendorWarning>,
) -> Result<(), String> {
    let mut probe = Vec::new();
    for (_, rel) in mirrors {
        let dir_rel = mirror_uuid_dir_rel(rel).ok_or("invalid workspace tarball path")?;
        probe.push(rel.clone());
        probe.push(format!("{dir_rel}/.gitignore"));
        probe.push(format!("{dir_rel}/.gitattributes"));
    }
    if probe.is_empty() {
        return Ok(());
    }
    match super::npm_dir::gitignore_probe(root, &probe).await {
        Ok(Some(rules)) => Err(format!(
            "{}: {}",
            super::npm_dir::GITIGNORED,
            super::npm_dir::gitignored_detail(&first_ignored(&rules, &probe[0]), &rules)
        )),
        Ok(None) => Ok(()),
        Err(why) => {
            warnings.push(VendorWarning::new(
                super::npm_dir::GITIGNORE_UNCHECKED,
                super::npm_dir::gitignore_unchecked_detail(&probe[0], &why),
            ));
            Ok(())
        }
    }
}

/// The first path [`super::npm_dir::gitignored`]'s rules name
/// (`<source>:<line>:<pattern>\t<path>; ...`), without a trailing `/`;
/// `fallback` when they name none.
pub(super) fn first_ignored(rules: &str, fallback: &str) -> String {
    rules
        .split("; ")
        .next()
        .and_then(|rule| rule.rsplit_once('\t'))
        .map(|(_, path)| path.trim_end_matches('/').to_string())
        .filter(|path| !path.is_empty())
        .unwrap_or_else(|| fallback.trim_end_matches('/').to_string())
}

/// The `<uuid>/.gitignore` and `<uuid>/.gitattributes` beside a workspace
/// mirror that go with it on removal: only ours, byte for byte, and only
/// when nothing but the mirror itself (and the scope directory holding it)
/// is left in that uuid dir, so the member's `.socket/` can still be pruned.
fn mirror_metadata(path: &Path) -> Vec<PathBuf> {
    // `<member>/.socket/vendor/npm/<uuid>`: the ancestor under `vendor/npm`.
    let Some(dir) = path.ancestors().skip(1).find(|dir| {
        let npm = dir.parent();
        npm.and_then(Path::file_name).is_some_and(|n| n == "npm")
            && npm
                .and_then(Path::parent)
                .and_then(Path::file_name)
                .is_some_and(|n| n == "vendor")
    }) else {
        return Vec::new();
    };
    let mut metadata = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let child = entry.path();
        if path.starts_with(&child) {
            // The mirror, or the `@scope/` directory holding only it.
            if child != path
                && std::fs::read_dir(&child).map_or(true, |mut it| {
                    it.any(|e| e.map_or(true, |e| e.path() != path))
                })
            {
                return Vec::new();
            }
            continue;
        }
        let ours: fn(&[u8]) -> bool = match entry.file_name().to_str() {
            Some(".gitignore") => |b| b == super::npm_dir::UUID_GITIGNORE.as_bytes(),
            // Current or pre-#1541 bytes.
            Some(".gitattributes") => super::npm_dir::is_uuid_gitattributes,
            _ => return Vec::new(),
        };
        if !read_regular_to_bytes_sync(&child).is_ok_and(|b| ours(&b)) {
            return Vec::new();
        }
        metadata.push(child);
    }
    metadata
}

/// Remove a reverted workspace tarball, if still there (with its `<uuid>/.gitignore` and
/// `.gitattributes`, see [`mirror_metadata`]) and prune its emptied
/// parents through the workspace's `.socket/`, or queue all of them for
/// after the commit of a staged hosted takeover (see
/// `group_commit::defer_removal`).
pub(super) async fn remove_mirror(path: &Path) -> std::io::Result<()> {
    let bound = path
        .ancestors()
        .skip(1)
        .take(5)
        .find(|dir| dir.file_name().is_some_and(|name| name == ".socket"))
        .unwrap_or(path);
    let metadata = mirror_metadata(path);
    // A tarball already gone (deleted by hand) still takes its metadata.
    let present = tokio::fs::symlink_metadata(path).await.is_ok();
    let queue: Vec<&Path> = present
        .then_some(path)
        .into_iter()
        .chain(metadata.iter().map(PathBuf::as_path))
        .collect();
    if let Some((first, rest)) = queue.split_first() {
        if crate::utils::group_commit::defer_removal(first, bound) {
            for file in rest {
                crate::utils::group_commit::defer_removal(file, bound);
            }
            return Ok(());
        }
    }
    if present {
        tokio::fs::remove_file(path).await?;
    }
    for file in &metadata {
        let _ = tokio::fs::remove_file(file).await;
    }
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
            let metadata = mirror_metadata(path);
            let _ = tokio::fs::remove_file(path).await;
            for file in &metadata {
                let _ = tokio::fs::remove_file(file).await;
            }
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
        /// The package the fixture vendors.
        name: &'static str,
        version: &'static str,
    }

    impl Fixture {
        fn root(&self) -> &Path {
            self.tmp.path()
        }
        fn installed(&self) -> PathBuf {
            self.root().join("node_modules").join(self.name)
        }
        fn purl(&self) -> String {
            format!("pkg:npm/{}@{}", self.name, self.version)
        }
        fn leaf(&self) -> String {
            format!("{}-{}.tgz", self.name, self.version)
        }
    }

    impl ts::FlipFixture for Fixture {
        fn flip_root(&self) -> &Path {
            self.root()
        }
        fn flip_key(&self) -> String {
            self.purl()
        }
        fn flip_uuid(&self) -> String {
            UUID.to_string()
        }
        fn flip_artifact_rel(&self) -> String {
            format!(".socket/vendor/npm/{UUID}/{}", self.leaf())
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
        fixture_with(ORIGINAL)
    }

    fn fixture_with(lock: &[u8]) -> Fixture {
        fixture_for(lock, "minimist", "1.2.2")
    }

    /// The workspace fixture vendoring left-pad, the one package its
    /// `packages/helper` member depends on: the package that gets a
    /// member-relative tarball copy.
    fn member_fixture() -> Fixture {
        fixture_for(ORIGINAL, "left-pad", "1.3.0")
    }

    /// `name@version` as an installed package: the tree a local pack reads.
    fn install(root: &Path, name: &str, version: &str) -> PathBuf {
        let installed = root.join("node_modules").join(name);
        std::fs::create_dir_all(&installed).unwrap();
        std::fs::write(installed.join("package.json"), package_json(name, version)).unwrap();
        std::fs::write(installed.join("index.js"), BEFORE).unwrap();
        installed
    }

    fn package_json(name: &str, version: &str) -> Vec<u8> {
        format!(r#"{{"name":"{name}","version":"{version}"}}"#).into_bytes()
    }

    fn fixture_for(lock: &[u8], name: &'static str, version: &'static str) -> Fixture {
        assert!(name != "minimist" || package_json(name, version) == PACKAGE);
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join(LOCK), lock).unwrap();
        install(root, name, version);
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
        Fixture {
            tmp,
            record,
            name,
            version,
        }
    }

    pub(super) async fn flip_run(fx: &Fixture, cfg: Option<&VendorServiceConfig>) -> VendorOutcome {
        let blobs = fx.root().join(".socket/blobs");
        crate::vendor::test_support::vendor_bun(
            &fx.purl(),
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

    fn prebuilt_archive_of(package_json: &[u8]) -> Vec<u8> {
        let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (name, bytes) in [("package.json", package_json), ("index.js", AFTER)] {
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
        let fx = member_fixture();
        let archive = prebuilt_archive_of(&package_json(fx.name, fx.version));
        let server = MockServer::start().await;
        ts::mount_granted(&server, UUID, &fx.leaf(), &archive).await;
        let config = ts::service_cfg(&server.uri(), VendorSource::Service, false);
        let (result, entry, warnings) = ts::expect_done(flip_run(&fx, Some(&config)).await);
        assert!(result.success, "{result:?}");
        assert!(ts::has_warning(&warnings, "vendor_prebuilt_downloaded"));
        ts::persist(fx.root(), &fx.purl(), entry.unwrap()).await;
        let before = ts::snapshot(&fx).await;
        assert!(
            before.len() > 2,
            "fixture wires a workspace mirror: {:?}",
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

    /// REGRESSION (VBV-S2): a ledger whose copy of the original lock was
    /// cut short (and its recorded total raised to match) ended `vendor
    /// --revert` in a slice panic. The record is left alone as drift, with
    /// the reason, and the lock, the artifact and the entry stay.
    #[tokio::test]
    async fn revert_refuses_a_torn_layout_snapshot_in_the_ledger() {
        use base64::Engine as _;
        let pristine = include_bytes!("../../tests/fixtures/bun-lockb/0.8.1-production/bun.lockb");
        let fx = fixture_with(pristine);
        let root = fx.root();
        let (result, entry, _) = ts::expect_done(flip_run(&fx, None).await);
        assert!(result.success, "{result:?}");
        let mut entry = entry.expect("vendoring wires the binary lock");
        let vendored = std::fs::read(root.join(LOCK)).unwrap();
        let mut torn = pristine.to_vec();
        torn.extend_from_slice(b"xxx");
        let total_at = b"#!/usr/bin/env bun\nbun-lockfile-format-v0\n".len() + 4 + 32;
        let total = (torn.len() as u64).to_le_bytes();
        torn[total_at..total_at + 8].copy_from_slice(&total);
        let record = entry.wiring.iter_mut().find(|r| r.kind == KIND).unwrap();
        let original = record.original.as_mut().unwrap();
        assert!(original["layout_original"].is_string());
        original["layout_original"] =
            serde_json::json!(base64::engine::general_purpose::STANDARD.encode(&torn));
        for dry_run in [true, false] {
            let outcome = revert(&entry, root, RevertOpts::new(dry_run)).await;
            assert!(outcome.success && outcome.kept_artifact, "{outcome:?}");
            let drift = outcome
                .warnings
                .iter()
                .find(|w| w.code == "vendor_lock_entry_drifted")
                .unwrap_or_else(|| panic!("{outcome:?}"));
            assert!(drift.detail.contains("layout_original"), "{drift:?}");
            assert_eq!(std::fs::read(root.join(LOCK)).unwrap(), vendored);
            assert!(root.join(&entry.artifact.path).exists());
        }
    }

    // ── several packages in one lock (VBV-D1, VBV-P2, VBV-P5) ────────────

    const UUID_B: &str = "22222222-2222-4222-8222-222222222222";

    /// Vendor `name@version` (patch `uuid`) beside whatever the fixture
    /// already holds and record it in the ledger, as the CLI does after
    /// each package.
    async fn vendor_package(
        fx: &Fixture,
        name: &str,
        version: &str,
        uuid: &str,
    ) -> (String, VendorEntry) {
        let root = fx.root();
        let purl = format!("pkg:npm/{name}@{version}");
        let installed = install(root, name, version);
        let blobs = root.join(".socket/blobs");
        let (result, entry, _) = ts::expect_done(
            ts::vendor_bun(
                &purl,
                &installed,
                root,
                &ts::with_uuid(&fx.record, uuid),
                &PatchSources::blobs_only(&blobs),
                "",
                false,
                false,
                None,
            )
            .await,
        );
        assert!(result.success, "{purl}: {result:?}");
        let entry = entry.unwrap_or_else(|| panic!("{purl}: vendoring wires the lock"));
        ts::persist(root, &purl, entry.clone()).await;
        (purl, entry)
    }

    /// Revert the ledger entries `keys` in that order the way
    /// `vendor --revert` does: each from the ledger as it stands, each
    /// dropped from it once reverted. After each one the lock must still be
    /// one this codec edits, with the packages not yet reverted still wired.
    async fn revert_in_order(root: &Path, keys: &[&str], label: &str) {
        for (done, key) in keys.iter().enumerate() {
            let mut state = crate::vendor::state::load_state(root).await.unwrap();
            let entry = state.entries[*key].clone();
            let outcome = revert(&entry, root, RevertOpts::new(false)).await;
            assert!(
                outcome.success && !outcome.kept_artifact && outcome.warnings.is_empty(),
                "{label}, {key}: {outcome:?}"
            );
            assert!(!root.join(&entry.artifact.path).exists(), "{label}, {key}");
            state.entries.remove(*key);
            crate::vendor::state::save_state(root, &state)
                .await
                .unwrap();
            let lock = BunLockb::parse(&std::fs::read(root.join(LOCK)).unwrap()).unwrap();
            lock.validate_mutation()
                .unwrap_or_else(|e| panic!("{label}, {key}: {e}"));
            let wired: Vec<String> = lock
                .packages()
                .unwrap()
                .into_iter()
                .filter(|p| parse_vendor_path(&p.resolution).is_some())
                .map(|p| p.resolution)
                .collect();
            let expected: Vec<String> = keys[done + 1..]
                .iter()
                .map(|key| state.entries[*key].artifact.path.clone())
                .collect();
            assert_eq!(
                wired.iter().collect::<std::collections::BTreeSet<_>>(),
                expected.iter().collect::<std::collections::BTreeSet<_>>(),
                "{label}, after {key}"
            );
        }
    }

    /// `(label, pristine lock, the second package to vendor)`: a current
    /// lock, one whose workspace dependency flags an edit normalizes, a
    /// format-1 lock an edit promotes, and one whose string buffer an edit
    /// rebuilds. minimist@1.2.2 is the first package in each.
    const TWO_PACKAGE_LOCKS: [(&str, &[u8], (&str, &str)); 4] = [
        (
            "1.1.45",
            include_bytes!("../../tests/fixtures/bun-lockb/1.1.45/bun.lockb"),
            ("is-number", "7.0.0"),
        ),
        ("1.1.45 workspace", ORIGINAL, ("left-pad", "1.3.0")),
        (
            "0.1.1 (format 1)",
            include_bytes!("../../tests/fixtures/bun-lockb/0.1.1/bun.lockb"),
            ("is-number", "7.0.0"),
        ),
        (
            "0.8.1 production",
            include_bytes!("../../tests/fixtures/bun-lockb/0.8.1-production-complex/bun.lockb"),
            ("is-number", "7.0.0"),
        ),
    ];

    /// REGRESSION (VBV-D1): two packages vendored into one `bun.lockb`
    /// revert to its exact pre-vendor bytes whichever is reverted first.
    /// Reverted in vendoring order (the order of their purls, which is the
    /// order `vendor --revert` uses), the first package's tarball path used
    /// to stay in the string buffer behind the second's, and a lock an edit
    /// had to normalize stayed normalized: its exact bytes were recorded
    /// with the first package only and went with that ledger entry.
    #[tokio::test]
    async fn packages_of_one_lock_revert_to_its_exact_bytes_in_either_order() {
        for (label, pristine, (name, version)) in TWO_PACKAGE_LOCKS {
            for first_vendored_first in [true, false] {
                let label = format!("{label}, first vendored first: {first_vendored_first}");
                let fx = fixture_with(pristine);
                let root = fx.root();
                let (first, _) = vendor_package(&fx, "minimist", "1.2.2", UUID).await;
                let (second, _) = vendor_package(&fx, name, version, UUID_B).await;
                let mut order = [first.as_str(), second.as_str()];
                if !first_vendored_first {
                    order.reverse();
                }
                revert_in_order(root, &order, &label).await;
                assert!(
                    std::fs::read(root.join(LOCK)).unwrap() == pristine,
                    "{label}: the reverted lock is the pre-vendor lock"
                );
                assert!(!root.join(".socket/vendor").exists(), "{label}");
            }
        }
    }

    /// The ledger socket-patch 5.0 and 5.1 wrote for two packages of
    /// `pristine`: each record snapshots the lock as its own vendoring
    /// found it (so only the first holds the pre-vendor lock), and the
    /// rewritten record repeats the layout snapshot.
    async fn stepwise_ledger(root: &Path, pristine: &[u8], second: (&str, &str)) -> [String; 2] {
        use base64::Engine as _;
        let mut lock = BunLockb::parse(pristine).unwrap();
        let mut state = crate::vendor::state::VendorState::new();
        let mut keys = Vec::new();
        for ((name, version), uuid) in [("minimist", "1.2.2"), second]
            .into_iter()
            .zip([UUID, UUID_B])
        {
            let id = lock
                .packages()
                .unwrap()
                .into_iter()
                .find(|p| p.name == name && p.version.as_deref() == Some(version))
                .unwrap()
                .id;
            let rel = format!(".socket/vendor/npm/{uuid}/{name}-{version}.tgz");
            let tarball = format!("{name} tarball");
            std::fs::create_dir_all(root.join(&rel).parent().unwrap()).unwrap();
            std::fs::write(root.join(&rel), &tarball).unwrap();
            let integrity = format!(
                "sha512-{}",
                base64::engine::general_purpose::STANDARD
                    .encode(<sha2::Sha512 as sha2::Digest>::digest(&tarball))
            );
            let original = lock.snapshot(id).unwrap();
            lock.set_package(id, &rel, &integrity).unwrap();
            let rewritten = lock.snapshot(id).unwrap();
            let purl = format!("pkg:npm/{name}@{version}");
            let entry: VendorEntry = serde_json::from_value(serde_json::json!({
                "ecosystem": "npm", "basePurl": purl, "uuid": uuid, "flavor": "bun",
                "artifact": { "path": rel, "sha256": "" },
                "wiring": [{
                    "file": LOCK, "kind": KIND, "action": "rewritten", "key": id.to_string(),
                    "original": original, "new": rewritten,
                }],
            }))
            .unwrap();
            state.entries.insert(purl.clone(), entry);
            keys.push(purl);
        }
        std::fs::write(root.join(LOCK), lock.bytes()).unwrap();
        crate::vendor::state::save_state(root, &state)
            .await
            .unwrap();
        [keys.remove(0), keys.remove(0)]
    }

    /// VBV-D1 for a ledger an earlier release wrote: reverted in one run,
    /// in either order, its packages still come back to the exact lock.
    /// The pre-vendor lock is recorded with the first package only, so that
    /// package's revert hands it on to the ones reverted after it.
    #[tokio::test]
    async fn an_earlier_releases_ledger_reverts_to_the_exact_lock_in_either_order() {
        for (label, pristine, second) in TWO_PACKAGE_LOCKS {
            for first_vendored_first in [true, false] {
                let label = format!("{label}, first vendored first: {first_vendored_first}");
                let tmp = tempfile::tempdir().unwrap();
                let root = tmp.path();
                let [first, second] = stepwise_ledger(root, pristine, second).await;
                let mut order = [first.as_str(), second.as_str()];
                if !first_vendored_first {
                    order.reverse();
                }
                revert_in_order(root, &order, &label).await;
                assert!(
                    std::fs::read(root.join(LOCK)).unwrap() == pristine,
                    "{label}: the reverted lock is the pre-vendor lock"
                );
            }
        }
    }

    /// REGRESSION (VBV-P2): a lock an edit must normalize is recorded whole
    /// so a revert can put its exact bytes back. It is recorded with the
    /// pre-vendor record only: the copy that used to sit in the rewritten
    /// record too was never read, and doubled a ledger that already holds
    /// one copy per package.
    #[tokio::test]
    async fn a_normalized_lock_is_recorded_once_per_wiring_record() {
        let pristine =
            include_bytes!("../../tests/fixtures/bun-lockb/0.8.1-production-complex/bun.lockb");
        let fx = fixture_with(pristine);
        let (_, first) = vendor_package(&fx, "minimist", "1.2.2", UUID).await;
        let (_, second) = vendor_package(&fx, "is-number", "7.0.0", UUID_B).await;
        for entry in [&first, &second] {
            let record = entry.wiring.iter().find(|r| r.kind == KIND).unwrap();
            let original = record.original.as_ref().unwrap();
            let layout = original["layout_original"].as_str().expect("the lock");
            let rewritten = record.new.as_ref().unwrap();
            assert!(rewritten.get("layout_original").is_none(), "{rewritten}");
            assert!(
                serde_json::to_string(record).unwrap().len() < layout.len() + 2048,
                "one copy of the lock per record"
            );
        }
        let ledger = std::fs::read(fx.root().join(".socket/vendor/state.json")).unwrap();
        assert!(
            ledger.len() < 2 * (pristine.len() * 4 / 3 + 4096),
            "{} bytes for two packages of a {}-byte lock",
            ledger.len(),
            pristine.len()
        );
    }

    /// REGRESSION (VBV-P5): a member gets its own copy of a vendored
    /// tarball only when its dependencies reach the package. The fixture's
    /// root depends on minimist and its `packages/helper` member on
    /// left-pad alone: minimist is not copied into the member, left-pad is.
    #[tokio::test]
    async fn a_member_gets_a_tarball_copy_only_of_what_it_depends_on() {
        let fx = flip_fixture().await;
        let root = fx.root();
        let (minimist, entry) = vendor_package(&fx, "minimist", "1.2.2", UUID).await;
        assert_eq!(mirror_rels(&entry), [] as [String; 0]);
        assert!(!root.join("packages/helper/.socket").exists());
        super::super::bun_workspace::verify(root, &entry)
            .await
            .unwrap();

        let (left_pad, entry) = vendor_package(&fx, "left-pad", "1.3.0", UUID_B).await;
        let copy = format!("packages/helper/.socket/vendor/npm/{UUID_B}/left-pad-1.3.0.tgz");
        assert_eq!(mirror_rels(&entry), [copy.clone()]);
        assert_eq!(
            std::fs::read(root.join(&copy)).unwrap(),
            std::fs::read(root.join(&entry.artifact.path)).unwrap()
        );
        super::super::bun_workspace::verify(root, &entry)
            .await
            .unwrap();
        assert!(!root
            .join(format!("packages/helper/.socket/vendor/npm/{UUID}"))
            .exists());

        revert_in_order(root, &[&left_pad, &minimist], "member copies").await;
        assert!(std::fs::read(root.join(LOCK)).unwrap() == ORIGINAL);
        assert!(!root.join("packages/helper/.socket").exists());
    }

    /// VBV-P5: releases before this one copied every vendored tarball into
    /// every member. Such a copy is still in the ledger: a revert removes
    /// it, and a health check does not ask for it back.
    #[tokio::test]
    async fn a_copy_an_earlier_release_made_in_every_member_is_still_reverted() {
        let fx = flip_fixture().await;
        let root = fx.root();
        let (minimist, mut entry) = vendor_package(&fx, "minimist", "1.2.2", UUID).await;
        let copy = format!("packages/helper/.socket/vendor/npm/{UUID}/minimist-1.2.2.tgz");
        let tarball = std::fs::read(root.join(&entry.artifact.path)).unwrap();
        std::fs::create_dir_all(root.join(&copy).parent().unwrap()).unwrap();
        std::fs::write(root.join(&copy), &tarball).unwrap();
        restore_mirror_metadata(root, &copy).await.unwrap();
        entry.wiring.push(WiringRecord {
            file: copy.clone(),
            kind: MIRROR_KIND.into(),
            action: WiringAction::Added,
            key: Some("packages/helper".into()),
            original: None,
            new: Some(serde_json::Value::String(
                crate::utils::digest::sha256_hex_of(&tarball),
            )),
        });
        ts::persist(root, &minimist, entry.clone()).await;
        super::super::bun_workspace::verify(root, &entry)
            .await
            .unwrap();

        revert_in_order(root, &[&minimist], "earlier copy").await;
        assert!(std::fs::read(root.join(LOCK)).unwrap() == ORIGINAL);
        assert!(!root.join("packages/helper/.socket").exists());
    }

    /// The artifact goes only when no record still installs from it
    /// (VBV-D3's invariant, for the binary lock): a record the ledger has
    /// no wiring for that resolves into the uuid dir keeps the tarball and
    /// the ledger entry, while the recorded one is restored.
    #[tokio::test]
    async fn a_record_the_ledger_never_wired_keeps_the_artifact() {
        let pristine = include_bytes!("../../tests/fixtures/bun-lockb/1.1.45/bun.lockb");
        let fx = fixture_with(pristine);
        let root = fx.root();
        let (_, entry) = vendor_package(&fx, "minimist", "1.2.2", UUID).await;
        let mut lock = BunLockb::parse(&std::fs::read(root.join(LOCK)).unwrap()).unwrap();
        let packages = lock.packages().unwrap();
        let minimist = packages.iter().find(|p| p.name == "minimist").unwrap();
        let other = packages.iter().find(|p| p.name == "is-number").unwrap();
        lock.set_package(
            other.id,
            &entry.artifact.path,
            minimist.integrity.as_deref().unwrap(),
        )
        .unwrap();
        let both = lock.bytes();
        std::fs::write(root.join(LOCK), &both).unwrap();

        for dry_run in [true, false] {
            let outcome = revert(&entry, root, RevertOpts::new(dry_run)).await;
            assert!(outcome.success && outcome.kept_artifact, "{outcome:?}");
            assert!(outcome.kept_for_residual_reference(), "{outcome:?}");
            assert!(
                outcome
                    .warnings
                    .iter()
                    .any(|w| w.detail.contains("is-number")),
                "{outcome:?}"
            );
            assert!(root.join(&entry.artifact.path).exists());
            let live = std::fs::read(root.join(LOCK)).unwrap();
            assert_eq!(live == both, dry_run, "only the wet run restores");
            let packages = BunLockb::parse_packages(&live).unwrap();
            let version = |name: &str| {
                let package = packages.iter().find(|p| p.name == name).unwrap();
                package.version.clone()
            };
            assert_eq!(version("minimist").is_some(), !dry_run);
            assert_eq!(version("is-number"), None, "still the tarball");
        }
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
        let fx = member_fixture();
        let archive = prebuilt_archive_of(&package_json(fx.name, fx.version));
        let server = MockServer::start().await;
        ts::mount_granted(&server, UUID, &fx.leaf(), &archive).await;
        let root = fx.tmp.path();
        let config = ts::service_cfg(&server.uri(), VendorSource::Service, false);
        let mut prior: Option<VendorEntry> = None;
        for prebuilt in [true, false] {
            if !prebuilt {
                server.reset().await;
                ts::mount_granted(&server, UUID, &fx.leaf(), &ts::regzip(&archive)).await;
                // The committed artifact is missing (deleted, never
                // committed): reuse cannot apply, so acquisition runs.
                std::fs::remove_file(root.join(ts::FlipFixture::flip_artifact_rel(&fx))).unwrap();
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
            assert_eq!(mirror_rels(&entry).len(), 1, "the member's copy");
            for mirror in entry.wiring.iter().filter(|r| r.kind == MIRROR_KIND) {
                assert_eq!(std::fs::read(root.join(&mirror.file)).unwrap(), bytes);
            }
            ts::persist(root, &fx.purl(), entry.clone()).await;
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

    // ── git-ignored workspace mirrors (#1116) ─────────────────────────────

    fn mirror_rels(entry: &VendorEntry) -> Vec<String> {
        entry
            .wiring
            .iter()
            .filter(|r| r.kind == MIRROR_KIND)
            .map(|r| r.file.clone())
            .collect()
    }

    /// Node.gitignore's `*.tgz` ignores every tarball, the member mirrors
    /// included: each mirror's uuid dir gets the root artifact's `!*`
    /// `.gitignore`, so git commits it (and `repair` puts it back). A
    /// revert takes that metadata with the mirror, pruning the member's
    /// `.socket/`.
    #[tokio::test]
    async fn a_tgz_rule_still_commits_every_workspace_mirror() {
        let fx = member_fixture();
        let root = fx.root();
        if ts::git_project(root, "node_modules\n*.tgz\n").is_none() {
            return;
        }
        assert_eq!(
            super::super::npm_common::npm_tarball_gitignore_preflight(root, UUID).await,
            None,
            "a file rule does not stop a takeover"
        );
        let (result, entry, warnings) = ts::expect_done(flip_run(&fx, None).await);
        assert!(result.success, "{result:?}");
        assert!(
            !ts::has_warning(&warnings, super::super::npm_dir::GITIGNORE_UNCHECKED),
            "{warnings:?}"
        );
        let entry = entry.expect("vendoring wires the lock");
        let mirrors = mirror_rels(&entry);
        assert!(!mirrors.is_empty(), "fixture wires workspace mirrors");
        assert_eq!(
            super::super::npm_dir::gitignored(root, &mirrors).await,
            None,
            "git commits every mirror"
        );
        let gitignore = |rel: &str| Path::new(rel).parent().unwrap().join(".gitignore");
        for rel in &mirrors {
            assert_eq!(
                std::fs::read_to_string(root.join(gitignore(rel))).unwrap(),
                super::super::npm_dir::UUID_GITIGNORE,
                "{rel}"
            );
        }

        for rel in &mirrors {
            std::fs::remove_file(root.join(gitignore(rel))).unwrap();
        }
        super::super::bun_workspace::repair(root, &entry, false)
            .await
            .unwrap();
        assert_eq!(
            super::super::npm_dir::gitignored(root, &mirrors).await,
            None,
            "repair restores the mirrors' .gitignore"
        );

        // A mirror deleted by hand still takes its metadata on revert, and
        // so does a `.gitattributes` an older release wrote (#1541).
        std::fs::remove_file(root.join(&mirrors[0])).unwrap();
        for rel in &mirrors {
            let attributes = Path::new(rel).parent().unwrap().join(".gitattributes");
            std::fs::write(
                root.join(attributes),
                super::super::npm_dir::LEGACY_UUID_GITATTRIBUTES,
            )
            .unwrap();
        }
        ts::persist(root, &fx.purl(), entry.clone()).await;
        let outcome = revert(&entry, root, RevertOpts::new(false)).await;
        assert!(outcome.success, "{outcome:?}");
        assert_eq!(std::fs::read(root.join(LOCK)).unwrap(), ORIGINAL);
        for rel in &mirrors {
            let member = rel.split("/.socket/").next().unwrap();
            assert!(
                !root.join(member).join(".socket").exists(),
                "{member}/.socket is pruned with its mirror"
            );
        }
    }

    /// A rule that ignores a member's `.socket/` as a directory cannot be
    /// overridden from inside it, so vendoring refuses
    /// `vendor_artifact_gitignored` before writing anything, dry run
    /// included, rather than commit a lock whose member tarball never
    /// reaches the repository.
    #[tokio::test]
    async fn an_ignored_member_vendor_dir_refuses_before_any_write() {
        let workspaces = BunLockb::parse(ORIGINAL)
            .unwrap()
            .workspace_paths()
            .unwrap();
        let member = workspaces[0].trim_start_matches("./").to_string();
        let shapes = [
            (
                "member .socket/",
                format!("{member}/.gitignore"),
                ".socket/\n",
            ),
            (
                "root member glob",
                ".gitignore".into(),
                "node_modules\n*/**/.socket/\n",
            ),
        ];
        for (label, file, rules) in &shapes {
            for dry_run in [true, false] {
                let fx = member_fixture();
                let root = fx.root();
                if ts::git_project(root, "node_modules\n").is_none() {
                    return;
                }
                std::fs::create_dir_all(root.join(&file).parent().unwrap()).unwrap();
                std::fs::write(root.join(file), rules).unwrap();
                // The hosted takeover's pre-flight (run before it restores
                // the registry entry) refuses the same project.
                let takeover =
                    super::super::npm_common::npm_tarball_gitignore_preflight(root, UUID).await;
                assert_eq!(
                    takeover.map(|(code, _)| code),
                    Some("vendor_artifact_gitignored"),
                    "{label}: takeover pre-flight"
                );
                let blobs = root.join(".socket/blobs");
                let outcome = crate::vendor::test_support::vendor_bun(
                    &fx.purl(),
                    &fx.installed(),
                    root,
                    &fx.record,
                    &PatchSources::blobs_only(&blobs),
                    "",
                    dry_run,
                    false,
                    None,
                )
                .await;
                match outcome {
                    VendorOutcome::Refused { code, detail } => {
                        assert_eq!(code, "vendor_artifact_gitignored", "{label}: {detail}");
                        assert!(detail.contains(&member), "{label}: {detail}");
                    }
                    other => {
                        panic!("{label} (dry run {dry_run}): expected a refusal, got {other:?}")
                    }
                }
                assert_eq!(std::fs::read(root.join(LOCK)).unwrap(), ORIGINAL, "{label}");
                assert!(!root.join(".socket/vendor").exists(), "{label}");
                assert!(!root.join(&member).join(".socket").exists(), "{label}");
            }
        }
    }

    /// A refusal names the path git reports as ignored, not the first one
    /// probed: with members `a` and `b`, only `b` may be ignored.
    #[test]
    fn first_ignored_names_the_path_git_reports() {
        let rules = "packages/b/.gitignore:1:.socket/\tpackages/b/.socket/vendor/npm/u/; \
                     .gitignore:2:x\tpackages/c/.socket/vendor/npm/u/";
        assert_eq!(
            first_ignored(rules, "packages/a/.socket/vendor/npm/u/"),
            "packages/b/.socket/vendor/npm/u"
        );
        assert_eq!(first_ignored("", "packages/a/x/"), "packages/a/x");
    }

    // ── bun.lockb migrated to bun.lock (#784) ─────────────────────────────

    const MIGRATED_LOCKB: &[u8] = include_bytes!("../../tests/fixtures/bun-lockb/1.2.23/bun.lockb");
    /// `(migrating Bun, pristine bun.lock, vendored bun.lock)`: the 1.2.23
    /// fixture lock migrated by `bun install --save-text-lockfile` before
    /// and after vendoring (see that fixture directory's README).
    const MIGRATIONS: [(&str, &str, &str); 2] = [
        (
            "1.2.23",
            include_str!("../../tests/fixtures/bun-lockb/1.2.23-migrated/pristine-1.2.23.lock"),
            include_str!("../../tests/fixtures/bun-lockb/1.2.23-migrated/vendored-1.2.23.lock"),
        ),
        (
            "1.4.2",
            include_str!("../../tests/fixtures/bun-lockb/1.2.23-migrated/pristine-1.4.2.lock"),
            include_str!("../../tests/fixtures/bun-lockb/1.2.23-migrated/vendored-1.4.2.lock"),
        ),
    ];

    /// Vendor the binary fixture, then migrate it as `bun` would: bun.lockb
    /// is gone and bun.lock carries the vendored tuple.
    async fn vendored_then_migrated(vendored: &str) -> (Fixture, VendorEntry) {
        let fx = fixture_with(MIGRATED_LOCKB);
        let (result, entry, _) = ts::expect_done(flip_run(&fx, None).await);
        assert!(result.success, "{result:?}");
        let entry = entry.expect("vendoring rewires bun.lockb");
        ts::persist(fx.root(), PURL, entry.clone()).await;
        let integrity = entry.wiring[0].new.as_ref().unwrap()["integrity"]
            .as_str()
            .unwrap();
        if vendored.matches("sha512-").count() == 2 {
            assert!(
                vendored.contains(integrity),
                "the fixture was captured from this packing"
            );
        }
        std::fs::remove_file(fx.root().join(LOCK)).unwrap();
        std::fs::write(fx.root().join(TEXT_LOCK), vendored).unwrap();
        (fx, entry)
    }

    /// After Bun migrates a vendored bun.lockb to bun.lock, revert restores
    /// the registry tuple Bun itself writes for the pristine binary lock,
    /// instead of failing on the missing bun.lockb.
    #[tokio::test]
    async fn revert_restores_registry_tuple_after_text_lock_migration() {
        for (bun, pristine, vendored) in MIGRATIONS {
            let (fx, entry) = vendored_then_migrated(vendored).await;
            let dry =
                super::super::bun_lock::revert_bun_opts(&entry, fx.root(), RevertOpts::new(true))
                    .await;
            // The preview's only advisory is the reinstall one the real
            // revert also gives for the fixture's hoisted copy (#764).
            let dry_codes: Vec<&str> = dry.warnings.iter().map(|w| w.code).collect();
            assert!(
                dry.success && dry_codes == [super::super::bun_lock::REINSTALL_REQUIRED],
                "{bun}: {dry:?}"
            );
            assert_eq!(
                std::fs::read_to_string(fx.root().join(TEXT_LOCK)).unwrap(),
                vendored
            );
            let outcome =
                super::super::bun_lock::revert_bun_opts(&entry, fx.root(), RevertOpts::new(false))
                    .await;
            assert!(outcome.success, "{bun}: {outcome:?}");
            // The fixture's hoisted node_modules/minimist is the only
            // advisory: Bun keeps it after the restore (#764).
            let codes: Vec<&str> = outcome.warnings.iter().map(|w| w.code).collect();
            assert_eq!(
                codes,
                [super::super::bun_lock::REINSTALL_REQUIRED],
                "{bun}: {outcome:?}"
            );
            assert_eq!(
                std::fs::read_to_string(fx.root().join(TEXT_LOCK)).unwrap(),
                pristine,
                "{bun}"
            );
            assert!(!fx.root().join(LOCK).exists());
            assert!(!fx.root().join(".socket/vendor/npm").exists(), "{bun}");
        }
    }

    /// A superseding patch vendored on the migrated bun.lock rewrites our
    /// own tuple, so it records no original itself: the ledger must carry
    /// the binary record's registry original over to it, and revert must
    /// then restore the pristine tuple.
    #[tokio::test]
    async fn superseding_vendor_after_migration_keeps_the_registry_original() {
        const UUID2: &str = "22222222-2222-4222-8222-222222222222";
        for (bun, pristine, vendored) in MIGRATIONS {
            let (fx, _) = vendored_then_migrated(vendored).await;
            let record = PatchRecord {
                uuid: UUID2.to_string(),
                ..fx.record.clone()
            };
            let blobs = fx.root().join(".socket/blobs");
            let (result, entry, _) = ts::expect_done(
                crate::vendor::test_support::vendor_bun(
                    PURL,
                    &fx.installed(),
                    fx.root(),
                    &record,
                    &PatchSources::blobs_only(&blobs),
                    "",
                    false,
                    false,
                    None,
                )
                .await,
            );
            assert!(result.success, "{bun}: {result:?}");
            ts::persist(fx.root(), PURL, entry.expect("re-pinned")).await;
            let state = crate::vendor::state::load_state(fx.root()).await.unwrap();
            let entry = state.entries[PURL].clone();
            let minimist = pristine
                .lines()
                .find(|l| l.contains("\"minimist\": ["))
                .unwrap();
            assert_eq!(
                entry.wiring[0].original,
                Some(serde_json::Value::String(minimist.to_string())),
                "{bun}"
            );
            let outcome =
                super::super::bun_lock::revert_bun_opts(&entry, fx.root(), RevertOpts::new(false))
                    .await;
            assert!(outcome.success, "{bun}: {outcome:?}");
            // The fixture's hoisted node_modules/minimist is the only
            // advisory: Bun keeps it after the restore (#764).
            let codes: Vec<&str> = outcome.warnings.iter().map(|w| w.code).collect();
            assert_eq!(
                codes,
                [super::super::bun_lock::REINSTALL_REQUIRED],
                "{bun}: {outcome:?}"
            );
            assert_eq!(
                std::fs::read_to_string(fx.root().join(TEXT_LOCK)).unwrap(),
                pristine,
                "{bun}"
            );
        }
    }

    /// A same-uuid re-run on the migrated bun.lock (artifact missing, or the
    /// tuple's digest changed) re-pins our own tuple as a text record, and
    /// the ledger carries the binary records forward beside it. Revert must
    /// restore the pristine tuple from that mixed entry, not report the text
    /// record as drift and leave the project vendored.
    #[tokio::test]
    async fn same_uuid_repin_after_migration_reverts_the_mixed_entry() {
        for (bun, pristine, vendored) in MIGRATIONS {
            let (fx, first) = vendored_then_migrated(vendored).await;
            std::fs::remove_dir_all(fx.root().join(".socket/vendor/npm")).unwrap();
            let integrity = first.wiring[0].new.as_ref().unwrap()["integrity"]
                .as_str()
                .unwrap()
                .to_string();
            if vendored.contains(&integrity) {
                // Force a re-pin of the digest-carrying tuple too.
                let lock = vendored.replace(&integrity, "sha512-AAAA");
                std::fs::write(fx.root().join(TEXT_LOCK), lock).unwrap();
            }
            let blobs = fx.root().join(".socket/blobs");
            let (result, entry, _) = ts::expect_done(
                crate::vendor::test_support::vendor_bun(
                    PURL,
                    &fx.installed(),
                    fx.root(),
                    &fx.record,
                    &PatchSources::blobs_only(&blobs),
                    "",
                    false,
                    false,
                    None,
                )
                .await,
            );
            assert!(result.success, "{bun}: {result:?}");
            ts::persist(fx.root(), PURL, entry.expect("re-pinned")).await;
            let state = crate::vendor::state::load_state(fx.root()).await.unwrap();
            let entry = state.entries[PURL].clone();
            let kinds: Vec<_> = entry.wiring.iter().map(|r| r.kind.as_str()).collect();
            assert!(
                kinds.contains(&"bun_lock_package") && kinds.contains(&KIND),
                "{bun}: {kinds:?}"
            );
            let dry =
                super::super::bun_lock::revert_bun_opts(&entry, fx.root(), RevertOpts::new(true))
                    .await;
            // The preview's only advisory is the reinstall one the real
            // revert also gives for the fixture's hoisted copy (#764).
            let dry_codes: Vec<&str> = dry.warnings.iter().map(|w| w.code).collect();
            assert!(
                dry.success && dry_codes == [super::super::bun_lock::REINSTALL_REQUIRED],
                "{bun}: {dry:?}"
            );
            let outcome =
                super::super::bun_lock::revert_bun_opts(&entry, fx.root(), RevertOpts::new(false))
                    .await;
            assert!(outcome.success, "{bun}: {outcome:?}");
            // The fixture's hoisted node_modules/minimist is the only
            // advisory: Bun keeps it after the restore (#764).
            let codes: Vec<&str> = outcome.warnings.iter().map(|w| w.code).collect();
            assert_eq!(
                codes,
                [super::super::bun_lock::REINSTALL_REQUIRED],
                "{bun}: {outcome:?}"
            );
            assert_eq!(
                std::fs::read_to_string(fx.root().join(TEXT_LOCK)).unwrap(),
                pristine,
                "{bun}"
            );
            assert!(!fx.root().join(".socket/vendor/npm").exists(), "{bun}");
        }
    }

    /// Bun writes the full tarball URL for any registry but its default one,
    /// and the rebuilt tuple keeps the vendored line's spelling.
    #[test]
    fn migrated_registry_line_spells_the_registry_slot_like_bun() {
        let original = |resolution: &str| {
            serde_json::json!({
                "name": "@s/p", "version": "1.0.0", "resolution": resolution,
                "integrity": "sha512-AA==",
            })
        };
        let line = format!(
            "    \"x/@s/p\": [\"@s/p@.socket/vendor/npm/{UUID}/@s/p-1.0.0.tgz\", {{ \"bin\": {{}} }}],\r"
        );
        assert_eq!(
            migrated_registry_line(
                &line,
                &original("https://registry.npmjs.org/@s/p/-/p-1.0.0.tgz")
            ),
            Some(
                "    \"x/@s/p\": [\"@s/p@1.0.0\", \"\", { \"bin\": {} }, \"sha512-AA==\"],\r"
                    .to_string()
            )
        );
        assert_eq!(
            migrated_registry_line(&line, &original("http://127.0.0.1:4873/@s/p/-/p-1.0.0.tgz")),
            Some(
                "    \"x/@s/p\": [\"@s/p@1.0.0\", \"http://127.0.0.1:4873/@s/p/-/p-1.0.0.tgz\", { \"bin\": {} }, \"sha512-AA==\"],\r"
                    .to_string()
            )
        );
        let other = serde_json::json!({
            "name": "@s/p", "version": "2.0.0",
            "resolution": "https://registry.npmjs.org/@s/p/-/p-2.0.0.tgz", "integrity": "sha512-AA==",
        });
        assert_eq!(
            migrated_registry_line(&line, &other),
            None,
            "another version's tarball"
        );
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

#[cfg(test)]
mod duplicate_tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::vendor::test_support as ts;

    /// The uuid the fixtures were first vendored under.
    const UUID: &str = "80630680-4da6-45f9-bba8-b888e0ffd58c";
    const BEFORE: &[u8] = b"module.exports = 'original';\n";
    const AFTER: &[u8] = b"module.exports = 'patched';\n";

    /// REGRESSION (#861): the vendored re-run after Bun gave a late
    /// dependent its own registry record of minimist@1.2.2, or of
    /// mkdirp@0.5.6 with its own dependency on minimist (`deps`; see
    /// `bun_lockb::tests::LATE_DEPENDENT`) leaves ONE record, the tarball,
    /// that every dependency edge resolves to — never two records with one
    /// tarball resolution, which the isolated linker installs into the same
    /// store directory (`EEXIST`). (The e2e `workspace_late_dependent_*`
    /// test reverts it through the first run's ledger.)
    #[tokio::test]
    async fn rerun_folds_the_late_registry_copy_into_the_tarball_record() {
        for name in [
            "1.3.9-late",
            "1.3.9-adder",
            "1.4.2-late",
            "1.4.2-adder",
            "1.3.9-deps-late",
            "1.3.9-deps-adder",
            "1.4.2-deps-late",
            "1.4.2-deps-adder",
        ] {
            let (package, version) = if name.contains("-deps-") {
                ("mkdirp", "0.5.6")
            } else {
                ("minimist", "1.2.2")
            };
            let purl = format!("pkg:npm/{package}@{version}");
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            let fixture = format!(
                "{}/tests/fixtures/bun-lockb/late-dependent/{name}.lockb",
                env!("CARGO_MANIFEST_DIR")
            );
            std::fs::copy(&fixture, root.join(LOCK)).unwrap();
            let installed = root.join("node_modules").join(package);
            std::fs::create_dir_all(&installed).unwrap();
            std::fs::write(
                installed.join("package.json"),
                format!(r#"{{"name":"{package}","version":"{version}"}}"#),
            )
            .unwrap();
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
            let (result, entry, warnings) = ts::expect_done(
                ts::vendor_bun(
                    &purl,
                    &installed,
                    root,
                    &record,
                    &PatchSources::blobs_only(&blobs),
                    "",
                    false,
                    false,
                    None,
                )
                .await,
            );
            assert!(result.success, "{name}: {result:?}");
            assert!(
                !ts::has_warning(&warnings, "vendor_bun_lockb_duplicate_records"),
                "{name}: {warnings:?}"
            );
            let entry = entry.expect("the lock changed");
            let lock = BunLockb::parse(&std::fs::read(root.join(LOCK)).unwrap()).unwrap();
            lock.validate_mutation().unwrap();
            let copies: Vec<_> = lock
                .packages()
                .unwrap()
                .into_iter()
                .filter(|p| p.name == package)
                .collect();
            assert_eq!(
                copies
                    .iter()
                    .map(|p| p.resolution.as_str())
                    .collect::<Vec<_>>(),
                [entry.artifact.path.as_str()],
                "{name}: one record per tarball resolution"
            );
        }
    }
}
