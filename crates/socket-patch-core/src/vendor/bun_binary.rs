//! Native binary Bun vendoring. Package records are edited without re-resolving
//! dependencies or requiring a Bun executable.
use super::bun_lock_text::{
    decode_json_string, packages_bounds, parse_entry_line, split_name_spec,
};
use super::bun_lockb::{BinaryPackage, BunLockb};
use super::common::{already_patched_result, refused};
use super::npm_common::{
    done_failure_unstage, gate_packages, guard_coordinates, guard_revert_uuid_dir, refusal_code,
    stage_patch_pack, tgz_rel_leaf, NpmCoords,
};
use super::path::parse_vendor_path;
use super::source::PackageSource;
use super::state::{
    write_marker_or_warn, VendorArtifact, VendorEntry, VendorMarker, WiringAction, WiringRecord,
};
use super::{RevertOpts, RevertOutcome, VendorOutcome, VendorWarning};
use crate::manifest::schema::PatchRecord;
use crate::patch::apply::PatchSources;
use crate::utils::fs::{
    atomic_write_bytes_preserving_mode, read_regular_to_bytes_sync, read_regular_to_string,
};
use std::path::{Path, PathBuf};

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
/// would. A record some bundled edge reaches is left to the rewrite: its
/// parent's tarball ships that copy. Where the lock's hoisting is not
/// exactly predictable ([`BunLockb::merge_packages`]) the records are all
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn vendor(
    purl: &str,
    installed_dir: PackageSource<'_>,
    root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
    service: Option<&super::VendorServiceConfig>,
) -> VendorOutcome {
    let coords = match guard_coordinates(purl, record) {
        Ok(v) => v,
        Err(o) => return *o,
    };
    let project = match read_project(root).await {
        Ok(v) => v,
        Err(o) => return *o,
    };
    let leaf = tgz_rel_leaf(&coords.name, &coords.version);
    let BinaryTargets {
        matches,
        mirrors,
        bundled,
    } = match preflight_package(&project, root, &coords, &leaf) {
        Ok(v) => v,
        Err(o) => return *o,
    };
    let BinaryProject { mut lock, .. } = project;
    let mut warnings = Vec::new();
    for package in bundled {
        // LOUD: this copy ships inside its PARENT's tarball, which we do not
        // repack — it stays the unpatched bytes after vendor (#469).
        warnings.push(super::VendorWarning::new(
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
    let preexisted = root.join(&coords.uuid_dir_rel).exists();
    let (staged, result) = match stage_patch_pack(
        purl,
        installed_dir,
        root,
        record,
        sources,
        dry_run,
        force,
        &mut warnings,
        service,
    )
    .await
    {
        Ok(v) => v,
        Err(o) => return *o,
    };
    let Some(staged) = staged else {
        return VendorOutcome::Done {
            result,
            entry: None,
            warnings,
        };
    };
    let mut wiring = Vec::new();
    let (matches, merged) = match merge_duplicates(
        &mut lock,
        matches,
        &staged.rel_tgz,
        &coords,
        &leaf,
        &mut warnings,
    ) {
        Ok(v) => v,
        Err(e) => {
            return done_failure_unstage(purl, e, root, &coords.uuid_dir_rel, preexisted).await
        }
    };
    for package in matches {
        if package.resolution == staged.rel_tgz
            && package.integrity.as_deref() == Some(&staged.packed.integrity)
        {
            continue;
        }
        let mutation = (|| {
            let original = lock.snapshot(package.id)?;
            lock.set_package(package.id, &staged.rel_tgz, &staged.packed.integrity)?;
            Ok::<_, String>((original, lock.snapshot(package.id)?))
        })();
        let (original, mut new) = match mutation {
            Ok(v) => v,
            Err(e) => {
                return done_failure_unstage(purl, e, root, &coords.uuid_dir_rel, preexisted).await
            }
        };
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
    let artifact = match read_regular_to_bytes_sync(&root.join(&staged.rel_tgz)) {
        Ok(bytes) => bytes,
        Err(e) => {
            return done_failure_unstage(
                purl,
                format!("cannot read staged tarball: {e}"),
                root,
                &coords.uuid_dir_rel,
                preexisted,
            )
            .await
        }
    };
    let lock_changed = merged || !wiring.is_empty();
    let mut mirror_backups: Vec<(PathBuf, Option<Vec<u8>>)> = Vec::new();
    for (workspace, rel) in &mirrors {
        let path = root.join(rel);
        let before = match read_regular_to_bytes_sync(&path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                undo_mirrors(&mirror_backups).await;
                return done_failure_unstage(
                    purl,
                    format!("cannot read workspace tarball {rel}: {e}"),
                    root,
                    &coords.uuid_dir_rel,
                    preexisted,
                )
                .await;
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
            return done_failure_unstage(
                purl,
                format!("cannot create workspace vendor directory: {e}"),
                root,
                &coords.uuid_dir_rel,
                preexisted,
            )
            .await;
        }
        if let Err(e) = atomic_write_bytes_preserving_mode(&path, &artifact).await {
            undo_mirrors(&mirror_backups).await;
            return done_failure_unstage(
                purl,
                format!("cannot write workspace tarball {rel}: {e}"),
                root,
                &coords.uuid_dir_rel,
                preexisted,
            )
            .await;
        }
        mirror_backups.push((path, before));
    }
    if !lock_changed && mirror_backups.is_empty() {
        return VendorOutcome::Done {
            result: already_patched_result(purl, &root.join(&staged.rel_tgz), &record.files),
            entry: None,
            warnings,
        };
    }
    if staged.staged_pkg_json.is_some() {
        warnings.push(VendorWarning::new("vendor_dep_manifest_stale", format!("the patch changes package.json; {LOCK} dependency edges were preserved — run bun install if dependency ranges changed")));
    }
    if let Err(e) = atomic_write_bytes_preserving_mode(&root.join(LOCK), &lock.bytes()).await {
        undo_mirrors(&mirror_backups).await;
        return done_failure_unstage(
            purl,
            format!("cannot write {LOCK}: {e}"),
            root,
            &coords.uuid_dir_rel,
            preexisted,
        )
        .await;
    }
    let marker = VendorMarker::new("npm", &coords.base_purl, record, vendored_at);
    write_marker_or_warn(&root.join(&coords.uuid_dir_rel), &marker, &mut warnings).await;
    VendorOutcome::Done {
        result,
        warnings,
        entry: Some(VendorEntry {
            ecosystem: "npm".into(),
            base_purl: coords.base_purl,
            uuid: record.uuid.clone(),
            artifact: VendorArtifact {
                yarn_berry10c0: None,
                path: staged.rel_tgz,
                sha256: staged.packed.sha256_hex,
                size: Some(staged.packed.size),
                platform_locked: None,
                file_inventory: None,
            },
            wiring,
            lock: None,
            took_over_go_patches: false,
            detached: false,
            record: None,
            flavor: Some("bun".into()),
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
        }),
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
        .filter(|p| is_target(p, coords, leaf))
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
        let restore = (|| {
            // A same-uuid re-vendor on the migrated bun.lock re-pins our own
            // tuple as a text record next to the binary records it carried
            // forward (#784): restore it like the text revert does.
            if let RevertLock::Migrated(lines) = &mut lock {
                if rec.file == TEXT_LOCK && rec.kind == super::bun_lock::KIND_LOCK_PACKAGE {
                    let mut dirty = false;
                    super::bun_lock::revert_one_record(
                        lines,
                        rec,
                        &entry.uuid,
                        &mut dirty,
                        &mut outcome.warnings,
                    );
                    return Ok(());
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
                    return Ok(());
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
                None if lock.find_snapshot_id(id, original)?.is_some() => return Ok(()),
                None => return Err("binary package resolution has drifted".into()),
            };
            lock.restore(id, original)
        })();
        if let Err(e) = restore {
            outcome
                .warnings
                .push(VendorWarning::new("vendor_lock_entry_drifted", e));
        }
    }
    if outcome.drift_skipped() {
        outcome.keep_artifact(&dir);
        return outcome;
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
    if !opts.keep_artifact {
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
            if let Err(e) = tokio::fs::remove_file(&mirror).await {
                return RevertOutcome::failed(format!(
                    "cannot remove workspace tarball {}: {e}",
                    mirror.display()
                ));
            }
            prune_mirror_parents(&mirror).await;
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
        fixture_with(ORIGINAL)
    }

    fn fixture_with(lock: &[u8]) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join(LOCK), lock).unwrap();
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
            assert!(dry.success && dry.warnings.is_empty(), "{bun}: {dry:?}");
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
            assert!(dry.success && dry.warnings.is_empty(), "{bun}: {dry:?}");
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
}

#[cfg(test)]
mod duplicate_tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::vendor::test_support as ts;

    /// The uuid the fixtures were first vendored under.
    const UUID: &str = "80630680-4da6-45f9-bba8-b888e0ffd58c";
    const PURL: &str = "pkg:npm/minimist@1.2.2";
    const BEFORE: &[u8] = b"module.exports = 'original';\n";
    const AFTER: &[u8] = b"module.exports = 'patched';\n";

    /// REGRESSION (#861): the vendored re-run after Bun gave a late
    /// dependent its own registry record of minimist@1.2.2 (see
    /// `bun_lockb::tests::LATE_DEPENDENT`) leaves ONE record, the tarball,
    /// that every dependency edge resolves to — never two records with one
    /// tarball resolution, which the isolated linker installs into the same
    /// store directory (`EEXIST`). (The e2e `workspace_late_dependent_*`
    /// test reverts it through the first run's ledger.)
    #[tokio::test]
    async fn rerun_folds_the_late_registry_copy_into_the_tarball_record() {
        for name in ["1.3.9-late", "1.3.9-adder", "1.4.2-late", "1.4.2-adder"] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            let fixture = format!(
                "{}/tests/fixtures/bun-lockb/late-dependent/{name}.lockb",
                env!("CARGO_MANIFEST_DIR")
            );
            std::fs::copy(&fixture, root.join(LOCK)).unwrap();
            let installed = root.join("node_modules/minimist");
            std::fs::create_dir_all(&installed).unwrap();
            std::fs::write(
                installed.join("package.json"),
                br#"{"name":"minimist","version":"1.2.2"}"#,
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
                    PURL,
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
            let minimist: Vec<_> = lock
                .packages()
                .unwrap()
                .into_iter()
                .filter(|p| p.name == "minimist")
                .collect();
            assert_eq!(
                minimist
                    .iter()
                    .map(|p| p.resolution.as_str())
                    .collect::<Vec<_>>(),
                [entry.artifact.path.as_str()],
                "{name}: one record per tarball resolution"
            );
        }
    }
}
