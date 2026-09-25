//! Native binary Bun vendoring. Package records are edited without re-resolving
//! dependencies or requiring a Bun executable.
use super::bun_lockb::{BinaryPackage, BunLockb};
use super::common::{already_patched_result, refused};
use super::npm_common::{
    done_failure_unstage, guard_coordinates, guard_revert_uuid_dir, stage_patch_pack, tgz_rel_leaf,
};
use super::path::parse_vendor_path;
use super::source::PackageSource;
use super::state::{
    write_marker_or_warn, VendorArtifact, VendorEntry, VendorMarker, WiringAction, WiringRecord,
};
use super::{RevertOpts, RevertOutcome, VendorOutcome, VendorWarning};
use crate::manifest::schema::PatchRecord;
use crate::patch::apply::PatchSources;
use crate::utils::fs::{atomic_write_bytes_preserving_mode, read_regular_to_bytes_sync};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub(crate) const LOCK: &str = "bun.lockb";
pub(crate) const KIND: &str = "bun_lockb_package";
const MIRROR_KIND: &str = "bun_lockb_workspace_artifact";

fn is_ours(package: &BinaryPackage, name: &str, leaf: &str) -> bool {
    package.name == name
        && parse_vendor_path(&package.resolution).is_some_and(|p| p.eco == "npm")
        && package.resolution.ends_with(&format!("/{leaf}"))
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
    if crate::utils::fs::is_symlink(&root.join(LOCK)).await {
        return refused(
            "vendor_bun_lockb_invalid",
            "bun.lockb is a symbolic link; replace it with a regular file before vendoring",
        );
    }
    let mut lock = match read_regular_to_bytes_sync(&root.join(LOCK))
        .map_err(|e| e.to_string())
        .and_then(|b| BunLockb::parse(&b))
    {
        Ok(v) => v,
        Err(e) => return refused("vendor_bun_lockb_invalid", e),
    };
    if let Err(e) = lock.validate_mutation() {
        return refused("vendor_bun_lockb_invalid", e);
    }
    let packages = match lock.packages() {
        Ok(v) => v,
        Err(e) => return refused("vendor_bun_lockb_invalid", e),
    };
    let leaf = tgz_rel_leaf(&coords.name, &coords.version);
    let matches: Vec<_> = packages
        .into_iter()
        .filter(|p| {
            (p.name == coords.name && p.version.as_deref() == Some(&coords.version))
                || is_ours(p, &coords.name, &leaf)
        })
        .collect();
    if matches.is_empty() {
        return refused(
            "vendor_lock_entry_not_found",
            format!(
                "{LOCK} has no registry entry for {}@{}",
                coords.name, coords.version
            ),
        );
    }
    let mirrors = match lock.workspace_paths().and_then(|paths| {
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
        Err(e) => return refused("vendor_bun_lockb_invalid", e),
    };
    let mut warnings = Vec::new();
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
    let lock_changed = !wiring.is_empty();
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
                    Ok(bytes) if hex::encode(Sha256::digest(&bytes)) == expected => Ok(Some(path)),
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
    let bytes = lock.bytes();
    if bytes != original_bytes {
        if let Err(e) = atomic_write_bytes_preserving_mode(&root.join(LOCK), &bytes).await {
            return RevertOutcome::failed(format!("cannot write {LOCK}: {e}"));
        }
    }
    if !opts.keep_artifact {
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
        vendor(
            PURL,
            (&fx.installed()).into(),
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

    /// A prebuilt archive whose tar headers deliberately differ from the
    /// local packer's (so its bytes never equal a local build's).
    fn prebuilt_archive() -> Vec<u8> {
        let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (name, bytes) in [("package.json", PACKAGE), ("index.js", AFTER)] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            // Deliberately differ from the local packer's deterministic mtime.
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
    /// request (the flip no longer re-pins).
    #[tokio::test]
    async fn same_uuid_prebuilt_then_outage_reuses_the_committed_archive() {
        let archive = prebuilt_archive();
        let server = MockServer::start().await;
        ts::mount_granted(&server, UUID, "minimist-1.2.2.tgz", &archive).await;
        let fx = flip_fixture().await;
        let config = ts::service_cfg(&server.uri(), VendorSource::Auto, false);
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
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(ts::snapshot(&fx).await, before);
        assert_eq!(ts::request_count(&server).await, 0);
    }

    /// With the canonical tarball GONE, an outage switches the same UUID
    /// from a prebuilt archive to a locally packed one. Different archive
    /// bytes must advance the integrity snapshot without losing the pristine
    /// registry predecessor, and revert must restore everything exactly.
    #[tokio::test]
    async fn same_uuid_prebuilt_then_local_fallback_reverts_exact_binary_and_mirrors() {
        let archive = prebuilt_archive();
        let server = MockServer::start().await;
        ts::mount_granted(&server, UUID, "minimist-1.2.2.tgz", &archive).await;
        let fx = flip_fixture().await;
        let root = fx.tmp.path();
        let config = ts::service_cfg(&server.uri(), VendorSource::Auto, false);
        let mut prior: Option<VendorEntry> = None;
        for prebuilt in [true, false] {
            if !prebuilt {
                mount_403(&server).await;
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
                    "vendor_prebuilt_unavailable"
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
}
