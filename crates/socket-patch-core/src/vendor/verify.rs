//! Verification of vendored patches for VEX attestation and drift audits.
//!
//! A vendored patch is attested only on **positive file-level evidence**: the
//! committed artifact must exist at its uuid-keyed path and every file the
//! manifest claims the patch modified must hash (git-blob sha256) to its
//! `afterHash` inside that artifact — the same standard `vex::verify` applies
//! to installed trees. Dir-shaped ecosystems are hashed in place; npm
//! tarballs and pypi wheels are decoded in memory (bounded — the artifacts
//! are committed and tamper-able, so a crafted archive must not OOM an
//! audit).
//!
//! Fail-closed order (each failure is a stable snake_case routing tag):
//! `no_files` → `vendor_path_unsafe` → `vendor_uuid_mismatch` →
//! `vendor_artifact_missing` → `vendor_artifact_unreadable` /
//! `file_not_found` / `vendor_hash_mismatch` / `vendor_inventory_mismatch`
//! (dir-shaped artifacts with a recorded [`file_inventory`] additionally
//! verify their FULL file tree — missing, extra and modified unpatched
//! files all fail; entries without one keep member-only verification).
//!
//! [`file_inventory`]: super::state::VendorArtifact::file_inventory

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::hash::git_sha256::compute_git_sha256_from_bytes;
use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{normalize_file_path, verify_file_patch, VerifyStatus};
use crate::patch::package::read_archive_to_map;

use super::path::parse_vendor_path;
use super::state::VendorEntry;

/// Hard cap on decompressed wheel bytes, mirroring
/// `patch::package`'s bomb posture for patch archives.
const MAX_WHEEL_DECOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_WHEEL_ENTRIES: usize = 10_000;

/// Validate `entry.artifact.path` and resolve it under `project_root`.
///
/// SECURITY: state.json is committed and tamper-able. The artifact path is
/// about to be stat'd/read/hashed, so it must (a) parse as a canonical
/// vendored path (which validates the uuid grammar), (b) be relative with no
/// `..`/absolute/NUL components, and (c) carry the uuid of the patch record
/// being attested — a poisoned path must neither read outside the project
/// tree nor launder one patch's artifact into another's attestation.
fn checked_artifact_path(
    project_root: &Path,
    entry: &VendorEntry,
    record: &PatchRecord,
) -> Result<PathBuf, String> {
    let rel = &entry.artifact.path;
    let parts = parse_vendor_path(rel).ok_or_else(|| "vendor_path_unsafe".to_string())?;
    let norm = rel.replace('\\', "/");
    if norm.starts_with('/')
        || norm.contains('\0')
        || !norm.starts_with(".socket/vendor/")
        || norm.split('/').any(|seg| seg == ".." || seg.is_empty())
    {
        return Err("vendor_path_unsafe".to_string());
    }
    // Stale-vendor detection: the path-level uuid IS the staleness signal —
    // a patch update changes record.uuid, so an artifact still sitting at the
    // old uuid path must not attest the new patch.
    if parts.uuid != record.uuid || entry.uuid != record.uuid {
        return Err("vendor_uuid_mismatch".to_string());
    }
    Ok(project_root.join(norm))
}

/// `Ok(())` iff every `record.files` entry hashes to its `afterHash` inside
/// the vendored artifact named by `entry`. The error is a stable routing tag
/// (see module docs) compatible with `vex::verify::FailedPatch.reason`.
pub async fn verify_vendored_patch_record(
    project_root: &Path,
    entry: &VendorEntry,
    record: &PatchRecord,
) -> Result<(), String> {
    if record.files.is_empty() {
        // Same contract as vex::verify: nothing to hash ⇒ never attested.
        return Err("no_files".to_string());
    }

    let artifact = checked_artifact_path(project_root, entry, record)?;
    if tokio::fs::metadata(&artifact).await.is_err() {
        return Err("vendor_artifact_missing".to_string());
    }

    // Archive-shaped artifacts are decoded in memory and their members hashed:
    // npm tarballs via the bomb-capped patch-archive reader (it strips the
    // `package/` prefix, matching `normalize_file_path`'d keys); `.whl` /
    // `.nupkg` (a plain OPC zip) / `.jar` (a plain zip) via the bounded zip
    // reader — their member paths are package-relative, exactly the manifest
    // key space. Everything else is a dir-shaped copy hashed in place.
    let path_str = artifact.to_string_lossy();
    let is_tarball = path_str.ends_with(".tgz") || path_str.ends_with(".tar.gz");
    let is_zip =
        path_str.ends_with(".whl") || path_str.ends_with(".nupkg") || path_str.ends_with(".jar");
    if !is_tarball && !is_zip {
        verify_dir_members(&artifact, record).await?;
        // Whole-tree cross-check: a dir-shaped artifact's bytes are covered
        // by NO lockfile integrity (bundler path sources, cargo path deps,
        // …), so the members above are the only thing the record can vouch
        // for — a recorded inventory extends the verdict to every file
        // (missing / extra / modified unpatched files, the stub gemspec).
        // Pre-inventory entries carry `None` and keep member-only behavior.
        if let Some(inventory) = &entry.artifact.file_inventory {
            verify_dir_inventory(&artifact, inventory).await?;
        }
        return Ok(());
    }
    let map = tokio::task::spawn_blocking(move || {
        if is_tarball {
            read_archive_to_map(&artifact).map_err(|_| "vendor_artifact_unreadable".to_string())
        } else {
            read_wheel_to_map(&artifact)
        }
    })
    .await
    .map_err(|_| "vendor_artifact_unreadable".to_string())??;
    verify_member_map(&map, record)
}

/// Dir-shaped ecosystems (cargo/golang/composer/gem): hash files in place,
/// reusing the hardened per-file verifier (it normalizes manifest keys and
/// fail-closes on path-escaping keys).
async fn verify_dir_members(dir: &Path, record: &PatchRecord) -> Result<(), String> {
    for (file_name, info) in &record.files {
        let result = verify_file_patch(dir, file_name, info).await;
        match result.status {
            VerifyStatus::AlreadyPatched => continue,
            VerifyStatus::Ready | VerifyStatus::HashMismatch => {
                return Err("vendor_hash_mismatch".to_string())
            }
            VerifyStatus::NotFound => return Err("file_not_found".to_string()),
        }
    }
    Ok(())
}

fn read_wheel_to_map(whl: &Path) -> Result<HashMap<String, Vec<u8>>, String> {
    // Open non-blockingly and require a regular file: a FIFO planted at the
    // artifact path would otherwise wedge the audit in `open(2)` waiting for
    // a writer that never comes (mirrors `read_archive_to_map`; O_NONBLOCK
    // has no effect on regular-file reads).
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(whl)
            .map_err(|_| "vendor_artifact_unreadable".to_string())?
    };
    #[cfg(not(unix))]
    let file = std::fs::File::open(whl).map_err(|_| "vendor_artifact_unreadable".to_string())?;
    if !file.metadata().map(|m| m.is_file()).unwrap_or(false) {
        return Err("vendor_artifact_unreadable".to_string());
    }
    let mut zip =
        zip::ZipArchive::new(file).map_err(|_| "vendor_artifact_unreadable".to_string())?;
    if zip.len() > MAX_WHEEL_ENTRIES {
        return Err("vendor_artifact_unreadable".to_string());
    }
    let mut out = HashMap::new();
    let mut declared: u64 = 0;
    let mut actual: u64 = 0;
    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|_| "vendor_artifact_unreadable".to_string())?;
        if !entry.is_file() {
            continue;
        }
        // SECURITY: bound the cumulative decompressed size — a
        // committed-but-tampered wheel must not balloon an audit's memory.
        // The declared `entry.size()` is header data the attacker controls
        // and the zip reader never enforces, so the binding budget is bytes
        // ACTUALLY decompressed; the declared check just fails honest
        // oversized wheels before reading anything.
        declared = declared.saturating_add(entry.size());
        if declared > MAX_WHEEL_DECOMPRESSED_BYTES {
            return Err("vendor_artifact_unreadable".to_string());
        }
        let name = entry.name().to_string();
        let mut bytes = Vec::new();
        // +1 so an entry that would exceed the remaining budget reads one
        // byte past it and is rejected, rather than truncating silently.
        entry
            .by_ref()
            .take(MAX_WHEEL_DECOMPRESSED_BYTES - actual + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "vendor_artifact_unreadable".to_string())?;
        actual = actual.saturating_add(bytes.len() as u64);
        if actual > MAX_WHEEL_DECOMPRESSED_BYTES {
            return Err("vendor_artifact_unreadable".to_string());
        }
        out.insert(name, bytes);
    }
    Ok(out)
}

/// Hard cap on whole-artifact bytes hashed by the health check — committed
/// artifacts are small (a package tarball/wheel); a tampered multi-GiB file
/// must not stall `repair`.
const MAX_HEALTH_HASH_BYTES: u64 = 512 * 1024 * 1024;

/// Hard cap on inventoried files, mirroring the zip reader's entry cap — a
/// committed artifact dir is one package; a tampered dir must not stall an
/// audit with a million planted files.
const MAX_INVENTORY_ENTRIES: usize = 10_000;

/// Is this artifact path a single committed FILE (tarball/wheel/nupkg/jar)
/// — whose whole-file drift check is the ledger `sha256` — as opposed to a
/// dir-shaped copy whose counterpart is the `fileInventory`? One suffix
/// rule shared by the health check, repair's fingerprint fill, and the
/// inventory-gap warning.
pub fn artifact_is_file_shaped(path: &str) -> bool {
    let norm = path.replace('\\', "/");
    norm.ends_with(".tgz")
        || norm.ends_with(".tar.gz")
        || norm.ends_with(".whl")
        || norm.ends_with(".nupkg")
        || norm.ends_with(".jar")
}

/// Full-file inventory of a dir-shaped artifact: every regular file under
/// `dir`, as `relative forward-slashed path → plain sha256 hex` (sorted —
/// the exact shape [`super::state::VendorArtifact::file_inventory`]
/// records). Fail-closed `Err` on anything that cannot be faithfully
/// inventoried: a non-regular entry (symlink/FIFO — hashing through one
/// could escape the artifact dir or wedge the audit), a non-UTF-8 name, an
/// unreadable file, or a tree past the entry cap.
pub async fn compute_dir_inventory(dir: &Path) -> Result<BTreeMap<String, String>, String> {
    let root = dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        use sha2::{Digest, Sha256};

        let mut out = BTreeMap::new();
        let mut stack: Vec<(PathBuf, String)> = vec![(root, String::new())];
        while let Some((abs, rel)) = stack.pop() {
            let entries = std::fs::read_dir(&abs)
                .map_err(|e| format!("unreadable artifact dir `{rel}`: {e}"))?;
            for entry in entries {
                let entry = entry.map_err(|e| format!("unreadable artifact dir `{rel}`: {e}"))?;
                let name = entry
                    .file_name()
                    .to_str()
                    .ok_or_else(|| format!("non-UTF-8 file name under `{rel}`"))?
                    .to_string();
                let child_rel = if rel.is_empty() {
                    name
                } else {
                    format!("{rel}/{name}")
                };
                // symlink_metadata: never follow links — a planted symlink
                // must fail the inventory, not hash bytes outside the dir.
                let meta = std::fs::symlink_metadata(entry.path())
                    .map_err(|e| format!("unreadable `{child_rel}`: {e}"))?;
                if meta.is_dir() {
                    stack.push((entry.path(), child_rel));
                    continue;
                }
                if !meta.is_file() {
                    return Err(format!("`{child_rel}` is not a regular file"));
                }
                if meta.len() > MAX_HEALTH_HASH_BYTES {
                    return Err(format!("`{child_rel}` exceeds the inventory size cap"));
                }
                if out.len() >= MAX_INVENTORY_ENTRIES {
                    return Err(format!(
                        "artifact dir exceeds {MAX_INVENTORY_ENTRIES} files"
                    ));
                }
                let mut file = std::fs::File::open(entry.path())
                    .map_err(|e| format!("unreadable `{child_rel}`: {e}"))?;
                let mut hasher = Sha256::new();
                std::io::copy(&mut file, &mut hasher)
                    .map_err(|e| format!("unreadable `{child_rel}`: {e}"))?;
                out.insert(child_rel, hex::encode(hasher.finalize()));
            }
        }
        Ok(out)
    })
    .await
    .map_err(|_| "artifact inventory task failed".to_string())?
}

/// Compare the live tree under `dir` against the recorded inventory:
/// missing, extra and modified files all fail with the
/// `vendor_inventory_mismatch` routing tag; a tree that cannot be walked
/// (planted symlink/FIFO, unreadable file) is `vendor_artifact_unreadable`.
async fn verify_dir_inventory(
    dir: &Path,
    inventory: &BTreeMap<String, String>,
) -> Result<(), String> {
    let actual = compute_dir_inventory(dir)
        .await
        .map_err(|_| "vendor_artifact_unreadable".to_string())?;
    if actual.len() != inventory.len() {
        return Err("vendor_inventory_mismatch".to_string());
    }
    for (rel, recorded) in inventory {
        match actual.get(rel) {
            Some(live) if live.eq_ignore_ascii_case(recorded) => {}
            _ => return Err("vendor_inventory_mismatch".to_string()),
        }
    }
    Ok(())
}

/// Classified health of one ledger entry's committed artifact, for
/// `repair`-style callers that need a DECISION (rebuild or not), not just a
/// routing tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactHealth {
    /// Exists and every record file hashes to its afterHash (and, for
    /// file-shaped artifacts, the whole file matches the ledger sha256).
    Healthy,
    /// Nothing at the artifact path: rebuildable.
    Missing,
    /// Present but failing verification: rebuildable. `reason` is the
    /// stable routing tag (`vendor_hash_mismatch`, `file_not_found`,
    /// `vendor_artifact_unreadable`, `vendor_sha256_mismatch`,
    /// `vendor_inventory_mismatch`).
    Corrupt { reason: String },
    /// The ledger/artifact uuid doesn't match the record: a re-vendor is
    /// pending — not repair's job.
    StaleUuid,
    /// The entry can't be judged (poisoned path, empty record): fail
    /// closed, never rebuild from it.
    Unverifiable { reason: String },
}

/// Health-check one vendored artifact against its patch record: the
/// per-file afterHash verification of [`verify_vendored_patch_record`]
/// (which for dir-shaped artifacts includes the whole-tree fileInventory
/// cross-check) plus, for file-shaped artifacts (`.tgz`/`.tar.gz`/`.whl`)
/// with a recorded ledger sha256, a whole-file hash cross-check — the
/// rewired lockfile integrity references those exact bytes, so silent
/// drift breaks the package manager even when the patched members still
/// verify.
pub async fn check_vendored_artifact(
    project_root: &Path,
    entry: &VendorEntry,
    record: &PatchRecord,
) -> ArtifactHealth {
    match verify_vendored_patch_record(project_root, entry, record).await {
        Err(tag) => match tag.as_str() {
            "vendor_artifact_missing" => ArtifactHealth::Missing,
            "vendor_uuid_mismatch" => ArtifactHealth::StaleUuid,
            "vendor_hash_mismatch"
            | "file_not_found"
            | "vendor_artifact_unreadable"
            | "vendor_inventory_mismatch" => ArtifactHealth::Corrupt { reason: tag },
            _ => ArtifactHealth::Unverifiable { reason: tag },
        },
        Ok(()) => {
            let norm = entry.artifact.path.replace('\\', "/");
            // `.nupkg` (NuGet) and `.jar` (Maven) are single committed files
            // whose recorded ledger sha256 the rewired lockfile / `.sha1`
            // sidecar references, so they get the same whole-file drift
            // cross-check as tarballs/wheels. (Dir-shaped artifacts got the
            // fileInventory whole-tree cross-check inside the verification
            // above.)
            if !artifact_is_file_shaped(&norm) || entry.artifact.sha256.is_empty() {
                return ArtifactHealth::Healthy;
            }
            // The path already passed checked_artifact_path inside the
            // verification above.
            match file_sha256_hex(&project_root.join(&norm)).await {
                Some(hex) if hex.eq_ignore_ascii_case(&entry.artifact.sha256) => {
                    ArtifactHealth::Healthy
                }
                Some(_) => ArtifactHealth::Corrupt {
                    reason: "vendor_sha256_mismatch".to_string(),
                },
                None => ArtifactHealth::Corrupt {
                    reason: "vendor_artifact_unreadable".to_string(),
                },
            }
        }
    }
}

/// Plain sha256 hex of a regular file, size-capped; `None` on any read
/// failure or cap breach. Public for repair's ledger re-synthesis (the
/// rebuilt artifact's recorded sha).
pub async fn file_sha256_hex(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncReadExt;

    let meta = tokio::fs::metadata(path).await.ok()?;
    if !meta.is_file() || meta.len() > MAX_HEALTH_HASH_BYTES {
        return None;
    }
    let mut file = tokio::fs::File::open(path).await.ok()?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).await.ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(hex::encode(hasher.finalize()))
}

fn verify_member_map(
    members: &HashMap<String, Vec<u8>>,
    record: &PatchRecord,
) -> Result<(), String> {
    for (file_name, info) in &record.files {
        let key = normalize_file_path(file_name);
        let bytes = members
            .get(key)
            .or_else(|| members.get(file_name.as_str()))
            .ok_or_else(|| "file_not_found".to_string())?;
        let hash = compute_git_sha256_from_bytes(bytes);
        if !hash.eq_ignore_ascii_case(&info.after_hash) {
            return Err("vendor_hash_mismatch".to_string());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::schema::PatchFileInfo;
    use crate::vendor::state::VendorArtifact;
    use flate2::write::GzEncoder;
    use std::io::Write;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const PATCHED: &[u8] = b"patched bytes\n";

    fn record(uuid: &str, file_key: &str) -> PatchRecord {
        let mut files = HashMap::new();
        files.insert(
            file_key.to_string(),
            PatchFileInfo {
                before_hash: "b".into(),
                after_hash: compute_git_sha256_from_bytes(PATCHED),
            },
        );
        PatchRecord {
            uuid: uuid.to_string(),
            exported_at: "t".into(),
            files,
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    fn entry(eco: &str, uuid: &str, rel_path: &str) -> VendorEntry {
        VendorEntry {
            ecosystem: eco.into(),
            base_purl: "pkg:npm/x@1.0.0".into(),
            uuid: uuid.into(),
            artifact: VendorArtifact {
                path: rel_path.into(),
                sha256: String::new(),
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            wiring: Vec::new(),
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
        }
    }

    fn write_tgz(dest: &Path, member: &str, bytes: &[u8]) {
        let mut builder = tar::Builder::new(GzEncoder::new(
            std::fs::File::create(dest).unwrap(),
            flate2::Compression::new(6),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, member, bytes).unwrap();
        builder.into_inner().unwrap().finish().unwrap();
    }

    fn write_whl(dest: &Path, member: &str, bytes: &[u8]) {
        let file = std::fs::File::create(dest).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file::<_, ()>(member, Default::default()).unwrap();
        zip.write_all(bytes).unwrap();
        zip.finish().unwrap();
    }

    /// The whole-tree inventory closes the dir-shaped blindspot: with only
    /// afterHashes, a tampered UNPATCHED file (or stub gemspec), a deleted
    /// file, or a planted extra file were all blessed Healthy. Each arm of
    /// the tamper matrix is hand-pinned; the legacy no-inventory entry keeps
    /// member-only behavior (backward tolerance).
    #[tokio::test]
    async fn dir_inventory_detects_unpatched_tamper_missing_and_extra_files() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel = format!(".socket/vendor/gem/{UUID}/rack-3.2.6");
        let dir = root.join(&rel);
        tokio::fs::create_dir_all(dir.join("lib")).await.unwrap();
        tokio::fs::write(dir.join("lib/rack.rb"), PATCHED)
            .await
            .unwrap();
        tokio::fs::write(dir.join("rack.gemspec"), b"stub gemspec\n")
            .await
            .unwrap();

        let rec = record(UUID, "lib/rack.rb");
        let mut ent = entry("gem", UUID, &rel);
        ent.artifact.file_inventory = Some(compute_dir_inventory(&dir).await.unwrap());
        // Anti-vacuity: the recorded inventory names both files with real
        // plain-sha256 values, and the pristine tree verifies end to end.
        {
            let inv = ent.artifact.file_inventory.as_ref().unwrap();
            assert_eq!(
                inv.keys().collect::<Vec<_>>(),
                ["lib/rack.rb", "rack.gemspec"]
            );
            use sha2::{Digest, Sha256};
            assert_eq!(inv["lib/rack.rb"], hex::encode(Sha256::digest(PATCHED)));
        }
        assert!(verify_vendored_patch_record(root, &ent, &rec).await.is_ok());
        assert_eq!(
            check_vendored_artifact(root, &ent, &rec).await,
            ArtifactHealth::Healthy
        );

        // 1. Tampered UNPATCHED file: afterHashes still verify, the
        //    inventory flips the verdict.
        tokio::fs::write(dir.join("rack.gemspec"), b"tampered gemspec\n")
            .await
            .unwrap();
        assert_eq!(
            verify_vendored_patch_record(root, &ent, &rec)
                .await
                .unwrap_err(),
            "vendor_inventory_mismatch",
            "modified unpatched file"
        );
        assert_eq!(
            check_vendored_artifact(root, &ent, &rec).await,
            ArtifactHealth::Corrupt {
                reason: "vendor_inventory_mismatch".to_string()
            },
            "Corrupt (rebuildable), never Unverifiable"
        );

        // 2. Missing unpatched file.
        tokio::fs::remove_file(dir.join("rack.gemspec"))
            .await
            .unwrap();
        assert_eq!(
            verify_vendored_patch_record(root, &ent, &rec)
                .await
                .unwrap_err(),
            "vendor_inventory_mismatch",
            "deleted unpatched file"
        );

        // 3. Extra planted file (count parity restored: gemspec back, plus
        //    a file the inventory never recorded).
        tokio::fs::write(dir.join("rack.gemspec"), b"stub gemspec\n")
            .await
            .unwrap();
        tokio::fs::write(dir.join("lib/evil.rb"), b"payload\n")
            .await
            .unwrap();
        assert_eq!(
            verify_vendored_patch_record(root, &ent, &rec)
                .await
                .unwrap_err(),
            "vendor_inventory_mismatch",
            "extra file"
        );
        tokio::fs::remove_file(dir.join("lib/evil.rb"))
            .await
            .unwrap();

        // 4. Same count, swapped identity: one recorded file replaced by a
        //    differently-named one (len-only comparison would miss it).
        tokio::fs::remove_file(dir.join("rack.gemspec"))
            .await
            .unwrap();
        tokio::fs::write(dir.join("rack.gemspec2"), b"stub gemspec\n")
            .await
            .unwrap();
        assert_eq!(
            verify_vendored_patch_record(root, &ent, &rec)
                .await
                .unwrap_err(),
            "vendor_inventory_mismatch",
            "renamed file at equal count"
        );
        tokio::fs::remove_file(dir.join("rack.gemspec2"))
            .await
            .unwrap();
        tokio::fs::write(dir.join("rack.gemspec"), b"stub gemspec\n")
            .await
            .unwrap();

        // 5. LEGACY entry (no inventory recorded): the same unpatched-file
        //    tamper keeps today's member-only Healthy verdict.
        tokio::fs::write(dir.join("rack.gemspec"), b"tampered gemspec\n")
            .await
            .unwrap();
        let legacy = entry("gem", UUID, &rel);
        assert!(legacy.artifact.file_inventory.is_none());
        assert!(
            verify_vendored_patch_record(root, &legacy, &rec)
                .await
                .is_ok(),
            "pre-inventory entries keep member-only verification"
        );
        assert_eq!(
            check_vendored_artifact(root, &legacy, &rec).await,
            ArtifactHealth::Healthy
        );
    }

    /// SECURITY: a symlink planted inside a vendored dir must fail the
    /// inventory walk (never hash through it — the target may live outside
    /// the artifact dir), surfacing as unreadable/Corrupt.
    #[cfg(unix)]
    #[tokio::test]
    async fn dir_inventory_refuses_planted_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel = format!(".socket/vendor/gem/{UUID}/rack-3.2.6");
        let dir = root.join(&rel);
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("lib.rb"), PATCHED).await.unwrap();

        let rec = record(UUID, "lib.rb");
        let mut ent = entry("gem", UUID, &rel);
        ent.artifact.file_inventory = Some(compute_dir_inventory(&dir).await.unwrap());

        let outside = root.join("outside.txt");
        tokio::fs::write(&outside, b"outside\n").await.unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("link.rb")).unwrap();
        assert!(
            compute_dir_inventory(&dir).await.is_err(),
            "symlinks are not inventoriable"
        );
        assert_eq!(
            verify_vendored_patch_record(root, &ent, &rec)
                .await
                .unwrap_err(),
            "vendor_artifact_unreadable"
        );
    }

    #[tokio::test]
    async fn dir_artifact_verifies_and_detects_tamper() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel = format!(".socket/vendor/cargo/{UUID}/serde-1.0.0");
        let dir = root.join(&rel);
        tokio::fs::create_dir_all(dir.join("src")).await.unwrap();
        tokio::fs::write(dir.join("src/lib.rs"), PATCHED)
            .await
            .unwrap();

        let rec = record(UUID, "src/lib.rs");
        let ent = entry("cargo", UUID, &rel);
        assert!(verify_vendored_patch_record(root, &ent, &rec).await.is_ok());

        tokio::fs::write(dir.join("src/lib.rs"), b"tampered")
            .await
            .unwrap();
        assert_eq!(
            verify_vendored_patch_record(root, &ent, &rec)
                .await
                .unwrap_err(),
            "vendor_hash_mismatch"
        );

        tokio::fs::remove_file(dir.join("src/lib.rs"))
            .await
            .unwrap();
        assert_eq!(
            verify_vendored_patch_record(root, &ent, &rec)
                .await
                .unwrap_err(),
            "file_not_found"
        );
    }

    #[tokio::test]
    async fn tarball_members_verified_with_package_prefix_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel = format!(".socket/vendor/npm/{UUID}/x-1.0.0.tgz");
        tokio::fs::create_dir_all(root.join(format!(".socket/vendor/npm/{UUID}")))
            .await
            .unwrap();
        write_tgz(&root.join(&rel), "package/index.js", PATCHED);

        // Manifest npm keys carry the package/ prefix.
        let rec = record(UUID, "package/index.js");
        let ent = entry("npm", UUID, &rel);
        assert!(verify_vendored_patch_record(root, &ent, &rec).await.is_ok());

        // One tampered byte inside the archive flips the verdict.
        write_tgz(&root.join(&rel), "package/index.js", b"tampered");
        assert_eq!(
            verify_vendored_patch_record(root, &ent, &rec)
                .await
                .unwrap_err(),
            "vendor_hash_mismatch"
        );

        // Member missing entirely.
        write_tgz(&root.join(&rel), "package/other.js", PATCHED);
        assert_eq!(
            verify_vendored_patch_record(root, &ent, &rec)
                .await
                .unwrap_err(),
            "file_not_found"
        );

        // Truncated/corrupt gzip is unreadable, not a crash.
        tokio::fs::write(root.join(&rel), b"\x1f\x8b00garbage")
            .await
            .unwrap();
        assert_eq!(
            verify_vendored_patch_record(root, &ent, &rec)
                .await
                .unwrap_err(),
            "vendor_artifact_unreadable"
        );
    }

    #[tokio::test]
    async fn wheel_members_verified() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel = format!(".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl");
        tokio::fs::create_dir_all(root.join(format!(".socket/vendor/pypi/{UUID}")))
            .await
            .unwrap();
        write_whl(&root.join(&rel), "six.py", PATCHED);

        let rec = record(UUID, "six.py");
        let ent = entry("pypi", UUID, &rel);
        assert!(verify_vendored_patch_record(root, &ent, &rec).await.is_ok());

        write_whl(&root.join(&rel), "six.py", b"tampered");
        assert_eq!(
            verify_vendored_patch_record(root, &ent, &rec)
                .await
                .unwrap_err(),
            "vendor_hash_mismatch"
        );
    }

    #[tokio::test]
    async fn nupkg_and_jar_members_verified_as_zip() {
        // `.nupkg` (NuGet) and `.jar` (Maven) are single committed zip files
        // routed through the wheel zip reader. Exercise both suffix arms:
        // member verify + tamper detection + the file-shaped sha256 drift
        // cross-check in check_vendored_artifact.
        let cases: &[(&str, &str, &str)] = &[
            ("nuget", "newtonsoft.json.13.0.3.nupkg", "LICENSE.md"),
            ("maven", "commons-text-1.10.0.jar", "META-INF/NOTICE.txt"),
        ];
        for (eco, leaf, member) in cases {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            let rel = format!(".socket/vendor/{eco}/{UUID}/{leaf}");
            tokio::fs::create_dir_all(root.join(format!(".socket/vendor/{eco}/{UUID}")))
                .await
                .unwrap();
            write_whl(&root.join(&rel), member, PATCHED);

            let rec = record(UUID, member);
            let ent = entry(eco, UUID, &rel);
            assert!(
                verify_vendored_patch_record(root, &ent, &rec).await.is_ok(),
                "{eco}: patched member verifies"
            );

            // A matching ledger sha256 → Healthy through the file-shaped path.
            let bytes = tokio::fs::read(root.join(&rel)).await.unwrap();
            let mut ent_sha = entry(eco, UUID, &rel);
            ent_sha.artifact.sha256 = {
                use sha2::{Digest, Sha256};
                hex::encode(Sha256::digest(&bytes))
            };
            assert_eq!(
                check_vendored_artifact(root, &ent_sha, &rec).await,
                ArtifactHealth::Healthy,
                "{eco}: matching ledger sha256 is Healthy"
            );

            // Whole-file drift the member check can't see (members still
            // verify, but the recorded sha differs).
            ent_sha.artifact.sha256 = "0".repeat(64);
            assert_eq!(
                check_vendored_artifact(root, &ent_sha, &rec).await,
                ArtifactHealth::Corrupt {
                    reason: "vendor_sha256_mismatch".to_string()
                },
                "{eco}: file-shaped sha256 drift is Corrupt"
            );

            // Member tamper flips the per-file verdict.
            write_whl(&root.join(&rel), member, b"tampered");
            assert_eq!(
                verify_vendored_patch_record(root, &ent, &rec)
                    .await
                    .unwrap_err(),
                "vendor_hash_mismatch",
                "{eco}: tampered member detected"
            );
        }
    }

    #[tokio::test]
    async fn fail_closed_ordering_and_guards() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel = format!(".socket/vendor/npm/{UUID}/x-1.0.0.tgz");

        // no_files first.
        let mut rec = record(UUID, "package/index.js");
        rec.files.clear();
        let ent = entry("npm", UUID, &rel);
        assert_eq!(
            verify_vendored_patch_record(root, &ent, &rec)
                .await
                .unwrap_err(),
            "no_files"
        );

        // SECURITY: poisoned state.json paths never stat/read outside the
        // project tree — rejected before any disk access.
        let rec = record(UUID, "package/index.js");
        let escape = format!(".socket/vendor/npm/{UUID}/../../../escape.tgz");
        for bad in [
            "/etc/passwd",
            "../../outside.tgz",
            escape.as_str(),
            ".socket/vendor/npm/not-a-uuid/x.tgz",
        ] {
            let ent = entry("npm", UUID, bad);
            assert_eq!(
                verify_vendored_patch_record(root, &ent, &rec)
                    .await
                    .unwrap_err(),
                "vendor_path_unsafe",
                "path {bad} must be rejected"
            );
        }

        // Stale vendor: artifact still at the OLD uuid while the record moved on.
        let new_uuid = "11111111-2222-4333-8444-555555555555";
        let rec_new = record(new_uuid, "package/index.js");
        let ent_old = entry("npm", UUID, &rel);
        assert_eq!(
            verify_vendored_patch_record(root, &ent_old, &rec_new)
                .await
                .unwrap_err(),
            "vendor_uuid_mismatch"
        );

        // Missing artifact (path fine, uuid fine, nothing on disk).
        let ent = entry("npm", UUID, &rel);
        let rec = record(UUID, "package/index.js");
        assert_eq!(
            verify_vendored_patch_record(root, &ent, &rec)
                .await
                .unwrap_err(),
            "vendor_artifact_missing"
        );
    }

    /// Rewrite every declared uncompressed size in `zip_path` (central
    /// directory AND local headers) to 0, leaving compressed data and CRCs
    /// intact — the header lie a tampered wheel uses to slip a decompression
    /// bomb past size accounting that trusts `entry.size()`.
    fn zero_declared_sizes(zip_path: &Path) {
        let mut bytes = std::fs::read(zip_path).unwrap();
        let eocd = bytes.len() - 22;
        assert_eq!(&bytes[eocd..eocd + 4], b"PK\x05\x06", "EOCD not found");
        let cd_count = u16::from_le_bytes([bytes[eocd + 10], bytes[eocd + 11]]) as usize;
        let mut off = u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        for _ in 0..cd_count {
            assert_eq!(
                &bytes[off..off + 4],
                b"PK\x01\x02",
                "central header not found"
            );
            let name_len = u16::from_le_bytes([bytes[off + 28], bytes[off + 29]]) as usize;
            let extra_len = u16::from_le_bytes([bytes[off + 30], bytes[off + 31]]) as usize;
            let comment_len = u16::from_le_bytes([bytes[off + 32], bytes[off + 33]]) as usize;
            let lho = u32::from_le_bytes(bytes[off + 42..off + 46].try_into().unwrap()) as usize;
            bytes[off + 24..off + 28].fill(0);
            assert_eq!(
                &bytes[lho..lho + 4],
                b"PK\x03\x04",
                "local header not found"
            );
            bytes[lho + 22..lho + 26].fill(0);
            off += 46 + name_len + extra_len + comment_len;
        }
        std::fs::write(zip_path, bytes).unwrap();
    }

    /// SECURITY: the declared `entry.size()` is attacker-controlled header
    /// data the zip reader never enforces — accounting must budget by bytes
    /// ACTUALLY decompressed, or a wheel declaring 0 everywhere buffers up to
    /// 64 MiB × 10_000 entries into the audit's memory.
    #[test]
    fn wheel_bomb_with_lying_declared_sizes_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let whl = tmp.path().join("bomb-1.0.0-py3-none-any.whl");
        // 5 × 16 MiB of zeros = 80 MiB actual (over the 64 MiB cap), a few
        // KiB compressed; every header then claims 0 uncompressed bytes.
        let file = std::fs::File::create(&whl).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let member = vec![0u8; 16 * 1024 * 1024];
        for i in 0..5 {
            zip.start_file::<_, ()>(format!("pad{i}.bin"), Default::default())
                .unwrap();
            zip.write_all(&member).unwrap();
        }
        zip.finish().unwrap();
        zero_declared_sizes(&whl);

        assert!(
            read_wheel_to_map(&whl).is_err(),
            "an 80 MiB-actual wheel declaring 0 bytes must not be buffered past the cap"
        );
    }

    /// SECURITY: a FIFO planted at the artifact path must fail verification,
    /// not wedge the audit in `open(2)` waiting for a writer that never
    /// comes (the tarball reader and file hasher already guard this).
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_wheel_artifact_fails_instead_of_wedging() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel = format!(".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl");
        tokio::fs::create_dir_all(root.join(format!(".socket/vendor/pypi/{UUID}")))
            .await
            .unwrap();
        let fifo = root.join(&rel);
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) }, 0);

        let rec = record(UUID, "six.py");
        let ent = entry("pypi", UUID, &rel);
        let verdict = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            verify_vendored_patch_record(root, &ent, &rec),
        )
        .await;
        // Release any opener still blocked on the FIFO (the buggy case) so
        // runtime shutdown doesn't hang on its spawn_blocking thread.
        {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&fifo);
        }
        let verdict = verdict.expect("a planted FIFO must not wedge verification");
        assert_eq!(verdict.unwrap_err(), "vendor_artifact_unreadable");
    }

    /// Full classification matrix for the repair-facing health check.
    #[tokio::test]
    async fn artifact_health_classification_matrix() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel = format!(".socket/vendor/npm/{UUID}/x-1.0.0.tgz");
        let rec = record(UUID, "package/index.js");

        // Missing.
        let ent = entry("npm", UUID, &rel);
        assert_eq!(
            check_vendored_artifact(root, &ent, &rec).await,
            ArtifactHealth::Missing
        );

        // Healthy (no ledger sha recorded → member verification only).
        tokio::fs::create_dir_all(root.join(format!(".socket/vendor/npm/{UUID}")))
            .await
            .unwrap();
        write_tgz(&root.join(&rel), "package/index.js", PATCHED);
        assert_eq!(
            check_vendored_artifact(root, &ent, &rec).await,
            ArtifactHealth::Healthy
        );

        // Healthy with a MATCHING ledger sha256.
        let tgz_bytes = tokio::fs::read(root.join(&rel)).await.unwrap();
        let mut ent_sha = entry("npm", UUID, &rel);
        ent_sha.artifact.sha256 = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(&tgz_bytes))
        };
        assert_eq!(
            check_vendored_artifact(root, &ent_sha, &rec).await,
            ArtifactHealth::Healthy
        );

        // Whole-file drift the member check can't see: members verify, but
        // the bytes differ from what the lockfile integrity references
        // (re-compressed archive → different sha).
        ent_sha.artifact.sha256 = "0".repeat(64);
        assert_eq!(
            check_vendored_artifact(root, &ent_sha, &rec).await,
            ArtifactHealth::Corrupt {
                reason: "vendor_sha256_mismatch".to_string()
            }
        );

        // Member tamper.
        write_tgz(&root.join(&rel), "package/index.js", b"tampered");
        assert_eq!(
            check_vendored_artifact(root, &ent, &rec).await,
            ArtifactHealth::Corrupt {
                reason: "vendor_hash_mismatch".to_string()
            }
        );

        // Unreadable.
        tokio::fs::write(root.join(&rel), b"\x1f\x8b00garbage")
            .await
            .unwrap();
        assert_eq!(
            check_vendored_artifact(root, &ent, &rec).await,
            ArtifactHealth::Corrupt {
                reason: "vendor_artifact_unreadable".to_string()
            }
        );

        // Stale uuid → not repair's job.
        let rec_new = record("11111111-2222-4333-8444-555555555555", "package/index.js");
        assert_eq!(
            check_vendored_artifact(root, &ent, &rec_new).await,
            ArtifactHealth::StaleUuid
        );

        // Poisoned path → fail closed.
        let ent_bad = entry("npm", UUID, "../../outside.tgz");
        assert_eq!(
            check_vendored_artifact(root, &ent_bad, &rec).await,
            ArtifactHealth::Unverifiable {
                reason: "vendor_path_unsafe".to_string()
            }
        );
    }

    /// SECURITY: the zip entry-count cap fails a tampered wheel closed —
    /// one entry past the cap (even zero-byte entries) is rejected up
    /// front, while a wheel at exactly the cap still reads (no off-by-one
    /// shrink of the legitimate budget).
    #[test]
    fn wheel_entry_count_cap_rejects_over_ten_thousand_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let write_n_entry_whl = |n: usize| -> PathBuf {
            let whl = tmp.path().join(format!("entries-{n}.whl"));
            let file = std::fs::File::create(&whl).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            for i in 0..n {
                zip.start_file::<_, ()>(format!("e{i}"), Default::default())
                    .unwrap();
            }
            zip.finish().unwrap();
            whl
        };

        let at_cap = write_n_entry_whl(MAX_WHEEL_ENTRIES);
        assert_eq!(
            read_wheel_to_map(&at_cap).unwrap().len(),
            MAX_WHEEL_ENTRIES,
            "a wheel at exactly the entry cap still reads"
        );

        let over_cap = write_n_entry_whl(MAX_WHEEL_ENTRIES + 1);
        assert_eq!(
            read_wheel_to_map(&over_cap).unwrap_err(),
            "vendor_artifact_unreadable",
            "one entry past the cap fails closed"
        );
    }

    /// SECURITY: an honest wheel DECLARING more than the 64 MiB budget is
    /// rejected by the declared-size fast-fail before its data is
    /// decompressed — the other half of the accounting pinned by the
    /// lying-header bomb test above.
    #[test]
    fn honest_oversized_wheel_rejected_by_declared_size_fast_fail() {
        let tmp = tempfile::tempdir().unwrap();
        let whl = tmp.path().join("big-1.0.0-py3-none-any.whl");
        let file = std::fs::File::create(&whl).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        // One byte past the cap, headers recording the TRUE size (zeros
        // deflate to a few KiB, so the fixture itself stays tiny).
        zip.start_file::<_, ()>("pad.bin", Default::default())
            .unwrap();
        zip.write_all(&vec![0u8; (MAX_WHEEL_DECOMPRESSED_BYTES + 1) as usize])
            .unwrap();
        zip.finish().unwrap();

        assert_eq!(
            read_wheel_to_map(&whl).unwrap_err(),
            "vendor_artifact_unreadable"
        );
    }

    /// Real wheels carry explicit directory entries; the zip reader must
    /// skip them (they are not hashable members) while still verifying the
    /// file members around them.
    #[tokio::test]
    async fn wheel_with_directory_entries_still_verifies() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel = format!(".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl");
        tokio::fs::create_dir_all(root.join(format!(".socket/vendor/pypi/{UUID}")))
            .await
            .unwrap();
        let abs = root.join(&rel);
        let file = std::fs::File::create(&abs).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.add_directory::<_, ()>("six/", Default::default())
            .unwrap();
        zip.start_file::<_, ()>("six.py", Default::default())
            .unwrap();
        zip.write_all(PATCHED).unwrap();
        zip.finish().unwrap();

        // The dir entry is excluded from the member map entirely…
        let map = read_wheel_to_map(&abs).unwrap();
        assert_eq!(map.keys().collect::<Vec<_>>(), ["six.py"]);

        // …and end-to-end verification of the file member still passes.
        let rec = record(UUID, "six.py");
        let ent = entry("pypi", UUID, &rel);
        assert!(verify_vendored_patch_record(root, &ent, &rec).await.is_ok());
    }

    /// SECURITY: the inventory per-file size cap fails closed on a single
    /// over-cap file (sparse, so the fixture is free — the cap trips on
    /// `len()` before any bytes are read), and the whole-file hasher
    /// refuses the same over-cap file and non-regular paths with `None`.
    #[tokio::test]
    async fn dir_inventory_size_cap_and_file_hasher_fail_closed() {
        use sha2::{Digest, Sha256};

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("artifact");
        std::fs::create_dir_all(&dir).unwrap();
        let huge = dir.join("huge.bin");
        std::fs::File::create(&huge)
            .unwrap()
            .set_len(MAX_HEALTH_HASH_BYTES + 1)
            .unwrap();

        let err = compute_dir_inventory(&dir).await.unwrap_err();
        assert!(err.contains("exceeds the inventory size cap"), "got: {err}");

        assert_eq!(file_sha256_hex(&huge).await, None, "over-cap file");
        assert_eq!(file_sha256_hex(&dir).await, None, "non-regular path");
        // Positive control: the Nones above are the cap/non-file arms, not
        // general hasher breakage.
        let small = tmp.path().join("small.txt");
        std::fs::write(&small, b"abc").unwrap();
        assert_eq!(
            file_sha256_hex(&small).await.unwrap(),
            hex::encode(Sha256::digest(b"abc"))
        );
    }

    /// SECURITY: the inventory entry cap refuses a tampered artifact dir
    /// with a planted file flood — exactly at the cap still inventories
    /// (no off-by-one shrink), one more file fails closed.
    #[tokio::test]
    async fn dir_inventory_entry_cap_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("artifact");
        std::fs::create_dir_all(&dir).unwrap();
        for i in 0..MAX_INVENTORY_ENTRIES {
            std::fs::File::create(dir.join(format!("f{i}"))).unwrap();
        }
        assert_eq!(
            compute_dir_inventory(&dir).await.unwrap().len(),
            MAX_INVENTORY_ENTRIES,
            "a dir at exactly the entry cap still inventories"
        );

        std::fs::File::create(dir.join("one-more")).unwrap();
        let err = compute_dir_inventory(&dir).await.unwrap_err();
        assert!(err.contains("exceeds 10000 files"), "got: {err}");
    }

    /// A committed artifact grown past the 512 MiB health-hash cap whose
    /// TAIL is still a valid wheel (zip readers resolve the archive offset
    /// past leading garbage) verifies member-wise but must classify
    /// Corrupt/unreadable: the ledger-sha cross-check cannot vouch for
    /// bytes it refuses to hash.
    #[tokio::test]
    async fn oversize_artifact_with_valid_zip_tail_is_corrupt_unreadable() {
        use std::io::{Seek, SeekFrom};

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel = format!(".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl");
        tokio::fs::create_dir_all(root.join(format!(".socket/vendor/pypi/{UUID}")))
            .await
            .unwrap();

        // A valid wheel appended after a 512 MiB sparse zero prefix.
        let scratch = root.join("scratch.whl");
        write_whl(&scratch, "six.py", PATCHED);
        let wheel_bytes = std::fs::read(&scratch).unwrap();
        let abs = root.join(&rel);
        let mut file = std::fs::File::create(&abs).unwrap();
        file.set_len(MAX_HEALTH_HASH_BYTES).unwrap();
        file.seek(SeekFrom::End(0)).unwrap();
        file.write_all(&wheel_bytes).unwrap();
        drop(file);

        let rec = record(UUID, "six.py");
        let mut ent = entry("pypi", UUID, &rel);
        ent.artifact.sha256 = "0".repeat(64);

        // Precondition: the zip reader tolerates the prefix, so member
        // verification alone would bless the artifact…
        assert!(
            verify_vendored_patch_record(root, &ent, &rec).await.is_ok(),
            "zip reader must resolve the archive offset past the sparse prefix"
        );
        // …and only the whole-file arm catches it: file_sha256_hex bails
        // on the size cap, so the recorded sha is unverifiable.
        assert_eq!(
            check_vendored_artifact(root, &ent, &rec).await,
            ArtifactHealth::Corrupt {
                reason: "vendor_artifact_unreadable".to_string()
            }
        );
    }
}
