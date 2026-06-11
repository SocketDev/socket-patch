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
//! `file_not_found` / `vendor_hash_mismatch`.

use std::collections::HashMap;
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

    let path_str = artifact.to_string_lossy().to_string();
    if path_str.ends_with(".tgz") || path_str.ends_with(".tar.gz") {
        verify_tarball_members(&artifact, record).await
    } else if path_str.ends_with(".whl") {
        verify_wheel_members(&artifact, record).await
    } else {
        verify_dir_members(&artifact, record).await
    }
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

/// npm tarballs: decode in memory via the bomb-capped patch-archive reader
/// (it strips the `package/` prefix, matching `normalize_file_path`'d keys)
/// and hash each member against its afterHash.
async fn verify_tarball_members(tgz: &Path, record: &PatchRecord) -> Result<(), String> {
    let tgz = tgz.to_path_buf();
    let map = tokio::task::spawn_blocking(move || read_archive_to_map(&tgz))
        .await
        .map_err(|_| "vendor_artifact_unreadable".to_string())?
        .map_err(|_| "vendor_artifact_unreadable".to_string())?;
    verify_member_map(&map, record)
}

/// pypi wheels: bounded zip decode (member names are site-packages-relative,
/// exactly the manifest's pypi key space).
async fn verify_wheel_members(whl: &Path, record: &PatchRecord) -> Result<(), String> {
    let whl = whl.to_path_buf();
    let map = tokio::task::spawn_blocking(move || read_wheel_to_map(&whl))
        .await
        .map_err(|_| "vendor_artifact_unreadable".to_string())??;
    verify_member_map(&map, record)
}

fn read_wheel_to_map(whl: &Path) -> Result<HashMap<String, Vec<u8>>, String> {
    let file = std::fs::File::open(whl).map_err(|_| "vendor_artifact_unreadable".to_string())?;
    let mut zip =
        zip::ZipArchive::new(file).map_err(|_| "vendor_artifact_unreadable".to_string())?;
    if zip.len() > MAX_WHEEL_ENTRIES {
        return Err("vendor_artifact_unreadable".to_string());
    }
    let mut out = HashMap::new();
    let mut total: u64 = 0;
    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|_| "vendor_artifact_unreadable".to_string())?;
        if !entry.is_file() {
            continue;
        }
        // SECURITY: bound the cumulative decompressed size before reading —
        // a committed-but-tampered wheel must not balloon an audit's memory.
        total = total.saturating_add(entry.size());
        if total > MAX_WHEEL_DECOMPRESSED_BYTES {
            return Err("vendor_artifact_unreadable".to_string());
        }
        let name = entry.name().to_string();
        let mut bytes = Vec::new();
        entry
            .by_ref()
            .take(MAX_WHEEL_DECOMPRESSED_BYTES)
            .read_to_end(&mut bytes)
            .map_err(|_| "vendor_artifact_unreadable".to_string())?;
        out.insert(name, bytes);
    }
    Ok(out)
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
    use crate::patch::vendor::state::VendorArtifact;
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
}
