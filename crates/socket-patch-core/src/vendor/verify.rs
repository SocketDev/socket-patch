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
//! `file_not_found` / `vendor_hash_mismatch` / `vendor_inventory_mismatch` /
//! `vendor_manifest_unverifiable`
//! (dir-shaped artifacts with a recorded [`file_inventory`] additionally
//! verify their FULL file tree — missing, extra and modified unpatched
//! files all fail; entries without one keep member-only verification).
//!
//! [`file_inventory`]: super::state::VendorArtifact::file_inventory

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::hash::git_sha256::compute_git_sha256_from_bytes;
use crate::manifest::schema::{PatchFileInfo, PatchRecord};
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
pub(crate) fn checked_artifact_path(
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
    if is_vlt_dir_entry(entry) {
        return verify_vlt_dir(project_root, &artifact, entry, record).await;
    }
    let path_str = artifact.to_string_lossy();
    let is_tarball = path_str.ends_with(".tgz") || path_str.ends_with(".tar.gz");
    let is_zip =
        path_str.ends_with(".whl") || path_str.ends_with(".nupkg") || path_str.ends_with(".jar");
    if !is_tarball && !is_zip {
        let cargo_uuid = (entry.ecosystem == "cargo").then_some(entry.uuid.as_str());
        verify_dir_members(&artifact, record, cargo_uuid).await?;
        // Whole-tree cross-check: a dir-shaped artifact's bytes are covered
        // by NO lockfile integrity (bundler path sources, cargo path deps,
        // …), so the members above are the only thing the record can vouch
        // for — a recorded inventory extends the verdict to every file
        // (missing / extra / modified unpatched files, the stub gemspec).
        // Pre-inventory entries carry `None` and keep member-only behavior.
        if let Some(inventory) = &entry.artifact.file_inventory {
            let cargo_uuid = (entry.ecosystem == "cargo").then_some(entry.uuid.as_str());
            verify_dir_inventory(&artifact, inventory, cargo_uuid).await?;
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
    verify_member_map(&map, record)?;
    super::bun_workspace::verify(project_root, entry).await
}

/// Dir-shaped ecosystems (cargo/golang/composer/gem): hash files in place,
/// reusing the hardened per-file verifier (it normalizes manifest keys and
/// fail-closes on path-escaping keys). A cargo copy's `Cargo.toml` carries
/// the `+socket.<uuid>` version tag written after the patch applied
/// (`vendor::cargo_tag`): a patched `Cargo.toml` verifies with the tag
/// dropped, provided the tag is exactly `cargo_uuid` (the entry's own patch)
/// — the same pin [`verify_dir_inventory`] applies. A copy tagged for ANOTHER
/// patch is a different build than the lock's `<version>+socket.<uuid>` names,
/// so it stays a mismatch here instead of verifying clean while VEX discovery
/// refuses it.
async fn verify_dir_members(
    dir: &Path,
    record: &PatchRecord,
    cargo_uuid: Option<&str>,
) -> Result<(), String> {
    for (file_name, info) in &record.files {
        let result = verify_file_patch(dir, file_name, info).await;
        match result.status {
            VerifyStatus::AlreadyPatched => continue,
            VerifyStatus::Ready | VerifyStatus::HashMismatch
                if match cargo_uuid {
                    Some(uuid) => {
                        super::cargo_tag::is_copy_manifest_key(file_name)
                            && untagged_manifest_matches(dir, uuid, &info.after_hash).await
                    }
                    None => false,
                } =>
            {
                continue
            }
            VerifyStatus::Ready | VerifyStatus::HashMismatch => {
                return Err("vendor_hash_mismatch".to_string())
            }
            VerifyStatus::NotFound => return Err("file_not_found".to_string()),
        }
    }
    Ok(())
}

/// A vlt package-dir entry (DESIGN §4.2): npm, flavor `vlt`, not a tarball.
pub(crate) fn is_vlt_dir_entry(entry: &VendorEntry) -> bool {
    entry.ecosystem == "npm"
        && entry.flavor.as_deref() == Some(super::vlt_lock::FLAVOR)
        && !artifact_is_file_shaped(&entry.artifact.path)
}

/// The largest afterHash blob the vlt manifest exemption reads.
const MAX_MANIFEST_BLOB_BYTES: u64 = 16 * 1024 * 1024;

/// A vlt package dir: the §4.2 structure rule, only links and `.bin/`
/// scripts under its `node_modules/`, every record member at its afterHash
/// with the vlt manifest exemption for `package.json` (§4.4), and the
/// inventory of everything but `node_modules/`.
async fn verify_vlt_dir(
    project_root: &Path,
    dir: &Path,
    entry: &VendorEntry,
    record: &PatchRecord,
) -> Result<(), String> {
    let Some((name, _)) = parse_vendor_path(&entry.artifact.path)
        .and_then(|p| super::vlt_lock_text::parse_vendored_dir_leaf(&p.leaf))
    else {
        return Err("vendor_path_unsafe".to_string());
    };
    if !super::npm_dir::structure_rule_holds(dir, &name).await
        || !super::npm_dir::node_modules_holds_only_links(dir).await
    {
        return Err("vendor_inventory_mismatch".to_string());
    }
    let inventory = entry.artifact.file_inventory.as_ref();
    for (file_name, info) in &record.files {
        if normalize_file_path(file_name) == "package.json" {
            if let Some(pin) = inventory.and_then(|inv| inv.get("package.json")) {
                if vlt_manifest_matches(project_root, dir, pin, &info.after_hash).await {
                    continue;
                }
                return Err("vendor_hash_mismatch".to_string());
            }
            unpinned_vlt_manifest(project_root, dir, file_name, info).await?;
            continue;
        }
        match verify_file_patch(dir, file_name, info).await.status {
            VerifyStatus::AlreadyPatched => {}
            VerifyStatus::Ready | VerifyStatus::HashMismatch => {
                return Err("vendor_hash_mismatch".to_string())
            }
            VerifyStatus::NotFound => return Err("file_not_found".to_string()),
        }
    }
    if let Some(inventory) = inventory {
        let actual = compute_package_dir_inventory(dir)
            .await
            .map_err(|_| "vendor_artifact_unreadable".to_string())?;
        let same = actual.len() == inventory.len()
            && inventory
                .iter()
                .all(|(rel, sha)| actual.get(rel).is_some_and(|a| a.eq_ignore_ascii_case(sha)));
        if !same {
            return Err("vendor_inventory_mismatch".to_string());
        }
    }
    Ok(())
}

/// Whether `installed`, an installed copy of the vlt package-dir `entry`,
/// carries `record`. vlt links a `file:` dependency straight to the
/// committed directory, so a copy that resolves to it is the artifact
/// itself; any other copy verifies each member, `package.json` under the
/// vlt manifest exemption.
pub(crate) async fn vlt_installed_copy_matches(
    project_root: &Path,
    installed: &Path,
    entry: &VendorEntry,
    record: &PatchRecord,
) -> bool {
    let artifact = project_root.join(normalize_file_path(&entry.artifact.path));
    if let (Ok(a), Ok(b)) = (
        tokio::fs::canonicalize(installed).await,
        tokio::fs::canonicalize(&artifact).await,
    ) {
        if a == b {
            return true;
        }
    }
    let pin = entry
        .artifact
        .file_inventory
        .as_ref()
        .and_then(|inv| inv.get("package.json"));
    for (file_name, info) in &record.files {
        if normalize_file_path(file_name) == "package.json" {
            let matches = match pin {
                Some(pin) => {
                    vlt_manifest_matches(project_root, installed, pin, &info.after_hash).await
                }
                None => unpinned_vlt_manifest(project_root, installed, file_name, info)
                    .await
                    .is_ok(),
            };
            if !matches {
                return false;
            }
            continue;
        }
        if verify_file_patch(installed, file_name, info).await.status
            != VerifyStatus::AlreadyPatched
        {
            return false;
        }
    }
    true
}

/// The vlt manifest exemption (DESIGN §4.4): the committed `package.json`
/// is post-transform, so it verifies iff it hashes to the inventory pin and,
/// when the afterHash blob is in the local blob store, the blob with its
/// devDependencies stripped hashes to that pin too.
async fn vlt_manifest_matches(
    project_root: &Path,
    dir: &Path,
    pin: &str,
    after_hash: &str,
) -> bool {
    use sha2::{Digest, Sha256};
    let Ok(on_disk) = crate::utils::fs::read_regular_to_bytes(&dir.join("package.json")).await
    else {
        return false;
    };
    if !hex::encode(Sha256::digest(&on_disk)).eq_ignore_ascii_case(pin) {
        return false;
    }
    let Some(blob) = local_after_blob(project_root, after_hash).await else {
        return true;
    };
    stripped_manifest(blob)
        .is_some_and(|stripped| hex::encode(Sha256::digest(&stripped)).eq_ignore_ascii_case(pin))
}

/// The vlt manifest exemption for an entry with no inventory pin (one
/// built from `vlt-lock.json` alone): `package.json` verifies at its
/// afterHash, or as the local afterHash blob with its devDependencies
/// stripped. Without that blob a transformed manifest cannot be judged
/// (`vendor_manifest_unverifiable`).
async fn unpinned_vlt_manifest(
    project_root: &Path,
    dir: &Path,
    file_name: &str,
    info: &PatchFileInfo,
) -> Result<(), String> {
    match verify_file_patch(dir, file_name, info).await.status {
        VerifyStatus::AlreadyPatched => return Ok(()),
        VerifyStatus::NotFound => return Err("file_not_found".to_string()),
        VerifyStatus::Ready | VerifyStatus::HashMismatch => {}
    }
    let Some(blob) = local_after_blob(project_root, &info.after_hash).await else {
        return Err("vendor_manifest_unverifiable".to_string());
    };
    let Ok(on_disk) = crate::utils::fs::read_regular_to_bytes(&dir.join("package.json")).await
    else {
        return Err("vendor_artifact_unreadable".to_string());
    };
    if stripped_manifest(blob).is_some_and(|stripped| stripped == on_disk) {
        Ok(())
    } else {
        Err("vendor_hash_mismatch".to_string())
    }
}

/// The afterHash blob from the local blob store, when present, bounded and
/// intact.
async fn local_after_blob(project_root: &Path, after_hash: &str) -> Option<Vec<u8>> {
    let blob_path = project_root.join(".socket/blobs").join(after_hash);
    let blob = match tokio::fs::metadata(&blob_path).await {
        Ok(meta) if meta.is_file() && meta.len() <= MAX_MANIFEST_BLOB_BYTES => {
            crate::utils::fs::read_regular_to_bytes(&blob_path)
                .await
                .ok()
        }
        _ => None,
    };
    blob.filter(|b| compute_git_sha256_from_bytes(b).eq_ignore_ascii_case(after_hash))
}

/// `blob` with its top-level devDependencies stripped (§4.4); `None` when
/// the transform refuses it.
fn stripped_manifest(blob: Vec<u8>) -> Option<Vec<u8>> {
    let text = String::from_utf8(blob).ok()?;
    match super::npm_dir::strip_dev_dependencies(&text) {
        Ok(Some(stripped)) => Some(stripped.into_bytes()),
        Ok(None) => Some(text.into_bytes()),
        Err(_) => None,
    }
}

/// Does the cargo copy's `Cargo.toml`, Socket tag dropped, hash to
/// `after_hash` — with the tag being exactly `uuid`'s? A manifest tagged for
/// another patch (a hand edit, a merged vendored tree, a half-applied uuid
/// bump) is NOT this entry's copy, so it never matches.
async fn untagged_manifest_matches(dir: &Path, uuid: &str, after_hash: &str) -> bool {
    let Ok(text) = crate::utils::fs::read_regular_to_string(&dir.join("Cargo.toml")).await else {
        return false;
    };
    if super::cargo_tag::manifest_tag_uuid(&text).as_deref() != Some(uuid) {
        return false;
    }
    super::cargo_tag::untagged_manifest_bytes(text.as_bytes())
        .is_some_and(|b| compute_git_sha256_from_bytes(&b).eq_ignore_ascii_case(after_hash))
}

fn read_wheel_to_map(whl: &Path) -> Result<HashMap<String, Vec<u8>>, String> {
    // The shared guarded opener: non-blocking open + regular-file check on
    // the handle, so a FIFO planted at the artifact path fails the audit
    // instead of wedging it in `open(2)` waiting for a writer that never
    // comes (mirrors `read_archive_to_map`). The handle is kept — the zip
    // reader streams from it.
    let (file, _metadata) = crate::utils::fs::open_regular_file_sync(whl)
        .map_err(|_| "vendor_artifact_unreadable".to_string())?;
    read_zip_to_map(file, false)
}

/// [`read_wheel_to_map`] over in-memory zip bytes — the same entry and
/// decompressed-size caps — for callers that hash and decode the SAME
/// buffer (a committed wheel read exactly once).
#[cfg(test)]
pub(crate) fn read_zip_bytes_to_map(bytes: &[u8]) -> Result<HashMap<String, Vec<u8>>, String> {
    read_zip_to_map(std::io::Cursor::new(bytes), false)
}

/// [`read_zip_bytes_to_map`] that also refuses a wheel an installer could
/// extract differently from how it decodes: a symlink entry, a name outside
/// [`canonical_member_key`]'s shape (non-ASCII, backslash, `..`, absolute),
/// or two entries that collide exactly or after ASCII case-folding (a
/// case-insensitive filesystem keeps only one of `six.py` / `SIX.py`, and
/// which one is the installer's choice, not ours). Fails with
/// `vendor_artifact_non_canonical`. For re-verifying a COMMITTED wheel
/// before it is reused unchanged.
///
/// [`canonical_member_key`]: crate::patch::package::canonical_member_key
pub(crate) fn read_zip_bytes_to_map_strict(
    bytes: &[u8],
) -> Result<HashMap<String, Vec<u8>>, String> {
    read_zip_to_map(std::io::Cursor::new(bytes), true)
}

/// The shared bounded zip decoder behind [`read_wheel_to_map`] and
/// [`read_zip_bytes_to_map`] (plus the canonical-shape gate when `strict`).
fn read_zip_to_map<R: Read + std::io::Seek>(
    reader: R,
    strict: bool,
) -> Result<HashMap<String, Vec<u8>>, String> {
    let mut zip =
        zip::ZipArchive::new(reader).map_err(|_| "vendor_artifact_unreadable".to_string())?;
    if zip.len() > MAX_WHEEL_ENTRIES {
        return Err("vendor_artifact_unreadable".to_string());
    }
    let mut out = HashMap::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut declared: u64 = 0;
    let mut actual: u64 = 0;
    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|_| "vendor_artifact_unreadable".to_string())?;
        if strict {
            let non_canonical = || "vendor_artifact_non_canonical".to_string();
            if entry.is_symlink() || entry.name().starts_with('/') {
                return Err(non_canonical());
            }
            let key = crate::patch::package::canonical_member_key(entry.name())
                .ok_or_else(non_canonical)?;
            // Directories share the key space: a dir `six.py/` next to a
            // file `SIX.py` collides on disk too.
            if !seen.insert(key) {
                return Err(non_canonical());
            }
        }
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
pub(crate) const MAX_HEALTH_HASH_BYTES: u64 = 512 * 1024 * 1024;

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
    inventory_walk(dir, false).await
}

/// [`compute_dir_inventory`] of a vlt package dir, leaving out its top-level
/// `node_modules/` (vlt's links, never part of the artifact).
pub(crate) async fn compute_package_dir_inventory(
    dir: &Path,
) -> Result<BTreeMap<String, String>, String> {
    inventory_walk(dir, true).await
}

async fn inventory_walk(
    dir: &Path,
    skip_node_modules: bool,
) -> Result<BTreeMap<String, String>, String> {
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
                if skip_node_modules && rel.is_empty() && name == "node_modules" {
                    continue;
                }
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
///
/// `cargo_uuid` (a cargo copy's patch uuid): the copy's root `Cargo.toml`
/// may ALSO match with its Socket version tag dropped, provided the tag is
/// exactly `cargo_uuid` — an inventory recorded over a copy vendored
/// before tagged versions keeps verifying once a re-run / repair tags it,
/// while every other byte (including any other tag) stays pinned. So the
/// tag step never re-baselines the inventory over bytes nobody verified.
async fn verify_dir_inventory(
    dir: &Path,
    inventory: &BTreeMap<String, String>,
    cargo_uuid: Option<&str>,
) -> Result<(), String> {
    let actual = compute_dir_inventory(dir)
        .await
        .map_err(|_| "vendor_artifact_unreadable".to_string())?;
    if actual.len() != inventory.len() {
        return Err("vendor_inventory_mismatch".to_string());
    }
    let untagged_manifest = match cargo_uuid {
        Some(uuid) => untagged_manifest_sha256(dir, uuid).await,
        None => None,
    };
    for (rel, recorded) in inventory {
        match actual.get(rel) {
            Some(live) if live.eq_ignore_ascii_case(recorded) => {}
            Some(_)
                if rel == "Cargo.toml"
                    && untagged_manifest
                        .as_deref()
                        .is_some_and(|h| h.eq_ignore_ascii_case(recorded)) => {}
            _ => return Err("vendor_inventory_mismatch".to_string()),
        }
    }
    Ok(())
}

/// Plain sha256 of the cargo copy manifest `<dir>/Cargo.toml` with its
/// Socket tag dropped — `None` unless the manifest is tagged for exactly
/// `uuid`.
async fn untagged_manifest_sha256(dir: &Path, uuid: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    let text = crate::utils::fs::read_regular_to_string(&dir.join("Cargo.toml"))
        .await
        .ok()?;
    if super::cargo_tag::manifest_tag_uuid(&text).as_deref() != Some(uuid) {
        return None;
    }
    super::cargo_tag::untagged_manifest_bytes(text.as_bytes())
        .map(|b| hex::encode(Sha256::digest(&b)))
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
    /// An npm entry wired by a flavor this build has no backend for (a
    /// newer socket-patch): its layout is not ours to judge or rebuild.
    UnknownFlavor { flavor: String },
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
    if entry.ecosystem == "npm" && !super::npm_flavor::npm_flavor_is_known(entry.flavor.as_deref())
    {
        return ArtifactHealth::UnknownFlavor {
            flavor: entry.flavor.clone().unwrap_or_default(),
        };
    }
    match verify_vendored_patch_record(project_root, entry, record).await {
        Err(tag) => {
            // A broken member copy must not hide a simultaneously corrupt
            // canonical artifact: repair can copy mirrors directly only
            // after the canonical fingerprint has been verified.
            if tag.starts_with("vendor_workspace_artifact_") && !entry.artifact.sha256.is_empty() {
                match file_sha256_hex(&project_root.join(&entry.artifact.path)).await {
                    Some(hex) if hex.eq_ignore_ascii_case(&entry.artifact.sha256) => {}
                    _ => {
                        return ArtifactHealth::Corrupt {
                            reason: "vendor_sha256_mismatch".into(),
                        }
                    }
                }
            }
            match tag.as_str() {
                "vendor_artifact_missing" => ArtifactHealth::Missing,
                "vendor_uuid_mismatch" => ArtifactHealth::StaleUuid,
                "vendor_hash_mismatch"
                | "file_not_found"
                | "vendor_artifact_unreadable"
                | "vendor_inventory_mismatch"
                | "vendor_workspace_artifact_missing"
                | "vendor_workspace_artifact_corrupt" => ArtifactHealth::Corrupt { reason: tag },
                _ => ArtifactHealth::Unverifiable { reason: tag },
            }
        }
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
/// rebuilt artifact's recorded sha). Opens once through the shared guarded
/// opener (`O_NONBLOCK` + fstat on the handle), so the size gate and the
/// bytes hashed come from the same inode and a FIFO swapped in at the path
/// can never wedge the health check in `open(2)`.
pub async fn file_sha256_hex(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncReadExt;

    let (mut file, meta) = crate::utils::fs::open_regular_file(path).await.ok()?;
    if meta.len() > MAX_HEALTH_HASH_BYTES {
        return None;
    }
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

pub(crate) fn verify_member_map(
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

    /// The in-memory zip reader decodes exactly what the path reader does.
    #[test]
    fn zip_bytes_reader_matches_path_reader() {
        let dir = tempfile::tempdir().unwrap();
        let whl = dir.path().join("x-1.0-py3-none-any.whl");
        write_whl(&whl, "x/__init__.py", PATCHED);
        let bytes = std::fs::read(&whl).unwrap();
        let from_bytes = read_zip_bytes_to_map(&bytes).unwrap();
        assert_eq!(from_bytes, read_wheel_to_map(&whl).unwrap());
        assert_eq!(
            from_bytes.get("x/__init__.py").map(Vec::as_slice),
            Some(PATCHED)
        );
        assert_eq!(
            read_zip_bytes_to_map(b"not a zip").unwrap_err(),
            "vendor_artifact_unreadable"
        );
    }

    #[tokio::test]
    async fn binary_workspace_health_attests_every_installable_tarball() {
        use base64::Engine as _;
        use sha2::Digest;
        let root = tempfile::tempdir().unwrap();
        let rel = format!(".socket/vendor/npm/{UUID}/minimist-1.2.2.tgz");
        std::fs::create_dir_all(root.path().join(&rel).parent().unwrap()).unwrap();
        write_tgz(&root.path().join(&rel), "package/index.js", PATCHED);
        let bytes = std::fs::read(root.path().join(&rel)).unwrap();
        let mut entry = entry("npm", UUID, &rel);
        entry.base_purl = "pkg:npm/minimist@1.2.2".into();
        entry.flavor = Some("bun".into());
        entry.artifact.sha256 = hex::encode(sha2::Sha256::digest(&bytes));
        let record = record(UUID, "index.js");
        let mut lock = super::super::bun_lockb::BunLockb::parse(include_bytes!(
            "../../tests/fixtures/bun-lockb/1.1.45-extensions/bun.lockb"
        ))
        .unwrap();
        let id = lock
            .packages()
            .unwrap()
            .into_iter()
            .find(|p| p.name == "minimist")
            .unwrap()
            .id;
        let sri = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(&bytes))
        );
        lock.set_package(id, &rel, &sri).unwrap();
        std::fs::write(root.path().join("bun.lockb"), lock.bytes()).unwrap();
        assert_eq!(
            check_vendored_artifact(root.path(), &entry, &record).await,
            ArtifactHealth::Corrupt {
                reason: "vendor_workspace_artifact_missing".into()
            }
        );
        entry.wiring = super::super::bun_workspace::repair(root.path(), &entry, false)
            .await
            .unwrap()
            .0;
        assert_eq!(
            check_vendored_artifact(root.path(), &entry, &record).await,
            ArtifactHealth::Healthy
        );
        std::fs::write(root.path().join(&entry.wiring[0].file), b"corrupt mirror").unwrap();
        assert_eq!(
            verify_vendored_patch_record(root.path(), &entry, &record)
                .await
                .unwrap_err(),
            "vendor_workspace_artifact_corrupt"
        );
        // The archive's patched member remains readable, but the canonical
        // fingerprint must take precedence over the damaged member copy.
        let mut changed = bytes;
        changed.extend_from_slice(b"trailing drift");
        std::fs::write(root.path().join(&rel), changed).unwrap();
        assert_eq!(
            check_vendored_artifact(root.path(), &entry, &record).await,
            ArtifactHealth::Corrupt {
                reason: "vendor_sha256_mismatch".into()
            }
        );
    }

    /// A cargo copy's inventory taken before tagged versions keeps
    /// verifying once its `Cargo.toml` carries THIS entry's tag (the check
    /// drops exactly that tag); a tag for another uuid, a drifted byte in
    /// the manifest beside the tag, or the same tag on a non-cargo entry all
    /// fail.
    #[tokio::test]
    async fn cargo_inventory_accepts_only_this_uuids_manifest_tag() {
        const OTHER: &str = "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d";
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel = format!(".socket/vendor/cargo/{UUID}/cfg-if-1.0.4");
        let dir = root.join(&rel);
        tokio::fs::create_dir_all(dir.join("src")).await.unwrap();
        tokio::fs::write(dir.join("src/lib.rs"), PATCHED)
            .await
            .unwrap();
        let untagged = "[package]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n";
        tokio::fs::write(dir.join("Cargo.toml"), untagged)
            .await
            .unwrap();

        let rec = record(UUID, "package/src/lib.rs");
        let mut ent = entry("cargo", UUID, &rel);
        ent.base_purl = "pkg:cargo/cfg-if@1.0.4".into();
        ent.artifact.file_inventory = Some(compute_dir_inventory(&dir).await.unwrap());
        assert!(verify_vendored_patch_record(root, &ent, &rec).await.is_ok());

        let tagged = |uuid: &str| untagged.replace("1.0.4", &format!("1.0.4+socket.{uuid}"));
        tokio::fs::write(dir.join("Cargo.toml"), tagged(UUID))
            .await
            .unwrap();
        assert!(
            verify_vendored_patch_record(root, &ent, &rec).await.is_ok(),
            "this uuid's tag verifies"
        );

        for (why, text) in [
            ("another uuid's tag", tagged(OTHER)),
            (
                "drift beside the tag",
                tagged(UUID) + "build = \"build.rs\"\n",
            ),
        ] {
            tokio::fs::write(dir.join("Cargo.toml"), text)
                .await
                .unwrap();
            assert_eq!(
                verify_vendored_patch_record(root, &ent, &rec)
                    .await
                    .unwrap_err(),
                "vendor_inventory_mismatch",
                "{why}"
            );
        }

        tokio::fs::write(dir.join("Cargo.toml"), tagged(UUID))
            .await
            .unwrap();
        let rec_gem = record(UUID, "src/lib.rs");
        let mut gem = entry("gem", UUID, &rel);
        gem.artifact.file_inventory = ent.artifact.file_inventory.clone();
        assert_eq!(
            verify_vendored_patch_record(root, &gem, &rec_gem)
                .await
                .unwrap_err(),
            "vendor_inventory_mismatch",
            "the tag allowance is cargo's alone"
        );
    }

    /// The MEMBER path (a record keyed on the copy's own `Cargo.toml`, the
    /// shape a patch that edits the crate's manifest takes) applies the same
    /// uuid pin as the inventory path: the tag is dropped only when it is
    /// THIS entry's. Cargo entries carry no inventory
    /// (`vendor::cargo` records `file_inventory: None`), so this is the live
    /// path, not a legacy one — and a copy tagged for another patch builds
    /// as a version the lock does not name, which VEX discovery already
    /// refuses to attest.
    #[tokio::test]
    async fn cargo_member_path_accepts_only_this_uuids_manifest_tag() {
        const OTHER: &str = "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d";
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel = format!(".socket/vendor/cargo/{UUID}/cfg-if-1.0.4");
        let dir = root.join(&rel);
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let untagged = "[package]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n\
                        \n[dependencies]\nlibc = \"0.2.155\"\n";
        let mut rec = record(UUID, "Cargo.toml");
        rec.files.insert(
            "Cargo.toml".to_string(),
            PatchFileInfo {
                before_hash: "b".into(),
                after_hash: compute_git_sha256_from_bytes(untagged.as_bytes()),
            },
        );
        let mut ent = entry("cargo", UUID, &rel);
        ent.base_purl = "pkg:cargo/cfg-if@1.0.4".into();
        assert!(ent.artifact.file_inventory.is_none(), "cargo records none");

        let tagged = |uuid: &str| untagged.replace("1.0.4\"", &format!("1.0.4+socket.{uuid}\""));
        for (why, text, want) in [
            (
                "untagged (the patch's own bytes)",
                untagged.to_string(),
                None,
            ),
            ("this uuid's tag", tagged(UUID), None),
            (
                "another uuid's tag",
                tagged(OTHER),
                Some("vendor_hash_mismatch"),
            ),
            (
                "drift beside this uuid's tag",
                tagged(UUID) + "build = \"build.rs\"\n",
                Some("vendor_hash_mismatch"),
            ),
        ] {
            tokio::fs::write(dir.join("Cargo.toml"), &text)
                .await
                .unwrap();
            let got = verify_vendored_patch_record(root, &ent, &rec).await;
            match want {
                None => assert!(got.is_ok(), "{why}: {got:?}"),
                Some(err) => assert_eq!(got.as_ref().unwrap_err(), err, "{why}"),
            }
            let health = check_vendored_artifact(root, &ent, &rec).await;
            assert_eq!(
                health == ArtifactHealth::Healthy,
                want.is_none(),
                "{why}: repair's rebuild decision follows the same verdict ({health:?})"
            );
        }

        // The allowance is cargo's alone: the same bytes under another
        // dir-shaped ecosystem stay pinned to the recorded hash.
        tokio::fs::write(dir.join("Cargo.toml"), tagged(UUID))
            .await
            .unwrap();
        let mut gem = entry("gem", UUID, &rel);
        gem.base_purl = "pkg:gem/cfg-if@1.0.4".into();
        assert_eq!(
            verify_vendored_patch_record(root, &gem, &rec)
                .await
                .unwrap_err(),
            "vendor_hash_mismatch"
        );
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

    #[cfg(unix)]
    #[tokio::test]
    async fn vlt_dirs_verify_with_links_and_refuse_planted_or_extra_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel = format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0/node_modules/left-pad");
        let dir = root.join(&rel);
        tokio::fs::create_dir_all(dir.join("node_modules/.bin"))
            .await
            .unwrap();
        tokio::fs::write(dir.join("index.js"), PATCHED)
            .await
            .unwrap();
        std::os::unix::fs::symlink("../../../dep", dir.join("node_modules/dep")).unwrap();
        tokio::fs::write(dir.join("node_modules/.bin/dep"), b"#!/bin/sh\n")
            .await
            .unwrap();
        let rec = record(UUID, "package/index.js");
        let mut ent = entry("npm", UUID, &rel);
        ent.flavor = Some("vlt".into());
        ent.artifact.file_inventory = Some(compute_package_dir_inventory(&dir).await.unwrap());
        assert_eq!(
            ent.artifact
                .file_inventory
                .as_ref()
                .unwrap()
                .keys()
                .collect::<Vec<_>>(),
            ["index.js"]
        );
        assert_eq!(
            check_vendored_artifact(root, &ent, &rec).await,
            ArtifactHealth::Healthy
        );

        tokio::fs::write(dir.join("node_modules/planted.js"), b"x")
            .await
            .unwrap();
        assert_eq!(
            verify_vendored_patch_record(root, &ent, &rec).await,
            Err("vendor_inventory_mismatch".to_string())
        );
        tokio::fs::remove_file(dir.join("node_modules/planted.js"))
            .await
            .unwrap();

        let beside = root.join(format!(
            ".socket/vendor/npm/{UUID}/left-pad-1.3.0/node_modules/other"
        ));
        tokio::fs::create_dir_all(&beside).await.unwrap();
        assert_eq!(
            verify_vendored_patch_record(root, &ent, &rec).await,
            Err("vendor_inventory_mismatch".to_string())
        );
        tokio::fs::remove_dir(&beside).await.unwrap();

        tokio::fs::write(dir.join("extra.js"), b"x").await.unwrap();
        assert!(matches!(
            check_vendored_artifact(root, &ent, &rec).await,
            ArtifactHealth::Corrupt { .. }
        ));
    }

    #[tokio::test]
    async fn vlt_manifest_blob_pins_the_inventory() {
        use sha2::Digest;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel = format!(".socket/vendor/npm/{UUID}/a-1.0.0/node_modules/a");
        let dir = root.join(&rel);
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let blob: &[u8] = b"{\"name\":\"a\",\"devDependencies\":{\"t\":\"1\"},\"main\":\"m.js\"}";
        let committed = "{\"name\":\"a\",\"main\":\"x.js\"}";
        tokio::fs::write(dir.join("package.json"), committed)
            .await
            .unwrap();
        let mut rec = record(UUID, "package/index.js");
        rec.files.clear();
        rec.files.insert(
            "package/package.json".into(),
            PatchFileInfo {
                before_hash: "b".into(),
                after_hash: compute_git_sha256_from_bytes(blob),
            },
        );
        let mut ent = entry("npm", UUID, &rel);
        ent.flavor = Some("vlt".into());
        ent.artifact.file_inventory = Some(BTreeMap::from([(
            "package.json".to_string(),
            hex::encode(sha2::Sha256::digest(committed.as_bytes())),
        )]));
        assert_eq!(verify_vendored_patch_record(root, &ent, &rec).await, Ok(()));
        let blobs = root.join(".socket/blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        tokio::fs::write(blobs.join(compute_git_sha256_from_bytes(blob)), blob)
            .await
            .unwrap();
        assert_eq!(
            verify_vendored_patch_record(root, &ent, &rec).await,
            Err("vendor_hash_mismatch".to_string()),
            "the blob stripped is not what the inventory pins"
        );
        tokio::fs::write(
            dir.join("package.json"),
            "{\"name\":\"a\",\"main\":\"m.js\"}",
        )
        .await
        .unwrap();
        ent.artifact.file_inventory = Some(BTreeMap::from([(
            "package.json".to_string(),
            hex::encode(sha2::Sha256::digest(b"{\"name\":\"a\",\"main\":\"m.js\"}")),
        )]));
        assert_eq!(verify_vendored_patch_record(root, &ent, &rec).await, Ok(()));
    }

    #[tokio::test]
    async fn unknown_npm_flavor_is_never_judged_by_this_builds_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel = format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0/node_modules/left-pad");
        tokio::fs::create_dir_all(root.join(&rel).join("node_modules"))
            .await
            .unwrap();
        tokio::fs::write(root.join(&rel).join("index.js"), b"tampered")
            .await
            .unwrap();
        let rec = record(UUID, "package/index.js");
        let mut ent = entry("npm", UUID, &rel);
        ent.flavor = Some("future-pm".into());
        assert_eq!(
            check_vendored_artifact(root, &ent, &rec).await,
            ArtifactHealth::UnknownFlavor {
                flavor: "future-pm".into()
            }
        );
        ent.flavor = Some("bun".into());
        assert!(matches!(
            check_vendored_artifact(root, &ent, &rec).await,
            ArtifactHealth::Corrupt { .. }
        ));
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
