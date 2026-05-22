use std::collections::HashMap;
use std::path::Path;

use crate::hash::git_sha256::compute_git_sha256_from_bytes;
use crate::manifest::schema::PatchFileInfo;
use crate::patch::cow::break_hardlink_if_needed;
use crate::patch::diff::apply_diff;
use crate::patch::file_hash::compute_file_git_sha256;
use crate::patch::package::read_archive_filtered;

/// Status of a file patch verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyStatus {
    /// File is ready to be patched (current hash matches beforeHash).
    Ready,
    /// File is already in the patched state (current hash matches afterHash).
    AlreadyPatched,
    /// File hash does not match either beforeHash or afterHash.
    HashMismatch,
    /// File was not found on disk.
    NotFound,
}

/// Result of verifying whether a single file can be patched.
#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub file: String,
    pub status: VerifyStatus,
    pub message: Option<String>,
    pub current_hash: Option<String>,
    pub expected_hash: Option<String>,
    pub target_hash: Option<String>,
}

/// Which patch source actually wrote the patched bytes for a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppliedVia {
    /// Bytes came from a per-package archive in `.socket/packages/`.
    Package,
    /// Bytes were produced by applying a bsdiff delta from
    /// `.socket/diffs/<uuid>.tar.gz`.
    Diff,
    /// Bytes came from a per-file blob in `.socket/blobs/`.
    Blob,
}

impl AppliedVia {
    /// Short lowercase tag, suitable for JSON and human output.
    pub fn as_tag(&self) -> &'static str {
        match self {
            AppliedVia::Package => "package",
            AppliedVia::Diff => "diff",
            AppliedVia::Blob => "blob",
        }
    }
}

/// Patch sources the apply pipeline may use to obtain patched bytes.
///
/// `blobs_path` is always required and serves as the universal fallback.
/// `packages_path` and `diffs_path` are optional opt-ins to the new
/// pathways introduced in socket-patch 2.2.
#[derive(Debug, Clone, Copy)]
pub struct PatchSources<'a> {
    pub blobs_path: &'a Path,
    pub packages_path: Option<&'a Path>,
    pub diffs_path: Option<&'a Path>,
}

impl<'a> PatchSources<'a> {
    /// Construct a `PatchSources` that only knows about the legacy
    /// per-file blob directory. Convenient for tests and existing call
    /// sites that have not been upgraded.
    pub fn blobs_only(blobs_path: &'a Path) -> Self {
        Self {
            blobs_path,
            packages_path: None,
            diffs_path: None,
        }
    }
}

/// Result of applying patches to a single package.
#[derive(Debug, Clone)]
pub struct ApplyResult {
    pub package_key: String,
    pub package_path: String,
    pub success: bool,
    pub files_verified: Vec<VerifyResult>,
    pub files_patched: Vec<String>,
    /// Per-file record of which source produced the patched bytes. Only
    /// populated for files in `files_patched`.
    pub applied_via: HashMap<String, AppliedVia>,
    pub error: Option<String>,
    /// Ecosystem sidecar fixup outcome — a typed
    /// [`SidecarRecord`](crate::patch::sidecars::SidecarRecord) carrying
    /// per-file actions (rewritten / deleted / created) and an
    /// optional structured advisory. `None` when no sidecar
    /// applied (e.g. npm) or when no files were patched.
    ///
    /// Surfaced in the CLI JSON envelope under
    /// `Envelope.sidecars[]` (top-level, not per-event).
    pub sidecar: Option<crate::patch::sidecars::SidecarRecord>,
}

/// Normalize file path by removing the "package/" prefix if present.
/// Patch files come from the API with paths like "package/lib/file.js"
/// but we need relative paths like "lib/file.js" for the actual package directory.
pub fn normalize_file_path(file_name: &str) -> &str {
    const PACKAGE_PREFIX: &str = "package/";
    if let Some(stripped) = file_name.strip_prefix(PACKAGE_PREFIX) {
        stripped
    } else {
        file_name
    }
}

/// Verify a single file can be patched.
pub async fn verify_file_patch(
    pkg_path: &Path,
    file_name: &str,
    file_info: &PatchFileInfo,
) -> VerifyResult {
    let normalized = normalize_file_path(file_name);
    let filepath = pkg_path.join(normalized);

    let is_new_file = file_info.before_hash.is_empty();

    // Check if file exists
    if tokio::fs::metadata(&filepath).await.is_err() {
        // New files (empty beforeHash) are expected to not exist yet.
        if is_new_file {
            return VerifyResult {
                file: file_name.to_string(),
                status: VerifyStatus::Ready,
                message: None,
                current_hash: None,
                expected_hash: None,
                target_hash: Some(file_info.after_hash.clone()),
            };
        }
        return VerifyResult {
            file: file_name.to_string(),
            status: VerifyStatus::NotFound,
            message: Some("File not found".to_string()),
            current_hash: None,
            expected_hash: None,
            target_hash: None,
        };
    }

    // Compute current hash
    let current_hash = match compute_file_git_sha256(&filepath).await {
        Ok(h) => h,
        Err(e) => {
            return VerifyResult {
                file: file_name.to_string(),
                status: VerifyStatus::NotFound,
                message: Some(format!("Failed to hash file: {}", e)),
                current_hash: None,
                expected_hash: None,
                target_hash: None,
            };
        }
    };

    // Check if already patched
    if current_hash == file_info.after_hash {
        return VerifyResult {
            file: file_name.to_string(),
            status: VerifyStatus::AlreadyPatched,
            message: None,
            current_hash: Some(current_hash),
            expected_hash: None,
            target_hash: None,
        };
    }

    // New files (empty beforeHash) with existing content that doesn't match
    // afterHash: treat as Ready (force overwrite).
    if is_new_file {
        return VerifyResult {
            file: file_name.to_string(),
            status: VerifyStatus::Ready,
            message: None,
            current_hash: Some(current_hash),
            expected_hash: None,
            target_hash: Some(file_info.after_hash.clone()),
        };
    }

    // Check if matches expected before hash
    if current_hash != file_info.before_hash {
        return VerifyResult {
            file: file_name.to_string(),
            status: VerifyStatus::HashMismatch,
            message: Some("File hash does not match expected value".to_string()),
            current_hash: Some(current_hash),
            expected_hash: Some(file_info.before_hash.clone()),
            target_hash: Some(file_info.after_hash.clone()),
        };
    }

    VerifyResult {
        file: file_name.to_string(),
        status: VerifyStatus::Ready,
        message: None,
        current_hash: Some(current_hash),
        expected_hash: None,
        target_hash: Some(file_info.after_hash.clone()),
    }
}

/// Apply a patch to a single file.
///
/// **Permission policy** (per the user-visible contract — patched
/// files must look identical to pre-patch perms-wise):
///
/// 1. **Existing file**. Snapshot mode + owner + group before writing.
///    If the file is read-only, temporarily grant owner-write so the
///    overwrite succeeds (e.g. Go's module cache marks sources read-only).
///    After the write, restore the **exact** original mode and chown
///    back to the pre-patch uid/gid. Owners stay put even when
///    `tokio::fs::write` truncates and rewrites.
///
/// 2. **New file** (created by the patch). Inherit owner + group from
///    the parent directory and force mode `0o444` (read-only for all).
///    Mirrors how an unpacked tarball treats new package files —
///    consumers expect package sources to be read-only by default.
///
/// On Windows there is no `uid`/`gid`, so the owner/group step is a
/// no-op; the read-only attribute is preserved on existing files and
/// set on new files to honor the read-only-by-default policy.
///
/// Writes the patched content and verifies the resulting hash.
pub async fn apply_file_patch(
    pkg_path: &Path,
    file_name: &str,
    patched_content: &[u8],
    expected_hash: &str,
) -> Result<(), std::io::Error> {
    let normalized = normalize_file_path(file_name);
    let filepath = pkg_path.join(normalized);

    // Hash-check the in-memory content BEFORE touching disk. Removes
    // the prior "wrote bytes, then post-write verify failed, can't
    // restore" failure mode — if the upstream blob is corrupt we
    // error out before any disk write.
    let content_hash = compute_git_sha256_from_bytes(patched_content);
    if content_hash != expected_hash {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Hash verification failed before patch. Expected: {}, Got: {}",
                expected_hash, content_hash
            ),
        ));
    }

    // Snapshot pre-patch metadata so `restore_file_permissions` can
    // re-apply the original mode + uid/gid to the post-rename inode.
    // `None` means the file is being created by this patch — the
    // new-file branch of restore_file_permissions inherits from the
    // parent dir.
    let existing_meta = tokio::fs::metadata(&filepath).await.ok();

    // Create parent directories if needed (e.g., new files added by a patch).
    if let Some(parent) = filepath.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // Copy-on-write defense against pnpm / bazel / nix shared inodes.
    // If `filepath` is a symlink into a content store, or a hardlink
    // shared with other projects, give this project a private inode
    // before we mutate. No-op on regular private files (single
    // syscall). See `patch::cow`.
    break_hardlink_if_needed(&filepath).await?;

    // Atomic write: stage in the parent directory, fsync, rename onto
    // the target. POSIX `rename(2)` is atomic — observers see either
    // the old bytes or the new bytes, never a truncated half-write.
    //
    // The stage file is created with the user's umask defaults
    // (typically 0o644) — that's how we sidestep the "existing file
    // is 0o444" problem the old in-place write had: we rename a fresh
    // user-writable inode over the target instead of trying to open
    // a read-only file for write. `restore_file_permissions` then
    // re-applies the pre-patch mode + uid/gid to the new inode.
    write_atomic(&filepath, patched_content).await?;

    // Restore (or set) the final permissions on the post-rename inode.
    // On Unix this includes chown back to the pre-patch uid/gid (or
    // to the parent dir's uid/gid for new files); on Windows we only
    // manage the readonly attribute.
    restore_file_permissions(&filepath, existing_meta.as_ref()).await?;

    Ok(())
}

/// Write `content` to `target` atomically via stage + rename.
///
/// Two-phase commit:
///   1. Create `<parent>/.socket-stage-<filename>-<uuid>` (leading dot
///      so editor globs ignore it; uuid suffix so concurrent callers
///      never collide — defense in depth on top of the apply lock).
///   2. `write_all` the content, then `sync_all()` so the bytes are
///      durably on disk before the rename.
///   3. `rename(stage, target)` — atomic on POSIX, best-effort on
///      Windows. On failure unlink the stage so we don't leave a
///      dotfile behind in the package directory.
async fn write_atomic(target: &Path, content: &[u8]) -> std::io::Result<()> {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let stem = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "anon".to_string());
    let stage = parent.join(format!(
        ".socket-stage-{}-{}",
        stem,
        uuid::Uuid::new_v4()
    ));

    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stage)
        .await?;

    use tokio::io::AsyncWriteExt;
    if let Err(e) = file.write_all(content).await {
        let _ = tokio::fs::remove_file(&stage).await;
        return Err(e);
    }
    if let Err(e) = file.sync_all().await {
        let _ = tokio::fs::remove_file(&stage).await;
        return Err(e);
    }
    drop(file);

    if let Err(e) = tokio::fs::rename(&stage, target).await {
        let _ = tokio::fs::remove_file(&stage).await;
        return Err(e);
    }
    Ok(())
}

/// Restore the post-write permission state on `filepath`.
///
/// * `pre_patch` = `Some(meta)` → the file existed before the patch;
///   restore its exact mode + uid/gid.
/// * `pre_patch` = `None` → the file is new; inherit owner/group from
///   the parent dir and set mode `0o444`.
///
/// Split out of `apply_file_patch` to keep that function readable and
/// to make the platform branching unit-testable.
async fn restore_file_permissions(
    filepath: &Path,
    pre_patch: Option<&std::fs::Metadata>,
) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        match pre_patch {
            Some(meta) => {
                // Existing file: re-apply the original mode + ownership.
                let restored = std::fs::Permissions::from_mode(meta.mode());
                tokio::fs::set_permissions(filepath, restored).await?;
                let uid = meta.uid();
                let gid = meta.gid();
                chown_blocking(filepath.to_path_buf(), Some(uid), Some(gid)).await?;
            }
            None => {
                // New file. Inherit owner/group from the parent dir.
                if let Some(parent) = filepath.parent() {
                    if let Ok(parent_meta) = tokio::fs::metadata(parent).await {
                        let uid = parent_meta.uid();
                        let gid = parent_meta.gid();
                        chown_blocking(filepath.to_path_buf(), Some(uid), Some(gid))
                            .await?;
                    }
                }
                // Default new-file mode: read-only for all.
                let readonly = std::fs::Permissions::from_mode(0o444);
                tokio::fs::set_permissions(filepath, readonly).await?;
            }
        }
    }

    #[cfg(windows)]
    {
        match pre_patch {
            Some(meta) => {
                // Re-apply the pre-patch readonly state; tokio::fs::write
                // does not preserve it across the truncate+rewrite.
                let perms = meta.permissions();
                tokio::fs::set_permissions(filepath, perms).await?;
            }
            None => {
                // New file: read-only by default.
                if let Ok(meta) = tokio::fs::metadata(filepath).await {
                    let mut perms = meta.permissions();
                    perms.set_readonly(true);
                    tokio::fs::set_permissions(filepath, perms).await?;
                }
            }
        }
    }

    let _ = filepath;
    let _ = pre_patch;
    Ok(())
}

/// Synchronous `chown` wrapped to run on the blocking pool so we don't
/// stall the async runtime. `std::os::unix::fs::chown` is a thin
/// syscall wrapper — fast in the no-op case (uid/gid already match)
/// but still nominally blocking.
#[cfg(unix)]
async fn chown_blocking(
    path: std::path::PathBuf,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), std::io::Error> {
    tokio::task::spawn_blocking(move || std::os::unix::fs::chown(&path, uid, gid))
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?
}

/// Verify and apply patches for a single package.
///
/// For each file in `files`, this function:
/// 1. Verifies the file is ready to be patched (or already patched).
/// 2. If not dry_run, tries patch sources in order: package archive → diff
///    archive → per-file blob. Each strategy is opt-in via `sources`.
/// 3. Returns a summary of what happened.
///
/// `uuid` is the patch UUID. Pass `Some` to enable package- and
/// diff-archive lookup (the corresponding `sources.packages_path` /
/// `sources.diffs_path` must also be set). Pass `None` to restrict the
/// pipeline to per-file blobs only — equivalent to pre-2.2 behavior.
pub async fn apply_package_patch(
    package_key: &str,
    pkg_path: &Path,
    files: &HashMap<String, PatchFileInfo>,
    sources: &PatchSources<'_>,
    uuid: Option<&str>,
    dry_run: bool,
    force: bool,
) -> ApplyResult {
    let mut result = ApplyResult {
        package_key: package_key.to_string(),
        package_path: pkg_path.display().to_string(),
        success: false,
        files_verified: Vec::new(),
        files_patched: Vec::new(),
        applied_via: HashMap::new(),
        error: None,
        sidecar: None,
    };

    // First, verify all files
    for (file_name, file_info) in files {
        let mut verify_result = verify_file_patch(pkg_path, file_name, file_info).await;

        if verify_result.status != VerifyStatus::Ready
            && verify_result.status != VerifyStatus::AlreadyPatched
        {
            if force {
                match verify_result.status {
                    VerifyStatus::HashMismatch => {
                        // Force: treat hash mismatch as ready
                        verify_result.status = VerifyStatus::Ready;
                    }
                    VerifyStatus::NotFound => {
                        // Force: skip files that don't exist (non-new files)
                        result.files_verified.push(verify_result);
                        continue;
                    }
                    _ => {}
                }
            } else {
                let msg = verify_result
                    .message
                    .clone()
                    .unwrap_or_else(|| format!("{:?}", verify_result.status));
                result.error = Some(format!(
                    "Cannot apply patch: {} - {}",
                    verify_result.file, msg
                ));
                result.files_verified.push(verify_result);
                return result;
            }
        }

        result.files_verified.push(verify_result);
    }

    // Check if all files are already patched
    let all_already_patched = result
        .files_verified
        .iter()
        .all(|v| v.status == VerifyStatus::AlreadyPatched);

    if all_already_patched {
        result.success = true;
        return result;
    }

    // Check if all files are either already patched or not found (force mode skip)
    let all_done_or_skipped = result
        .files_verified
        .iter()
        .all(|v| v.status == VerifyStatus::AlreadyPatched || v.status == VerifyStatus::NotFound);

    if all_done_or_skipped {
        // Some or all files were not found but skipped via --force
        let not_found_count = result.files_verified.iter()
            .filter(|v| v.status == VerifyStatus::NotFound)
            .count();
        result.success = true;
        result.error = Some(format!(
            "All patch files were skipped: {} not found on disk (--force)",
            not_found_count
        ));
        return result;
    }

    // If dry run, stop here
    if dry_run {
        result.success = true;
        return result;
    }

    // Eagerly load the package and diff archives (if any) into memory so
    // we don't reparse the tar.gz once per file. Both are small archives.
    let package_entries = match (uuid, sources.packages_path) {
        (Some(uuid), Some(dir)) => load_archive_if_present(dir, uuid, files).await,
        _ => None,
    };
    let diff_entries = match (uuid, sources.diffs_path) {
        (Some(uuid), Some(dir)) => load_archive_if_present(dir, uuid, files).await,
        _ => None,
    };

    // Apply patches to files that need it. For each file, try package
    // archive first, then diff, then blob.
    for (file_name, file_info) in files {
        let verify_result = result.files_verified.iter().find(|v| v.file == *file_name);
        if let Some(vr) = verify_result {
            if vr.status == VerifyStatus::AlreadyPatched
                || vr.status == VerifyStatus::NotFound
            {
                continue;
            }
        }

        let normalized = normalize_file_path(file_name).to_string();

        // ── Strategy 1: package archive ──────────────────────────────
        if try_apply_from_archive(
            package_entries.as_ref(),
            &normalized,
            pkg_path,
            file_name,
            file_info,
        )
        .await
        {
            result.files_patched.push(file_name.clone());
            result
                .applied_via
                .insert(file_name.clone(), AppliedVia::Package);
            continue;
        }

        // ── Strategy 2: per-file diff ────────────────────────────────
        // Diffs only apply cleanly when the on-disk content actually
        // hashes to `before_hash` — otherwise the bsdiff output won't
        // match `after_hash`. We pass the pre-apply current_hash
        // captured by `verify_file_patch` so `try_apply_from_diff` can
        // skip the wasted decompress+apply work when --force is
        // overriding a hash mismatch (force flips status to Ready but
        // the underlying hash is still wrong).
        let current_hash_for_diff = verify_result.and_then(|v| v.current_hash.as_deref());
        if try_apply_from_diff(
            diff_entries.as_ref(),
            &normalized,
            pkg_path,
            file_name,
            file_info,
            current_hash_for_diff,
        )
        .await
        {
            result.files_patched.push(file_name.clone());
            result
                .applied_via
                .insert(file_name.clone(), AppliedVia::Diff);
            continue;
        }

        // ── Strategy 3: per-file blob (legacy fallback) ──────────────
        let blob_path = sources.blobs_path.join(&file_info.after_hash);
        let patched_content = match tokio::fs::read(&blob_path).await {
            Ok(content) => content,
            Err(e) => {
                result.error = Some(format!(
                    "Failed to read blob {}: {}",
                    file_info.after_hash, e
                ));
                return result;
            }
        };

        if let Err(e) =
            apply_file_patch(pkg_path, file_name, &patched_content, &file_info.after_hash).await
        {
            result.error = Some(e.to_string());
            return result;
        }

        result.files_patched.push(file_name.clone());
        result
            .applied_via
            .insert(file_name.clone(), AppliedVia::Blob);
    }

    // Ecosystem sidecar fixup. Best-effort: a failing sidecar does
    // NOT undo the patch (the bytes were committed atomically via
    // stage+rename; nothing to roll back). The error path is
    // converted at this boundary into a `SidecarRecord` carrying
    // `SidecarAdvisoryCode::SidecarFixupFailed` so downstream
    // consumers see a uniform shape regardless of whether the
    // fixup succeeded, was advisory-only, or raised an error.
    if !result.files_patched.is_empty() {
        use crate::patch::sidecars::{
            dispatch_fixup, SidecarAdvisory, SidecarAdvisoryCode, SidecarRecord, SidecarSeverity,
        };
        match dispatch_fixup(package_key, pkg_path, &result.files_patched, files).await {
            Ok(Some(record)) => result.sidecar = Some(record),
            Ok(None) => {}
            Err(e) => {
                let ecosystem = crate::crawlers::Ecosystem::from_purl(package_key)
                    .map(|eco| eco.cli_name().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                result.sidecar = Some(SidecarRecord {
                    purl: package_key.to_string(),
                    ecosystem,
                    files: Vec::new(),
                    advisory: Some(SidecarAdvisory {
                        code: SidecarAdvisoryCode::SidecarFixupFailed,
                        severity: SidecarSeverity::Error,
                        message: format!("sidecar fixup failed (patch still applied): {}", e),
                    }),
                });
            }
        }
    }

    result.success = true;
    result
}

/// Try to write the patched bytes from `package_entries[normalized_path]`
/// to disk, verifying the post-write hash. Returns `true` on success.
async fn try_apply_from_archive(
    package_entries: Option<&HashMap<String, Vec<u8>>>,
    normalized_path: &str,
    pkg_path: &Path,
    file_name: &str,
    file_info: &PatchFileInfo,
) -> bool {
    let entries = match package_entries {
        Some(e) => e,
        None => return false,
    };
    let bytes = match entries.get(normalized_path) {
        Some(b) => b,
        None => return false,
    };
    if compute_git_sha256_from_bytes(bytes) != file_info.after_hash {
        return false;
    }
    apply_file_patch(pkg_path, file_name, bytes, &file_info.after_hash)
        .await
        .is_ok()
}

/// Try to apply the bsdiff delta from `diff_entries[normalized_path]` to
/// the on-disk file at `pkg_path/normalized_path`. Bails out (returning
/// `false`) for any of:
///   * no diff entry,
///   * `current_hash` is missing or doesn't match `file_info.before_hash`
///     (this is the strong gate — even `--force` promoting a
///     HashMismatch to Ready will still bail here, because the on-disk
///     hash captured by `verify_file_patch` was the real, mismatched
///     value),
///   * `file_info.before_hash` is empty (new files),
///   * read/diff/verify/write failure.
async fn try_apply_from_diff(
    diff_entries: Option<&HashMap<String, Vec<u8>>>,
    normalized_path: &str,
    pkg_path: &Path,
    file_name: &str,
    file_info: &PatchFileInfo,
    current_hash: Option<&str>,
) -> bool {
    let entries = match diff_entries {
        Some(e) => e,
        None => return false,
    };
    let delta = match entries.get(normalized_path) {
        Some(d) => d,
        None => return false,
    };
    if file_info.before_hash.is_empty() {
        // New files have no before content to diff against.
        return false;
    }
    // Strong invariant: only run the diff when on-disk bytes hash to
    // exactly the `before_hash` the delta was authored against. This
    // closes the force-mode loophole — `--force` flips VerifyStatus to
    // Ready, but `current_hash` retains the original on-disk hash, so
    // the comparison below still rejects.
    match current_hash {
        Some(h) if h == file_info.before_hash => {}
        _ => return false,
    }

    let on_disk_path = pkg_path.join(normalized_path);
    let before_bytes = match tokio::fs::read(&on_disk_path).await {
        Ok(b) => b,
        Err(_) => return false,
    };
    let patched = match apply_diff(&before_bytes, delta) {
        Ok(p) => p,
        Err(_) => return false,
    };
    if compute_git_sha256_from_bytes(&patched) != file_info.after_hash {
        return false;
    }
    apply_file_patch(pkg_path, file_name, &patched, &file_info.after_hash)
        .await
        .is_ok()
}

/// Open `<dir>/<uuid>.tar.gz` (if it exists) and return its entries
/// filtered to the patched files in `files`. Errors and missing files
/// both yield `None` so the caller silently falls through to the next
/// strategy.
async fn load_archive_if_present(
    dir: &Path,
    uuid: &str,
    files: &HashMap<String, PatchFileInfo>,
) -> Option<HashMap<String, Vec<u8>>> {
    let archive_path = dir.join(format!("{uuid}.tar.gz"));
    if tokio::fs::metadata(&archive_path).await.is_err() {
        return None;
    }
    // `read_archive_filtered` is synchronous (tar + flate2 are sync). Run
    // it on the blocking pool so we don't stall the executor for large
    // archives.
    let archive_path_owned = archive_path.clone();
    let files_owned = files.clone();
    tokio::task::spawn_blocking(move || read_archive_filtered(&archive_path_owned, &files_owned))
        .await
        .ok()
        .and_then(|r| r.ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;

    #[test]
    fn test_normalize_file_path_with_prefix() {
        assert_eq!(normalize_file_path("package/lib/server.js"), "lib/server.js");
    }

    #[test]
    fn test_normalize_file_path_without_prefix() {
        assert_eq!(normalize_file_path("lib/server.js"), "lib/server.js");
    }

    #[test]
    fn test_normalize_file_path_just_prefix() {
        assert_eq!(normalize_file_path("package/"), "");
    }

    #[test]
    fn test_normalize_file_path_package_not_prefix() {
        // "package" without trailing "/" should NOT be stripped
        assert_eq!(normalize_file_path("packagefoo/bar.js"), "packagefoo/bar.js");
    }

    #[tokio::test]
    async fn test_verify_file_patch_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let file_info = PatchFileInfo {
            before_hash: "aaa".to_string(),
            after_hash: "bbb".to_string(),
        };

        let result = verify_file_patch(dir.path(), "nonexistent.js", &file_info).await;
        assert_eq!(result.status, VerifyStatus::NotFound);
    }

    #[tokio::test]
    async fn test_verify_file_patch_ready() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"original content";
        let before_hash = compute_git_sha256_from_bytes(content);
        let after_hash = "bbbbbbbb".to_string();

        tokio::fs::write(dir.path().join("index.js"), content)
            .await
            .unwrap();

        let file_info = PatchFileInfo {
            before_hash: before_hash.clone(),
            after_hash,
        };

        let result = verify_file_patch(dir.path(), "index.js", &file_info).await;
        assert_eq!(result.status, VerifyStatus::Ready);
        assert_eq!(result.current_hash.unwrap(), before_hash);
    }

    #[tokio::test]
    async fn test_verify_file_patch_already_patched() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"patched content";
        let after_hash = compute_git_sha256_from_bytes(content);

        tokio::fs::write(dir.path().join("index.js"), content)
            .await
            .unwrap();

        let file_info = PatchFileInfo {
            before_hash: "aaaa".to_string(),
            after_hash: after_hash.clone(),
        };

        let result = verify_file_patch(dir.path(), "index.js", &file_info).await;
        assert_eq!(result.status, VerifyStatus::AlreadyPatched);
    }

    #[tokio::test]
    async fn test_verify_file_patch_hash_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("index.js"), b"something else")
            .await
            .unwrap();

        let file_info = PatchFileInfo {
            before_hash: "aaaa".to_string(),
            after_hash: "bbbb".to_string(),
        };

        let result = verify_file_patch(dir.path(), "index.js", &file_info).await;
        assert_eq!(result.status, VerifyStatus::HashMismatch);
    }

    #[tokio::test]
    async fn test_verify_with_package_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"original content";
        let before_hash = compute_git_sha256_from_bytes(content);

        // File is at lib/server.js but patch refers to package/lib/server.js
        tokio::fs::create_dir_all(dir.path().join("lib")).await.unwrap();
        tokio::fs::write(dir.path().join("lib/server.js"), content)
            .await
            .unwrap();

        let file_info = PatchFileInfo {
            before_hash: before_hash.clone(),
            after_hash: "bbbb".to_string(),
        };

        let result = verify_file_patch(dir.path(), "package/lib/server.js", &file_info).await;
        assert_eq!(result.status, VerifyStatus::Ready);
    }

    #[tokio::test]
    async fn test_apply_file_patch_success() {
        let dir = tempfile::tempdir().unwrap();
        let original = b"original";
        let patched = b"patched content";
        let patched_hash = compute_git_sha256_from_bytes(patched);

        tokio::fs::write(dir.path().join("index.js"), original)
            .await
            .unwrap();

        apply_file_patch(dir.path(), "index.js", patched, &patched_hash)
            .await
            .unwrap();

        let written = tokio::fs::read(dir.path().join("index.js")).await.unwrap();
        assert_eq!(written, patched);
    }

    #[tokio::test]
    async fn test_apply_file_patch_hash_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("index.js"), b"original")
            .await
            .unwrap();

        let result =
            apply_file_patch(dir.path(), "index.js", b"patched content", "wrong_hash").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Hash verification failed"));
    }

    /// Atomic-write contract: if the apply errors mid-flight (here:
    /// in-memory hash mismatch, which fires BEFORE any disk write),
    /// the target file is byte-identical to its pre-call state AND
    /// no `.socket-stage-*` file is left in the parent directory.
    #[tokio::test]
    async fn test_apply_file_patch_hash_mismatch_leaves_original_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.js");
        tokio::fs::write(&path, b"original").await.unwrap();

        let result = apply_file_patch(dir.path(), "index.js", b"patched", "deadbeef").await;
        assert!(result.is_err());

        // Original content untouched.
        assert_eq!(tokio::fs::read(&path).await.unwrap(), b"original");

        // No stage litter (stage files are named `.socket-stage-*`).
        let mut entries = tokio::fs::read_dir(dir.path()).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            let name = entry.file_name().to_string_lossy().to_string();
            assert!(
                !name.starts_with(".socket-stage-"),
                "stage file leaked into parent dir: {name}"
            );
        }
    }

    /// Apply against a hardlink (the pnpm content-store case) must
    /// only mutate this project's view. The sibling link — which
    /// represents another project's `node_modules/<pkg>` or the
    /// global store entry — must keep the original bytes.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_apply_file_patch_does_not_propagate_to_hardlinked_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project-b").join("foo.js");
        let store = dir.path().join("store-a.js");
        tokio::fs::create_dir_all(project.parent().unwrap())
            .await
            .unwrap();

        // Pre-existing store entry; both project and store point at
        // the same inode (this is what pnpm produces with
        // `package-import-method=hardlink`).
        tokio::fs::write(&store, b"original").await.unwrap();
        tokio::fs::hard_link(&store, &project).await.unwrap();

        let patched = b"patched";
        let patched_hash = compute_git_sha256_from_bytes(patched);
        apply_file_patch(project.parent().unwrap(), "foo.js", patched, &patched_hash)
            .await
            .unwrap();

        // Project sees the patched bytes.
        assert_eq!(tokio::fs::read(&project).await.unwrap(), b"patched");
        // Store entry is untouched — the headline pnpm invariant.
        assert_eq!(tokio::fs::read(&store).await.unwrap(), b"original");
    }

    /// Existing read-only file: temporarily made writable for the
    /// overwrite, restored to read-only afterward, content updated.
    /// Mirrors the Go module cache scenario.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_apply_file_patch_preserves_readonly_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.js");
        let original = b"original";
        let patched = b"patched content";
        let patched_hash = compute_git_sha256_from_bytes(patched);

        tokio::fs::write(&path, original).await.unwrap();
        // 0o444 = r--r--r--. Owner has no write bit.
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444))
            .await
            .unwrap();

        apply_file_patch(dir.path(), "index.js", patched, &patched_hash)
            .await
            .unwrap();

        // Content updated.
        let written = tokio::fs::read(&path).await.unwrap();
        assert_eq!(written, patched);
        // Mode preserved bit-for-bit.
        let mode_after = tokio::fs::metadata(&path).await.unwrap().permissions().mode()
            & 0o7777;
        assert_eq!(
            mode_after, 0o444,
            "mode must be restored to the pre-patch value after the write"
        );
    }

    /// Non-default mode (e.g. 0o755 for an executable script) survives
    /// the patch round-trip unchanged.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_apply_file_patch_preserves_executable_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bin.sh");
        let original = b"#!/bin/sh\necho old\n";
        let patched = b"#!/bin/sh\necho new\n";
        let patched_hash = compute_git_sha256_from_bytes(patched);

        tokio::fs::write(&path, original).await.unwrap();
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .await
            .unwrap();

        apply_file_patch(dir.path(), "bin.sh", patched, &patched_hash)
            .await
            .unwrap();

        let mode_after = tokio::fs::metadata(&path).await.unwrap().permissions().mode()
            & 0o7777;
        assert_eq!(mode_after, 0o755);
    }

    /// New file created by the patch: default mode is read-only (0o444)
    /// and the parent directory's uid/gid get inherited (the uid/gid
    /// check is a smoke test — running as a regular user the new file
    /// would already inherit the user's uid, but the test still locks
    /// in that the new file's uid matches the parent's, which is what
    /// the chown call enforces).
    #[cfg(unix)]
    #[tokio::test]
    async fn test_apply_file_patch_new_file_is_readonly_and_inherits_dir_owner() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let nested = "new-dir/new.js";
        let patched = b"brand new file content\n";
        let patched_hash = compute_git_sha256_from_bytes(patched);

        // File does not yet exist — this is the new-file path.
        apply_file_patch(dir.path(), nested, patched, &patched_hash)
            .await
            .unwrap();

        let path = dir.path().join(nested);
        // Default new-file mode is 0o444.
        let mode = tokio::fs::metadata(&path).await.unwrap().permissions().mode()
            & 0o7777;
        assert_eq!(mode, 0o444, "new files default to read-only");

        // uid/gid inherited from the parent directory.
        let parent_meta = tokio::fs::metadata(path.parent().unwrap()).await.unwrap();
        let file_meta = tokio::fs::metadata(&path).await.unwrap();
        assert_eq!(file_meta.uid(), parent_meta.uid());
        assert_eq!(file_meta.gid(), parent_meta.gid());
    }

    /// Existing patched file's uid/gid survive the round-trip. We can
    /// only verify "uid stays the same" without root, but that's
    /// enough to catch a regression that accidentally clobbered ownership.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_apply_file_patch_preserves_uid_gid() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.js");
        let original = b"orig";
        let patched = b"new";
        let patched_hash = compute_git_sha256_from_bytes(patched);

        tokio::fs::write(&path, original).await.unwrap();
        let pre = tokio::fs::metadata(&path).await.unwrap();

        apply_file_patch(dir.path(), "index.js", patched, &patched_hash)
            .await
            .unwrap();

        let post = tokio::fs::metadata(&path).await.unwrap();
        assert_eq!(pre.uid(), post.uid());
        assert_eq!(pre.gid(), post.gid());
    }

    #[tokio::test]
    async fn test_apply_package_patch_success() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let original = b"original content";
        let patched = b"patched content";
        let before_hash = compute_git_sha256_from_bytes(original);
        let after_hash = compute_git_sha256_from_bytes(patched);

        // Write original file
        tokio::fs::write(pkg_dir.path().join("index.js"), original)
            .await
            .unwrap();

        // Write blob
        tokio::fs::write(blobs_dir.path().join(&after_hash), patched)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash,
                after_hash: after_hash.clone(),
            },
        );

        let result =
            apply_package_patch("pkg:npm/test@1.0.0", pkg_dir.path(), &files, &PatchSources::blobs_only(blobs_dir.path()), None, false, false)
                .await;

        assert!(result.success);
        assert_eq!(result.files_patched.len(), 1);
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn test_apply_package_patch_dry_run() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let original = b"original content";
        let before_hash = compute_git_sha256_from_bytes(original);

        tokio::fs::write(pkg_dir.path().join("index.js"), original)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash,
                after_hash: "bbbb".to_string(),
            },
        );

        let result =
            apply_package_patch("pkg:npm/test@1.0.0", pkg_dir.path(), &files, &PatchSources::blobs_only(blobs_dir.path()), None, true, false)
                .await;

        assert!(result.success);
        assert_eq!(result.files_patched.len(), 0); // dry run: nothing actually patched

        // File should still have original content
        let content = tokio::fs::read(pkg_dir.path().join("index.js")).await.unwrap();
        assert_eq!(content, original);
    }

    #[tokio::test]
    async fn test_apply_package_patch_all_already_patched() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let patched = b"patched content";
        let after_hash = compute_git_sha256_from_bytes(patched);

        tokio::fs::write(pkg_dir.path().join("index.js"), patched)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash: "aaaa".to_string(),
                after_hash,
            },
        );

        let result =
            apply_package_patch("pkg:npm/test@1.0.0", pkg_dir.path(), &files, &PatchSources::blobs_only(blobs_dir.path()), None, false, false)
                .await;

        assert!(result.success);
        assert_eq!(result.files_patched.len(), 0);
    }

    #[tokio::test]
    async fn test_apply_package_patch_hash_mismatch_blocks() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        tokio::fs::write(pkg_dir.path().join("index.js"), b"something unexpected")
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash: "aaaa".to_string(),
                after_hash: "bbbb".to_string(),
            },
        );

        let result =
            apply_package_patch("pkg:npm/test@1.0.0", pkg_dir.path(), &files, &PatchSources::blobs_only(blobs_dir.path()), None, false, false)
                .await;

        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn test_apply_package_patch_force_hash_mismatch() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let patched = b"patched content";
        let after_hash = compute_git_sha256_from_bytes(patched);

        // Write a file whose hash does NOT match before_hash
        tokio::fs::write(pkg_dir.path().join("index.js"), b"something unexpected")
            .await
            .unwrap();

        // Write blob
        tokio::fs::write(blobs_dir.path().join(&after_hash), patched)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash: "aaaa".to_string(),
                after_hash: after_hash.clone(),
            },
        );

        // Without force: should fail
        let result =
            apply_package_patch("pkg:npm/test@1.0.0", pkg_dir.path(), &files, &PatchSources::blobs_only(blobs_dir.path()), None, false, false)
                .await;
        assert!(!result.success);

        // Reset the file
        tokio::fs::write(pkg_dir.path().join("index.js"), b"something unexpected")
            .await
            .unwrap();

        // With force: should succeed
        let result =
            apply_package_patch("pkg:npm/test@1.0.0", pkg_dir.path(), &files, &PatchSources::blobs_only(blobs_dir.path()), None, false, true)
                .await;
        assert!(result.success);
        assert_eq!(result.files_patched.len(), 1);

        let written = tokio::fs::read(pkg_dir.path().join("index.js")).await.unwrap();
        assert_eq!(written, patched);
    }

    #[tokio::test]
    async fn test_apply_package_patch_force_not_found_skips() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let mut files = HashMap::new();
        files.insert(
            "missing.js".to_string(),
            PatchFileInfo {
                before_hash: "aaaa".to_string(),
                after_hash: "bbbb".to_string(),
            },
        );

        // Without force: should fail (NotFound for non-new file)
        let result =
            apply_package_patch("pkg:npm/test@1.0.0", pkg_dir.path(), &files, &PatchSources::blobs_only(blobs_dir.path()), None, false, false)
                .await;
        assert!(!result.success);

        // With force: should succeed by skipping the missing file
        let result =
            apply_package_patch("pkg:npm/test@1.0.0", pkg_dir.path(), &files, &PatchSources::blobs_only(blobs_dir.path()), None, false, true)
                .await;
        assert!(result.success);
        assert_eq!(result.files_patched.len(), 0);
    }

    // ── Fallback-chain tests ─────────────────────────────────────────
    //
    // Tests below exercise the new strategies introduced in 2.2:
    // package archive (.socket/packages/<uuid>.tar.gz) and per-file diff
    // archive (.socket/diffs/<uuid>.tar.gz), plus the priority order
    // package → diff → blob.

    use flate2::write::GzEncoder;
    use flate2::Compression as GzCompression;
    use qbsdiff::Bsdiff;

    const TEST_UUID: &str = "11111111-1111-4111-8111-111111111111";

    /// Write a tar.gz archive at `<dir>/<uuid>.tar.gz` containing the
    /// given (entry name → bytes) pairs.
    fn write_uuid_archive(dir: &Path, uuid: &str, entries: &[(&str, &[u8])]) {
        let archive_path = dir.join(format!("{uuid}.tar.gz"));
        let file = std::fs::File::create(&archive_path).unwrap();
        let gz = GzEncoder::new(file, GzCompression::default());
        let mut builder = tar::Builder::new(gz);
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *data).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
    }

    fn make_delta(before: &[u8], after: &[u8]) -> Vec<u8> {
        let mut delta = Vec::new();
        Bsdiff::new(before, after)
            .compare(std::io::Cursor::new(&mut delta))
            .unwrap();
        delta
    }

    /// Returns a fully-populated three-source fixture: original file on
    /// disk, all of (package, diff, blob) available with valid patched
    /// content. Caller can then delete sources to test fallback.
    async fn make_fixture() -> (
        tempfile::TempDir, // root holding pkg/, blobs/, packages/, diffs/
        std::path::PathBuf, // pkg dir
        std::path::PathBuf, // blobs dir
        std::path::PathBuf, // packages dir
        std::path::PathBuf, // diffs dir
        HashMap<String, PatchFileInfo>,
        Vec<u8>, // original bytes
        Vec<u8>, // patched bytes
    ) {
        let root = tempfile::tempdir().unwrap();
        let pkg_dir = root.path().join("pkg");
        let blobs_dir = root.path().join("blobs");
        let packages_dir = root.path().join("packages");
        let diffs_dir = root.path().join("diffs");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();
        tokio::fs::create_dir_all(&packages_dir).await.unwrap();
        tokio::fs::create_dir_all(&diffs_dir).await.unwrap();

        let original: Vec<u8> = b"the original content of the file".to_vec();
        let patched: Vec<u8> = b"the PATCHED content of the file!".to_vec();
        let before_hash = compute_git_sha256_from_bytes(&original);
        let after_hash = compute_git_sha256_from_bytes(&patched);

        // On-disk file at pkg/index.js
        tokio::fs::write(pkg_dir.join("index.js"), &original)
            .await
            .unwrap();

        // Per-file blob at blobs/<after_hash>
        tokio::fs::write(blobs_dir.join(&after_hash), &patched)
            .await
            .unwrap();

        // Package archive containing the patched bytes
        write_uuid_archive(&packages_dir, TEST_UUID, &[("index.js", &patched)]);

        // Diff archive containing bsdiff(original -> patched)
        let delta = make_delta(&original, &patched);
        write_uuid_archive(&diffs_dir, TEST_UUID, &[("index.js", &delta)]);

        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash,
                after_hash,
            },
        );

        (root, pkg_dir, blobs_dir, packages_dir, diffs_dir, files, original, patched)
    }

    #[tokio::test]
    async fn test_apply_via_package_when_archive_present() {
        let (_root, pkg_dir, blobs_dir, packages_dir, diffs_dir, files, _orig, patched) =
            make_fixture().await;

        let sources = PatchSources {
            blobs_path: &blobs_dir,
            packages_path: Some(&packages_dir),
            diffs_path: Some(&diffs_dir),
        };
        let result = apply_package_patch(
            "pkg:npm/x@1.0.0",
            &pkg_dir,
            &files,
            &sources,
            Some(TEST_UUID),
            false,
            false,
        )
        .await;

        assert!(result.success, "expected success: {:?}", result.error);
        assert_eq!(result.files_patched, vec!["index.js".to_string()]);
        assert_eq!(
            result.applied_via.get("index.js"),
            Some(&AppliedVia::Package)
        );
        let written = tokio::fs::read(pkg_dir.join("index.js")).await.unwrap();
        assert_eq!(written, patched);
    }

    #[tokio::test]
    async fn test_apply_falls_back_to_diff_when_no_package() {
        let (_root, pkg_dir, blobs_dir, packages_dir, diffs_dir, files, _orig, patched) =
            make_fixture().await;
        // Delete the package archive.
        tokio::fs::remove_file(packages_dir.join(format!("{TEST_UUID}.tar.gz")))
            .await
            .unwrap();

        let sources = PatchSources {
            blobs_path: &blobs_dir,
            packages_path: Some(&packages_dir),
            diffs_path: Some(&diffs_dir),
        };
        let result = apply_package_patch(
            "pkg:npm/x@1.0.0",
            &pkg_dir,
            &files,
            &sources,
            Some(TEST_UUID),
            false,
            false,
        )
        .await;

        assert!(result.success, "expected success: {:?}", result.error);
        assert_eq!(result.applied_via.get("index.js"), Some(&AppliedVia::Diff));
        let written = tokio::fs::read(pkg_dir.join("index.js")).await.unwrap();
        assert_eq!(written, patched);
    }

    #[tokio::test]
    async fn test_apply_falls_back_to_blob_when_no_archives() {
        let (_root, pkg_dir, blobs_dir, packages_dir, diffs_dir, files, _orig, patched) =
            make_fixture().await;
        // Delete both archives.
        tokio::fs::remove_file(packages_dir.join(format!("{TEST_UUID}.tar.gz")))
            .await
            .unwrap();
        tokio::fs::remove_file(diffs_dir.join(format!("{TEST_UUID}.tar.gz")))
            .await
            .unwrap();

        let sources = PatchSources {
            blobs_path: &blobs_dir,
            packages_path: Some(&packages_dir),
            diffs_path: Some(&diffs_dir),
        };
        let result = apply_package_patch(
            "pkg:npm/x@1.0.0",
            &pkg_dir,
            &files,
            &sources,
            Some(TEST_UUID),
            false,
            false,
        )
        .await;

        assert!(result.success);
        assert_eq!(result.applied_via.get("index.js"), Some(&AppliedVia::Blob));
        let written = tokio::fs::read(pkg_dir.join("index.js")).await.unwrap();
        assert_eq!(written, patched);
    }

    #[tokio::test]
    async fn test_apply_uuid_none_disables_alt_sources() {
        // Even if archives exist, passing `uuid = None` must restrict the
        // pipeline to the blob path — preserving pre-2.2 behavior.
        let (_root, pkg_dir, blobs_dir, packages_dir, diffs_dir, files, _orig, _patched) =
            make_fixture().await;

        let sources = PatchSources {
            blobs_path: &blobs_dir,
            packages_path: Some(&packages_dir),
            diffs_path: Some(&diffs_dir),
        };
        let result = apply_package_patch(
            "pkg:npm/x@1.0.0",
            &pkg_dir,
            &files,
            &sources,
            None,
            false,
            false,
        )
        .await;

        assert!(result.success);
        assert_eq!(result.applied_via.get("index.js"), Some(&AppliedVia::Blob));
    }

    #[tokio::test]
    async fn test_apply_via_diff_falls_through_when_before_hash_mismatch() {
        // Corrupt the on-disk file so its hash no longer matches
        // before_hash. Diff strategy must NOT run (its output would never
        // match after_hash), so we fall through to the blob.
        let (_root, pkg_dir, blobs_dir, packages_dir, diffs_dir, files, _orig, patched) =
            make_fixture().await;
        tokio::fs::remove_file(packages_dir.join(format!("{TEST_UUID}.tar.gz")))
            .await
            .unwrap();
        // Overwrite on-disk content with garbage; use --force so verify
        // promotes the HashMismatch to Ready and the pipeline still tries
        // to apply.
        tokio::fs::write(pkg_dir.join("index.js"), b"garbage")
            .await
            .unwrap();

        let sources = PatchSources {
            blobs_path: &blobs_dir,
            packages_path: Some(&packages_dir),
            diffs_path: Some(&diffs_dir),
        };
        let result = apply_package_patch(
            "pkg:npm/x@1.0.0",
            &pkg_dir,
            &files,
            &sources,
            Some(TEST_UUID),
            false,
            true, // --force
        )
        .await;

        assert!(result.success);
        // Diff would produce wrong output → strategy skipped → blob writes.
        assert_eq!(result.applied_via.get("index.js"), Some(&AppliedVia::Blob));
        let written = tokio::fs::read(pkg_dir.join("index.js")).await.unwrap();
        assert_eq!(written, patched);
    }

    #[tokio::test]
    async fn test_apply_via_package_skips_when_hash_mismatches() {
        // Package archive contains the WRONG bytes (would not hash to
        // after_hash). The package strategy must refuse the entry and
        // fall back to diff or blob.
        let (_root, pkg_dir, blobs_dir, packages_dir, diffs_dir, files, _orig, patched) =
            make_fixture().await;
        // Replace the package archive with one whose entry is corrupt.
        tokio::fs::remove_file(packages_dir.join(format!("{TEST_UUID}.tar.gz")))
            .await
            .unwrap();
        write_uuid_archive(
            &packages_dir,
            TEST_UUID,
            &[("index.js", b"corrupt package payload")],
        );

        let sources = PatchSources {
            blobs_path: &blobs_dir,
            packages_path: Some(&packages_dir),
            diffs_path: Some(&diffs_dir),
        };
        let result = apply_package_patch(
            "pkg:npm/x@1.0.0",
            &pkg_dir,
            &files,
            &sources,
            Some(TEST_UUID),
            false,
            false,
        )
        .await;

        assert!(result.success);
        // Package refused → diff succeeded next.
        assert_eq!(result.applied_via.get("index.js"), Some(&AppliedVia::Diff));
        let written = tokio::fs::read(pkg_dir.join("index.js")).await.unwrap();
        assert_eq!(written, patched);
    }

    #[tokio::test]
    async fn test_apply_dry_run_does_not_touch_alternative_sources() {
        // Even with package/diff archives present, dry-run must not modify
        // files on disk.
        let (_root, pkg_dir, blobs_dir, packages_dir, diffs_dir, files, original, _patched) =
            make_fixture().await;

        let sources = PatchSources {
            blobs_path: &blobs_dir,
            packages_path: Some(&packages_dir),
            diffs_path: Some(&diffs_dir),
        };
        let result = apply_package_patch(
            "pkg:npm/x@1.0.0",
            &pkg_dir,
            &files,
            &sources,
            Some(TEST_UUID),
            true, // dry-run
            false,
        )
        .await;

        assert!(result.success);
        assert!(result.files_patched.is_empty());
        let on_disk = tokio::fs::read(pkg_dir.join("index.js")).await.unwrap();
        assert_eq!(on_disk, original);
    }

    #[test]
    fn test_applied_via_as_tag() {
        assert_eq!(AppliedVia::Package.as_tag(), "package");
        assert_eq!(AppliedVia::Diff.as_tag(), "diff");
        assert_eq!(AppliedVia::Blob.as_tag(), "blob");
    }

    #[test]
    fn test_patch_sources_blobs_only_disables_other_strategies() {
        let dir = tempfile::tempdir().unwrap();
        let sources = PatchSources::blobs_only(dir.path());
        assert!(sources.packages_path.is_none());
        assert!(sources.diffs_path.is_none());
    }
}
