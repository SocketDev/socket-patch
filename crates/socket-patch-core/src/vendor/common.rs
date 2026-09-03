//! Leaf helpers shared by the vendor backends (and [`crate::patch::redirect::golang_local`]).
//!
//! Each backend used to carry a private, byte-identical copy of these; they
//! are hoisted here so the shapes stay in lockstep.

use std::collections::HashMap;
use std::path::Path;

use serde_json::Value;
use toml_edit::{DocumentMut, Item, Table};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::manifest::schema::PatchFileInfo;
use crate::patch::apply::{
    is_safe_relative_subpath, normalize_file_path, ApplyResult, VerifyResult, VerifyStatus,
};
use crate::patch::file_hash::compute_file_git_sha256;
use crate::utils::fs::{atomic_write_bytes_preserving_mode, open_regular_file};

use super::state::{VendorEntry, WiringAction, WiringRecord};
use super::{RevertOutcome, VendorOutcome, VendorServiceConfig, VendorWarning};

/// A [`VerifyResult`] reporting `file` as already patched.
fn already_patched_verify(file: &str) -> VerifyResult {
    VerifyResult {
        file: file.to_string(),
        status: VerifyStatus::AlreadyPatched,
        message: None,
        current_hash: None,
        expected_hash: None,
        target_hash: None,
    }
}

/// Shared helper the vendor backends (and `go_redirect`) delegate to: a
/// success [`ApplyResult`] in which every patched file reads as
/// `AlreadyPatched`, synthesized without running the apply pipeline (the
/// in-sync hot paths, and the service-download paths where trust is the
/// verified artifact integrity rather than a local apply).
pub(crate) fn already_patched_result(
    package_key: &str,
    path: &Path,
    files: &HashMap<String, PatchFileInfo>,
) -> ApplyResult {
    let files_verified = files.keys().map(|f| already_patched_verify(f)).collect();
    synthesized_result(package_key, path, files_verified, true, None)
}

/// Shared helper the vendor backends (and `go_redirect`) delegate to: an
/// [`ApplyResult`] synthesized without running the apply pipeline.
pub(crate) fn synthesized_result(
    package_key: &str,
    path: &Path,
    files_verified: Vec<VerifyResult>,
    success: bool,
    error: Option<String>,
) -> ApplyResult {
    ApplyResult {
        package_key: package_key.to_string(),
        package_path: path.display().to_string(),
        success,
        files_verified,
        files_patched: Vec::new(),
        applied_via: HashMap::new(),
        error,
        sidecar: None,
    }
}

/// Shared helper the vendor backends delegate to: a [`VendorOutcome::Refused`].
pub(crate) fn refused(code: &'static str, detail: impl Into<String>) -> VendorOutcome {
    VendorOutcome::Refused {
        code,
        detail: detail.into(),
    }
}

/// Shared helper the vendor backends delegate to: a [`VendorOutcome::Done`].
pub(crate) fn done(
    result: ApplyResult,
    entry: Option<VendorEntry>,
    warnings: Vec<VendorWarning>,
) -> VendorOutcome {
    VendorOutcome::Done {
        result,
        entry,
        warnings,
    }
}

/// Shared helper the vendor backends delegate to: the fail-closed refusal
/// for `--vendor-source=service` combined with `--offline`, checked before
/// any service consultation.
pub(crate) fn service_offline_conflict(
    service: Option<&VendorServiceConfig>,
) -> Option<VendorOutcome> {
    let cfg = service?;
    if cfg.source.requires_service() && cfg.offline {
        return Some(refused(
            "vendor_service_offline_conflict",
            "--vendor-source=service needs the network but --offline is set",
        ));
    }
    None
}

/// Shared helper the vendor backends delegate to: an un-successful
/// [`ApplyResult`] carrying `error`, synthesized without running the apply
/// pipeline.
pub(crate) fn failed_result(package_key: &str, path: &Path, error: String) -> ApplyResult {
    synthesized_result(package_key, path, Vec::new(), false, Some(error))
}

/// The file's indent unit: the leading whitespace of the first indented
/// line (npm emits 2 spaces; respect whatever formatter the project uses
/// so untouched lines stay byte-identical in diffs). Defaults to 2 spaces.
pub(crate) fn detect_indent(text: &str) -> String {
    for line in text.lines() {
        let trimmed = line.trim_start_matches([' ', '\t']);
        if !trimmed.is_empty() && trimmed.len() < line.len() {
            return line[..line.len() - trimmed.len()].to_string();
        }
    }
    "  ".to_string()
}

/// The file's dominant line terminator (new lines we write use it; bytes
/// outside edited spans keep whatever they had).
pub(crate) fn detect_eol(text: &str) -> &'static str {
    if text.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}

/// Pretty-print JSON with `indent` + a trailing newline (the shape npm and
/// composer themselves emit), so untouched keys stay byte-identical and a
/// later `npm install` / `composer update` produces no format-only churn.
pub(crate) fn serialize_json(value: &Value, indent: &str) -> std::io::Result<Vec<u8>> {
    use serde::Serialize;
    let mut out = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(indent.as_bytes());
    let mut ser = serde_json::Serializer::with_formatter(&mut out, formatter);
    value.serialize(&mut ser).map_err(std::io::Error::other)?;
    out.push(b'\n');
    Ok(out)
}

/// Serialize `(name, bytes, unix mode)` entries — in the given order — into
/// a deterministic zip: a fixed DOS timestamp (1980-01-01 00:00:00) and a
/// fixed deflate level, so rebuilding the same content always yields
/// identical bytes (churn-free commits, stable checksums).
pub(crate) fn write_zip_entries(entries: &[(String, Vec<u8>, u32)]) -> Result<Vec<u8>, String> {
    use std::io::Write as _;

    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, bytes, mode) in entries {
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .compression_level(Some(6))
            .last_modified_time(zip::DateTime::default())
            .unix_permissions(*mode);
        writer
            .start_file(name, options)
            .map_err(|e| format!("zip start {name}: {e}"))?;
        writer
            .write_all(bytes)
            .map_err(|e| format!("zip write {name}: {e}"))?;
    }
    let cursor = writer.finish().map_err(|e| format!("zip finish: {e}"))?;
    Ok(cursor.into_inner())
}

/// True when `metadata`'s unix mode carries any exec bit (always false on
/// non-unix, where archive modes are normalized at pack time instead).
pub(crate) fn is_executable(metadata: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

/// Re-zip a patched stage into a deterministic archive (see
/// [`write_zip_entries`]) with entries sorted lexicographically. Both
/// consumers (`.jar` / `.nupkg`) are plain zips whose resolvers read the
/// central directory, so entry order is free to be lexicographic.
/// `skip_entry` drops one archive-relative name (NuGet's `.signature.p7s` —
/// the content changed, so the rebuilt package must read as unsigned).
pub(crate) fn rebuild_zip(stage: &Path, skip_entry: Option<&str>) -> Result<Vec<u8>, String> {
    let mut entries: Vec<(String, Vec<u8>, u32)> = Vec::new();
    for entry in walkdir::WalkDir::new(stage).follow_links(false) {
        let entry = entry.map_err(|e| format!("walk {}: {e}", stage.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(stage)
            .map_err(|e| format!("strip prefix: {e}"))?;
        let name = rel.to_string_lossy().replace('\\', "/");
        if skip_entry == Some(name.as_str()) {
            continue;
        }
        let bytes = std::fs::read(entry.path()).map_err(|e| format!("read {name}: {e}"))?;
        entries.push((name, bytes, 0o644));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    write_zip_entries(&entries)
}

/// True when the committed archive (a plain zip: `.jar` / `.nupkg`) exists and
/// every patched file in it already hashes to its `afterHash` (the zip twin of
/// [`copy_matches_after_hashes`], reading the archive's entries).
pub(crate) async fn zip_matches_after_hashes(
    archive_path: &Path,
    files: &HashMap<String, PatchFileInfo>,
) -> bool {
    use std::io::Read as _;

    use tokio::io::AsyncReadExt as _;

    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    // Guarded read (`open_regular_file`: O_NONBLOCK + regular-file check): a
    // FIFO planted at the archive path must read as out-of-sync, not wedge
    // the probe forever in an `open(2)` waiting for a writer.
    let Ok((mut file, metadata)) = open_regular_file(archive_path).await else {
        return false;
    };
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    if file.read_to_end(&mut bytes).await.is_err() {
        return false;
    }
    let Ok(mut archive) = zip::ZipArchive::new(std::io::Cursor::new(bytes)) else {
        return false;
    };
    for (file_name, info) in files {
        let normalized = normalize_file_path(file_name);
        // SECURITY: never look up a key that escapes the package dir — treat
        // it as out-of-sync (the full pipeline would refuse it anyway).
        if !is_safe_relative_subpath(normalized) {
            return false;
        }
        let Ok(mut entry) = archive.by_name(normalized) else {
            return false;
        };
        let mut content = Vec::with_capacity(entry.size() as usize);
        if entry.read_to_end(&mut content).is_err() {
            return false;
        }
        if compute_git_sha256_from_bytes(&content) != info.after_hash {
            return false;
        }
    }
    true
}

/// Shared helper the vendor backends (and `go_redirect`) delegate to: true
/// when the copy exists and every patched file in it already hashes to its
/// `afterHash`.
pub(crate) async fn copy_matches_after_hashes(
    copy_dir: &Path,
    files: &HashMap<String, PatchFileInfo>,
) -> bool {
    if tokio::fs::metadata(copy_dir).await.is_err() {
        return false;
    }
    for (file_name, info) in files {
        let normalized = normalize_file_path(file_name);
        // SECURITY: never hash through a manifest key that escapes the copy
        // dir — fail the sync check instead (the full pipeline would refuse
        // the key anyway).
        if !is_safe_relative_subpath(normalized) {
            return false;
        }
        match compute_file_git_sha256(&copy_dir.join(normalized)).await {
            Ok(h) if h == info.after_hash => {}
            _ => return false,
        }
    }
    true
}

/// Shared [`WiringRecord`] constructor for the lock-splicing backends:
/// `original`/`new` are verbatim text fragments of `file`.
pub(crate) fn record(
    file: &str,
    kind: &str,
    action: WiringAction,
    key: &str,
    original: Option<String>,
    new: String,
) -> WiringRecord {
    WiringRecord {
        file: file.to_string(),
        kind: kind.to_string(),
        action,
        key: Some(key.to_string()),
        original: original.map(Value::String),
        new: Some(Value::String(new)),
    }
}

/// `key` looked up through any table-like TOML item (standard or inline
/// table).
pub(crate) fn item_get<'a>(item: &'a Item, key: &str) -> Option<&'a Item> {
    item.as_table_like().and_then(|t| t.get(key))
}

/// Leading PEP 508 distribution name of a dependency spec.
pub(crate) fn pep508_name(spec: &str) -> &str {
    let s = spec.trim_start();
    let end = s
        .char_indices()
        .find(|(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .map(|(i, _)| i)
        .unwrap_or(s.len());
    &s[..end]
}

/// Whether a `[[package]]` unit (as its lines) names `canon` — PEP 503
/// canonical comparison, the form the pypi lock generators record.
pub(crate) fn unit_has_canon_name(lines: &[&str], canon: &str) -> bool {
    lines
        .iter()
        .find_map(|l| l.strip_prefix("name = "))
        .map(|r| canonicalize_pypi_name(r.trim().trim_matches('"')))
        .as_deref()
        == Some(canon)
}

/// The lock's `[[package]]` tables whose `name` canonicalizes (PEP 503) to
/// `canon_name` — the poetry/pdm target-guard probe (uv records names
/// pre-canonicalized and counts them directly instead).
pub(crate) fn lock_units_named<'a>(lock: &'a DocumentMut, canon_name: &str) -> Vec<&'a Table> {
    lock.get("package")
        .and_then(Item::as_array_of_tables)
        .map(|pkgs| {
            pkgs.iter()
                .filter(|t| {
                    t.get("name")
                        .and_then(Item::as_str)
                        .map(canonicalize_pypi_name)
                        .as_deref()
                        == Some(canon_name)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Collect the PEP 621 `[project] dependencies` / `optional-dependencies`
/// distribution names into `declared` — the pyproject surface shared by the
/// poetry/pdm/uv dep classifiers (each adds its tool-specific tables on top).
pub(crate) fn pep621_declared_names(doc: &DocumentMut, declared: &mut Vec<String>) {
    let Some(project) = doc.get("project") else {
        return;
    };
    if let Some(deps) = item_get(project, "dependencies").and_then(Item::as_array) {
        declared.extend(
            deps.iter()
                .filter_map(toml_edit::Value::as_str)
                .map(|s| pep508_name(s).to_string()),
        );
    }
    if let Some(optional) = item_get(project, "optional-dependencies").and_then(Item::as_table_like)
    {
        for (_, item) in optional.iter() {
            if let Some(arr) = item.as_array() {
                declared.extend(
                    arr.iter()
                        .filter_map(toml_edit::Value::as_str)
                        .map(|s| pep508_name(s).to_string()),
                );
            }
        }
    }
}

/// Shared revert for the single-file, single-kind lock-splice backends
/// (poetry/pdm): restore the verbatim original fragment each wiring record
/// holds for `lock_file`. A fragment that no longer matches what we wrote is
/// left alone with a `vendor_lock_entry_drifted` warning — revert never
/// clobbers third-party edits.
pub(crate) async fn revert_lock_fragment_splice(
    entry: &VendorEntry,
    root: &Path,
    dry_run: bool,
    lock_file: &str,
    kind: &str,
    flavor: &str,
) -> RevertOutcome {
    use tokio::io::AsyncReadExt as _;

    let lock_path = root.join(lock_file);
    // Guarded read (`open_regular_file`: O_NONBLOCK + regular-file check): a
    // FIFO planted as the lock must fail this revert fast and loudly, not
    // wedge remove/rollback forever in an `open(2)` waiting for a writer.
    let mut lock_text = match open_regular_file(&lock_path).await {
        Ok((mut file, metadata)) => {
            let mut t = String::with_capacity(metadata.len() as usize);
            if let Err(e) = file.read_to_string(&mut t).await {
                return RevertOutcome::failed(format!("cannot read {lock_file}: {e}"));
            }
            t
        }
        Err(e) => return RevertOutcome::failed(format!("cannot read {lock_file}: {e}")),
    };
    let mut warnings: Vec<VendorWarning> = Vec::new();

    for rec in entry.wiring.iter().rev() {
        // SECURITY: `rec.file` comes verbatim from the committed, tamper-able
        // state.json. These backends only ever wrote their single lock file
        // (the per-flavor file allowlist); any other recorded path is skipped
        // fail-closed with a warning and is NEVER resolved against the
        // filesystem.
        if rec.file != lock_file {
            warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "ignoring wiring record for unexpected file `{}` (only {lock_file} is \
                     {flavor}-owned)",
                    rec.file
                ),
            ));
            continue;
        }
        // Forward compatibility: a newer ledger's unknown kind degrades to a
        // warning (never guess at a fragment shape).
        if rec.kind != kind {
            warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!("unknown {flavor} wiring kind {:?}; skipped", rec.kind),
            ));
            continue;
        }
        let new_text = rec.new.as_ref().and_then(Value::as_str);
        let original_text = rec.original.as_ref().and_then(Value::as_str);
        match super::toml_surgery::replace_fragment(&lock_text, new_text, original_text) {
            Some(t) => lock_text = t,
            None => {
                // ALREADY CONVERGED (the LIVENESS CONTRACT, vendor/mod.rs):
                // the lock already carries the recorded pre-vendor original
                // — an earlier partial revert or a relock regeneration
                // already restored the unit. Not drift: stay silent so the
                // drift-skip keep gate can converge instead of keeping the
                // artifact dir and ledger entry forever.
                if original_text.is_some_and(|orig| lock_text.contains(orig)) {
                    continue;
                }
                warnings.push(VendorWarning::new(
                    "vendor_lock_entry_drifted",
                    format!(
                        "{lock_file} fragment for {:?} changed since vendoring; left untouched",
                        rec.key
                    ),
                ));
            }
        }
    }

    if !dry_run {
        // Mode-preserving: the lock is a user-owned file we merely edit, so
        // the swapped-in inode must keep its permission bits rather than
        // reset them to umask defaults.
        if let Err(e) = atomic_write_bytes_preserving_mode(&lock_path, lock_text.as_bytes()).await {
            return RevertOutcome {
                kept_artifact: false,
                success: false,
                warnings,
                error: Some(format!("cannot write {lock_file}: {e}")),
            };
        }
    }
    RevertOutcome {
        kept_artifact: false,
        success: true,
        warnings,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::hash::git_sha256::compute_git_sha256_from_bytes;

    /// A one-entry `pkg.jar` (`lib/a.js` = `b"patched\n"`) written into `dir`,
    /// plus the files map whose `afterHash` matches it — the in-sync baseline
    /// each `zip_matches_after_hashes` case perturbs.
    fn in_sync_jar_fixture(
        dir: &Path,
    ) -> (std::path::PathBuf, HashMap<String, PatchFileInfo>, Vec<u8>) {
        let zip_bytes = write_zip_entries(&[("lib/a.js".to_string(), b"patched\n".to_vec(), 0o644)])
            .expect("fixture zip");
        let jar = dir.join("pkg.jar");
        std::fs::write(&jar, &zip_bytes).unwrap();
        let files = HashMap::from([(
            "lib/a.js".to_string(),
            PatchFileInfo {
                before_hash: "before".to_string(),
                after_hash: compute_git_sha256_from_bytes(b"patched\n"),
            },
        )]);
        (jar, files, zip_bytes)
    }

    /// Control for the negative cases below: an archive whose every patched
    /// entry hashes to its `afterHash` reads as in-sync.
    #[tokio::test]
    async fn zip_matches_after_hashes_accepts_in_sync_archive() {
        let dir = tempfile::tempdir().unwrap();
        let (jar, files, _) = in_sync_jar_fixture(dir.path());
        assert!(
            zip_matches_after_hashes(&jar, &files).await,
            "an archive matching every afterHash must read as in-sync"
        );
    }

    /// Bytes that aren't a zip archive at all (a truncated or clobbered
    /// `.jar` / `.nupkg`) must read as out-of-sync, not error or panic.
    #[tokio::test]
    async fn zip_matches_after_hashes_rejects_non_zip_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let (jar, files, _) = in_sync_jar_fixture(dir.path());
        std::fs::write(&jar, b"not a zip archive").unwrap();
        assert!(
            !zip_matches_after_hashes(&jar, &files).await,
            "non-zip bytes must read as out-of-sync"
        );
    }

    /// SECURITY: a manifest key that escapes the package dir must read as
    /// out-of-sync BEFORE any lookup — even when the archive itself carries
    /// a literal `../evil.js` entry whose content hashes to the afterHash
    /// (so without the guard the probe would say in-sync).
    #[tokio::test]
    async fn zip_matches_after_hashes_rejects_escaping_manifest_key() {
        let dir = tempfile::tempdir().unwrap();
        let zip_bytes =
            write_zip_entries(&[("../evil.js".to_string(), b"patched\n".to_vec(), 0o644)])
                .expect("fixture zip");
        let jar = dir.path().join("pkg.jar");
        std::fs::write(&jar, &zip_bytes).unwrap();
        let files = HashMap::from([(
            "../evil.js".to_string(),
            PatchFileInfo {
                before_hash: "before".to_string(),
                after_hash: compute_git_sha256_from_bytes(b"patched\n"),
            },
        )]);
        assert!(
            !zip_matches_after_hashes(&jar, &files).await,
            "a manifest key escaping the package dir must read as out-of-sync"
        );
    }

    /// A patched file the archive no longer contains must read as
    /// out-of-sync.
    #[tokio::test]
    async fn zip_matches_after_hashes_rejects_missing_entry() {
        let dir = tempfile::tempdir().unwrap();
        let (jar, _, _) = in_sync_jar_fixture(dir.path());
        let files = HashMap::from([(
            "lib/missing.js".to_string(),
            PatchFileInfo {
                before_hash: "before".to_string(),
                after_hash: compute_git_sha256_from_bytes(b"patched\n"),
            },
        )]);
        assert!(
            !zip_matches_after_hashes(&jar, &files).await,
            "an entry absent from the archive must read as out-of-sync"
        );
    }

    /// A corrupted entry payload (deflate/CRC read error behind an intact
    /// central directory, so `by_name` still succeeds) must read as
    /// out-of-sync instead of erroring.
    #[tokio::test]
    async fn zip_matches_after_hashes_rejects_corrupt_entry_payload() {
        let dir = tempfile::tempdir().unwrap();
        let (jar, files, mut zip_bytes) = in_sync_jar_fixture(dir.path());
        // The byte just before the central-directory signature is the last
        // byte of the (sole) entry's deflate payload — ZipWriter over a
        // Cursor seeks back to patch the local header, so there is no data
        // descriptor in between. Flipping it corrupts the stream/CRC while
        // the central directory stays intact.
        let cd_offset = zip_bytes
            .windows(4)
            .position(|w| w == [0x50, 0x4b, 0x01, 0x02])
            .expect("central directory signature");
        zip_bytes[cd_offset - 1] ^= 0xff;
        std::fs::write(&jar, &zip_bytes).unwrap();
        assert!(
            !zip_matches_after_hashes(&jar, &files).await,
            "a corrupt entry payload must read as out-of-sync"
        );
    }

    /// An entry whose content no longer hashes to its `afterHash` must read
    /// as out-of-sync.
    #[tokio::test]
    async fn zip_matches_after_hashes_rejects_after_hash_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let (jar, _, _) = in_sync_jar_fixture(dir.path());
        let files = HashMap::from([(
            "lib/a.js".to_string(),
            PatchFileInfo {
                before_hash: "before".to_string(),
                after_hash: "0".repeat(64),
            },
        )]);
        assert!(
            !zip_matches_after_hashes(&jar, &files).await,
            "a content-hash mismatch must read as out-of-sync"
        );
    }

    /// Control for the escape test below: a copy whose every patched file
    /// hashes to its `afterHash` reads as in-sync.
    #[tokio::test]
    async fn copy_matches_after_hashes_accepts_in_sync_copy() {
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("copy");
        std::fs::create_dir_all(copy.join("lib")).unwrap();
        std::fs::write(copy.join("lib/a.js"), b"patched\n").unwrap();
        let files = HashMap::from([(
            "lib/a.js".to_string(),
            PatchFileInfo {
                before_hash: "before".to_string(),
                after_hash: compute_git_sha256_from_bytes(b"patched\n"),
            },
        )]);
        assert!(
            copy_matches_after_hashes(&copy, &files).await,
            "a copy matching every afterHash must read as in-sync"
        );
    }

    /// SECURITY: a manifest key that escapes the copy dir must read as
    /// out-of-sync BEFORE any hashing — even when a real file at the escaped
    /// location hashes to the afterHash (so without the guard the probe
    /// would resolve outside the copy dir and say in-sync).
    #[tokio::test]
    async fn copy_matches_after_hashes_refuses_escaping_key() {
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("copy");
        std::fs::create_dir_all(copy.join("lib")).unwrap();
        std::fs::write(copy.join("lib/a.js"), b"patched\n").unwrap();
        // A real, afterHash-matching file OUTSIDE the copy dir at the exact
        // spot `copy.join("../evil.js")` would resolve to.
        std::fs::write(dir.path().join("evil.js"), b"patched\n").unwrap();
        let files = HashMap::from([(
            "../evil.js".to_string(),
            PatchFileInfo {
                before_hash: "before".to_string(),
                after_hash: compute_git_sha256_from_bytes(b"patched\n"),
            },
        )]);
        assert!(
            !copy_matches_after_hashes(&copy, &files).await,
            "a manifest key escaping the copy dir must read as out-of-sync"
        );
    }

    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c_path =
            std::ffi::CString::new(path.as_os_str().as_bytes()).expect("fifo path has no NUL");
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
        assert_eq!(
            rc,
            0,
            "mkfifo(2) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    /// A FIFO planted at the committed archive path (`.jar` / `.nupkg`) must
    /// read as out-of-sync instead of wedging the maven/nuget in-sync probes
    /// — and with them every apply — forever in an `open(2)` that waits for
    /// a writer that never comes. Same `open_regular_file` guard class as
    /// the Cargo.lock / lock-splice twins.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_archive_fails_fast_in_zip_matches_after_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let jar = dir.path().join("pkg.jar");
        mkfifo(&jar);
        let files: HashMap<String, PatchFileInfo> = HashMap::from([(
            "lib/a.js".to_string(),
            PatchFileInfo {
                before_hash: "before".to_string(),
                after_hash: "after".to_string(),
            },
        )]);

        // On timeout the open is wedged in a `spawn_blocking` thread that the
        // runtime waits for on shutdown; connect a writer to release it so
        // the test can FAIL instead of hanging the whole suite.
        let deadline = std::time::Duration::from_secs(5);
        let Ok(in_sync) =
            tokio::time::timeout(deadline, zip_matches_after_hashes(&jar, &files)).await
        else {
            let _ = std::fs::OpenOptions::new().write(true).open(&jar);
            panic!("zip_matches_after_hashes must fail fast on a FIFO archive");
        };
        assert!(!in_sync, "a FIFO archive must read as out-of-sync");
    }

    /// A FIFO planted as the lock file must fail the revert fast and loudly
    /// instead of wedging `remove` / rollback forever in an `open(2)` that
    /// waits for a writer that never comes.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_lock_fails_fast_in_revert_lock_fragment_splice() {
        let dir = tempfile::tempdir().unwrap();
        mkfifo(&dir.path().join("poetry.lock"));

        let mut entry: VendorEntry = serde_json::from_value(serde_json::json!({
            "ecosystem": "pypi",
            "basePurl": "pkg:pypi/six@1.16.0",
            "uuid": "u",
            "artifact": {"path": ".socket/vendor/pypi/u/x.whl"},
            "wiring": [],
        }))
        .unwrap();
        entry.wiring = vec![record(
            "poetry.lock",
            "poetry_lock_package",
            WiringAction::Rewritten,
            "six",
            Some("OLD-FRAGMENT".into()),
            "NEW-FRAGMENT".into(),
        )];

        // Same timeout-then-release shape as the archive test above.
        let deadline = std::time::Duration::from_secs(5);
        let Ok(outcome) = tokio::time::timeout(
            deadline,
            revert_lock_fragment_splice(
                &entry,
                dir.path(),
                false,
                "poetry.lock",
                "poetry_lock_package",
                "poetry",
            ),
        )
        .await
        else {
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .open(dir.path().join("poetry.lock"));
            panic!("revert_lock_fragment_splice must fail fast on a FIFO lock");
        };
        assert!(!outcome.success, "a FIFO lock must fail the revert");
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("cannot read poetry.lock")),
            "{:?}",
            outcome.error
        );
    }

    /// LIVENESS CONTRACT (vendor/mod.rs): a fragment whose lock already
    /// carries the recorded pre-vendor original — a relock regenerated the
    /// unit, or an earlier partial revert restored it — is CONVERGED, not
    /// drifted: re-classifying it would make the pypi drift-keep gate
    /// retain the artifact dir and ledger entry forever, with remediation
    /// advice that can never be satisfied.
    #[tokio::test]
    async fn revert_lock_fragment_splice_converged_fragment_is_silent_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("poetry.lock");
        tokio::fs::write(&lock, "alpha\nOLD-FRAGMENT\nomega\n")
            .await
            .unwrap();

        let mut entry: VendorEntry = serde_json::from_value(serde_json::json!({
            "ecosystem": "pypi",
            "basePurl": "pkg:pypi/six@1.16.0",
            "uuid": "u",
            "artifact": {"path": ".socket/vendor/pypi/u/x.whl"},
            "wiring": [],
        }))
        .unwrap();
        entry.wiring = vec![record(
            "poetry.lock",
            "poetry_lock_package",
            WiringAction::Rewritten,
            "six",
            Some("OLD-FRAGMENT".into()),
            "NEW-FRAGMENT".into(),
        )];

        let outcome = revert_lock_fragment_splice(
            &entry,
            dir.path(),
            false,
            "poetry.lock",
            "poetry_lock_package",
            "poetry",
        )
        .await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome.warnings.is_empty(),
            "converged fragments must not read as drift: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(&lock).await.unwrap(),
            "alpha\nOLD-FRAGMENT\nomega\n",
            "nothing to restore"
        );
    }

    /// The lock file is user-owned: reverting the splice must not reset its
    /// permission bits (the `package_json/update.rs` mode-reset bug, same
    /// class — see `atomic_write_bytes_preserving_mode`).
    #[cfg(unix)]
    #[tokio::test]
    async fn revert_lock_fragment_splice_preserves_lock_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("poetry.lock");
        tokio::fs::write(&lock, "alpha\nNEW-FRAGMENT\nomega\n")
            .await
            .unwrap();
        let mut perms = std::fs::metadata(&lock).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&lock, perms).unwrap();

        let mut entry: VendorEntry = serde_json::from_value(serde_json::json!({
            "ecosystem": "pypi",
            "basePurl": "pkg:pypi/six@1.16.0",
            "uuid": "u",
            "artifact": {"path": ".socket/vendor/pypi/u/x.whl"},
            "wiring": [],
        }))
        .unwrap();
        entry.wiring = vec![record(
            "poetry.lock",
            "poetry_lock_package",
            WiringAction::Rewritten,
            "six",
            Some("OLD-FRAGMENT".into()),
            "NEW-FRAGMENT".into(),
        )];

        let outcome = revert_lock_fragment_splice(
            &entry,
            dir.path(),
            false,
            "poetry.lock",
            "poetry_lock_package",
            "poetry",
        )
        .await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert_eq!(
            tokio::fs::read_to_string(&lock).await.unwrap(),
            "alpha\nOLD-FRAGMENT\nomega\n",
            "fragment restored"
        );
        let mode = std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "revert must preserve the lock file's permission bits"
        );
    }

    /// A lock file that opens as a regular file but isn't valid UTF-8 (a
    /// stray Latin-1 byte in a poetry.lock/pdm.lock) must fail the revert
    /// loudly with `cannot read <lock>` — and leave the bytes on disk
    /// untouched — rather than proceed on garbled text.
    #[tokio::test]
    async fn revert_lock_fragment_splice_fails_on_non_utf8_lock() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("poetry.lock");
        let lock_bytes: &[u8] = b"alpha\nNEW-FRAGMENT\n\xff\xfe\n";
        std::fs::write(&lock, lock_bytes).unwrap();

        let mut entry: VendorEntry = serde_json::from_value(serde_json::json!({
            "ecosystem": "pypi",
            "basePurl": "pkg:pypi/six@1.16.0",
            "uuid": "u",
            "artifact": {"path": ".socket/vendor/pypi/u/x.whl"},
            "wiring": [],
        }))
        .unwrap();
        entry.wiring = vec![record(
            "poetry.lock",
            "poetry_lock_package",
            WiringAction::Rewritten,
            "six",
            Some("OLD-FRAGMENT".into()),
            "NEW-FRAGMENT".into(),
        )];

        let outcome = revert_lock_fragment_splice(
            &entry,
            dir.path(),
            false,
            "poetry.lock",
            "poetry_lock_package",
            "poetry",
        )
        .await;
        assert!(!outcome.success, "a non-UTF-8 lock must fail the revert");
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("cannot read poetry.lock")),
            "{:?}",
            outcome.error
        );
        assert!(
            !outcome.kept_artifact,
            "kept_artifact is never set on failure"
        );
        assert_eq!(
            std::fs::read(&lock).unwrap(),
            lock_bytes,
            "a failed revert must leave the lock bytes untouched"
        );
    }

    /// When the final atomic write fails (read-only parent dir — the
    /// documented 'atomic write needs writable parent' class), the revert
    /// must fail with `cannot write <lock>`, keep `kept_artifact == false`
    /// (the mod.rs contract), and — the reason lines 462-467 hand-build the
    /// outcome instead of calling `RevertOutcome::failed` — carry the drift
    /// warnings accumulated before the write into the failed outcome.
    #[cfg(unix)]
    #[tokio::test]
    async fn revert_lock_fragment_splice_write_failure_keeps_warnings() {
        use std::os::unix::fs::PermissionsExt;
        // root ignores permission bits, so the read-only dir wouldn't fail.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("poetry.lock");
        tokio::fs::write(&lock, "alpha\nNEW-FRAGMENT\nomega\n")
            .await
            .unwrap();

        let mut entry: VendorEntry = serde_json::from_value(serde_json::json!({
            "ecosystem": "pypi",
            "basePurl": "pkg:pypi/six@1.16.0",
            "uuid": "u",
            "artifact": {"path": ".socket/vendor/pypi/u/x.whl"},
            "wiring": [],
        }))
        .unwrap();
        entry.wiring = vec![
            // Allowlist-skipped record: seeds a vendor_lock_entry_drifted
            // warning that must survive the failed write below.
            record(
                "other.lock",
                "poetry_lock_package",
                WiringAction::Rewritten,
                "six",
                Some("OLD".into()),
                "NEW".into(),
            ),
            record(
                "poetry.lock",
                "poetry_lock_package",
                WiringAction::Rewritten,
                "six",
                Some("OLD-FRAGMENT".into()),
                "NEW-FRAGMENT".into(),
            ),
        ];

        // Read-only parent: the atomic write stages its temp file in the
        // parent dir, so the write fails EACCES while the lock itself stays
        // readable.
        let mut dir_perms = std::fs::metadata(dir.path()).unwrap().permissions();
        dir_perms.set_mode(0o555);
        std::fs::set_permissions(dir.path(), dir_perms).unwrap();

        let outcome = revert_lock_fragment_splice(
            &entry,
            dir.path(),
            false,
            "poetry.lock",
            "poetry_lock_package",
            "poetry",
        )
        .await;

        // Restore before asserting so tempdir cleanup succeeds even on a
        // failed assertion.
        let mut dir_perms = std::fs::metadata(dir.path()).unwrap().permissions();
        dir_perms.set_mode(0o755);
        std::fs::set_permissions(dir.path(), dir_perms).unwrap();

        assert!(!outcome.success, "a failed write must fail the revert");
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("cannot write poetry.lock")),
            "{:?}",
            outcome.error
        );
        assert!(
            !outcome.kept_artifact,
            "kept_artifact is never set on failure"
        );
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted" && w.detail.contains("other.lock")),
            "warnings accumulated before the failed write must survive it: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(&lock).await.unwrap(),
            "alpha\nNEW-FRAGMENT\nomega\n",
            "a failed revert must leave the lock content untouched"
        );
    }
}
