//! Leaf helpers shared by the vendor backends (and [`crate::patch::go_redirect`]).
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
use crate::utils::fs::atomic_write_bytes_preserving_mode;

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

    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    let Ok(bytes) = tokio::fs::read(archive_path).await else {
        return false;
    };
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
    let lock_path = root.join(lock_file);
    let mut lock_text = match tokio::fs::read_to_string(&lock_path).await {
        Ok(t) => t,
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
            None => warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "{lock_file} fragment for {:?} changed since vendoring; left untouched",
                    rec.key
                ),
            )),
        }
    }

    if !dry_run {
        // Mode-preserving: the lock is a user-owned file we merely edit, so
        // the swapped-in inode must keep its permission bits rather than
        // reset them to umask defaults.
        if let Err(e) = atomic_write_bytes_preserving_mode(&lock_path, lock_text.as_bytes()).await {
            return RevertOutcome {
                success: false,
                warnings,
                error: Some(format!("cannot write {lock_file}: {e}")),
            };
        }
    }
    RevertOutcome {
        success: true,
        warnings,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
