//! Composer's path-repository mirror silently skips files of the vendored
//! copy, so neutralize the filters it applies before the copy is wired.
//!
//! `transport-options.symlink: false` makes `composer install` MIRROR the
//! copy into `vendor/<vendor>/<name>` through `ArchivableFilesFinder`, the
//! same finder `composer archive` uses. It applies, at the copy root:
//!
//! * `GitExcludeFilter` over `.gitignore` — Composer 1.x through 2.1.x;
//! * `GitExcludeFilter` over `.gitattributes` `export-ignore` rules — every
//!   version (`-export-ignore` negations from 2.x);
//! * `HgExcludeFilter` over `.hgignore` — Composer 1.x.
//!
//! A package shipping any of those (its own dist often does) therefore lands
//! in `vendor/` MISSING the matched files: a patched file among them installs
//! as nothing, or a file the package needs at runtime vanishes. The copy's
//! filter files are rewritten so that every Composer version mirrors every
//! file: `.gitignore` / `.hgignore` are truncated to empty (the file set is
//! unchanged, so versions that ignore them are unaffected) and each
//! `.gitattributes` line carrying an `export-ignore` / `-export-ignore`
//! attribute is dropped, every other line and its line ending kept.
//!
//! A filter file the patch itself rewrites cannot be neutralized without
//! breaking its `afterHash`; that is a [`MirrorFilterError::PatchedFilterFile`]
//! conflict, raised only when the file would actually need a change.

use std::io;
use std::path::Path;

use crate::manifest::schema::PatchRecord;
use crate::utils::fs::atomic_write_bytes_preserving_mode;

use crate::vendor::VendorWarning;

const GITIGNORE: &str = ".gitignore";
const HGIGNORE: &str = ".hgignore";
const GITATTRIBUTES: &str = ".gitattributes";

/// What [`neutralize_mirror_filters`] changed in the copy.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct MirrorFilterReport {
    pub gitignore_neutralized: bool,
    pub hgignore_neutralized: bool,
    pub export_ignore_rules_removed: usize,
}

impl MirrorFilterReport {
    pub fn changed(&self) -> bool {
        self.gitignore_neutralized
            || self.hgignore_neutralized
            || self.export_ignore_rules_removed > 0
    }
}

#[derive(Debug)]
pub(super) enum MirrorFilterError {
    /// The patch rewrites this filter file, and it would need neutralizing.
    PatchedFilterFile(&'static str),
    Io(io::Error),
}

impl std::fmt::Display for MirrorFilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PatchedFilterFile(file) => write!(
                f,
                "the patch rewrites the package's {file}, whose rules make Composer's path \
                 mirror skip files of the vendored copy; neutralizing them would break the \
                 patched file's hash"
            ),
            Self::Io(e) => write!(f, "could not neutralize the copy's mirror filters: {e}"),
        }
    }
}

/// A `.gitattributes` line whose attributes include `export-ignore` or
/// `-export-ignore` (the first whitespace token is the path pattern).
fn is_export_ignore_rule(line: &str) -> bool {
    line.split_whitespace()
        .skip(1)
        .any(|attr| attr == "export-ignore" || attr == "-export-ignore")
}

/// `text` without its export-ignore rules, and how many were dropped.
fn strip_export_ignore(text: &str) -> (String, usize) {
    let mut out = String::with_capacity(text.len());
    let mut removed = 0;
    for line in text.split_inclusive('\n') {
        if is_export_ignore_rule(line) {
            removed += 1;
        } else {
            out.push_str(line);
        }
    }
    (out, removed)
}

/// The neutralized bytes for one filter file, `None` when it is already
/// neutral (absent, or nothing to drop). A symlink is always replaced by an
/// empty regular file: its target may sit outside the copy and is never
/// read.
async fn plan(path: &Path, file: &'static str) -> io::Result<Option<(Vec<u8>, usize)>> {
    let meta = match tokio::fs::symlink_metadata(path).await {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if meta.file_type().is_symlink() {
        return Ok(Some((Vec::new(), 0)));
    }
    if !meta.is_file() {
        return Ok(None);
    }
    let bytes = tokio::fs::read(path).await?;
    if file != GITATTRIBUTES {
        return Ok((!bytes.is_empty()).then(|| (Vec::new(), 0)));
    }
    let text = String::from_utf8_lossy(&bytes);
    let (stripped, removed) = strip_export_ignore(&text);
    Ok((removed > 0).then(|| (stripped.into_bytes(), removed)))
}

/// Rewrite the copy's `.gitignore`, `.hgignore` and `.gitattributes` so
/// Composer's path mirror copies every file (see the module doc).
/// Idempotent: a second run changes nothing.
pub(super) async fn neutralize_mirror_filters(
    copy_dir: &Path,
    patched_files: &[String],
) -> Result<MirrorFilterReport, MirrorFilterError> {
    let mut planned = Vec::new();
    for file in [GITIGNORE, HGIGNORE, GITATTRIBUTES] {
        let path = copy_dir.join(file);
        if let Some(change) = plan(&path, file).await.map_err(MirrorFilterError::Io)? {
            if patched_files.iter().any(|p| p == file) {
                return Err(MirrorFilterError::PatchedFilterFile(file));
            }
            planned.push((file, path, change));
        }
    }
    let mut report = MirrorFilterReport::default();
    for (file, path, (bytes, removed)) in planned {
        atomic_write_bytes_preserving_mode(&path, &bytes)
            .await
            .map_err(MirrorFilterError::Io)?;
        match file {
            GITIGNORE => report.gitignore_neutralized = true,
            HGIGNORE => report.hgignore_neutralized = true,
            _ => report.export_ignore_rules_removed += removed.max(1),
        }
    }
    Ok(report)
}

fn patched_keys(record: &PatchRecord) -> Vec<String> {
    record.files.keys().cloned().collect()
}

fn neutralized_warning(pkg: &str, report: &MirrorFilterReport) -> VendorWarning {
    let mut what = Vec::new();
    if report.gitignore_neutralized {
        what.push(".gitignore".to_string());
    }
    if report.hgignore_neutralized {
        what.push(".hgignore".to_string());
    }
    if report.export_ignore_rules_removed > 0 {
        what.push(format!(
            ".gitattributes export-ignore ({} rule{})",
            report.export_ignore_rules_removed,
            if report.export_ignore_rules_removed == 1 {
                ""
            } else {
                "s"
            }
        ));
    }
    VendorWarning::new(
        "vendor_composer_mirror_filters_neutralized",
        format!(
            "{pkg}: Composer's path mirror would have skipped files matched by the vendored \
             copy's {}; those rules were neutralized in the vendored copy (commit it)",
            what.join(", ")
        ),
    )
}

/// Fresh-vendor gate: neutralize, warn on change; `Err(detail)` when the
/// copy cannot be made mirror-safe (the caller unwinds and refuses).
pub(super) async fn neutralize_or_conflict(
    copy_dir: &Path,
    record: &PatchRecord,
    pkg: &str,
    warnings: &mut Vec<VendorWarning>,
) -> Result<(), String> {
    match neutralize_mirror_filters(copy_dir, &patched_keys(record)).await {
        Ok(report) => {
            if report.changed() {
                warnings.push(neutralized_warning(pkg, &report));
            }
            Ok(())
        }
        Err(e) => Err(format!("{pkg}: {e}")),
    }
}

/// Already-wired paths (artifact rebuild, idempotent re-run): the lock stays
/// wired whatever happens, so a conflict is only warned about. Heals copies
/// vendored by a CLI that predates the neutralization.
pub(super) async fn heal_or_warn(
    copy_dir: &Path,
    record: &PatchRecord,
    pkg: &str,
    warnings: &mut Vec<VendorWarning>,
) {
    if let Err(detail) = neutralize_or_conflict(copy_dir, record, pkg, warnings).await {
        warnings.push(VendorWarning::new(
            "vendor_composer_mirror_filter_conflict",
            format!("{detail}; `composer install` may not mirror every file of the copy"),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn write(dir: &Path, rel: &str, text: &str) {
        tokio::fs::write(dir.join(rel), text).await.unwrap();
    }

    async fn read(dir: &Path, rel: &str) -> String {
        tokio::fs::read_to_string(dir.join(rel)).await.unwrap()
    }

    #[tokio::test]
    async fn nothing_present_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let report = neutralize_mirror_filters(dir.path(), &[]).await.unwrap();
        assert!(!report.changed());
        assert!(!dir.path().join(GITIGNORE).exists());
    }

    #[tokio::test]
    async fn ignore_files_are_truncated() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), GITIGNORE, "/src\n*.php\n").await;
        write(dir.path(), HGIGNORE, "syntax: glob\nsrc\n").await;
        let report = neutralize_mirror_filters(dir.path(), &[]).await.unwrap();
        assert!(report.gitignore_neutralized && report.hgignore_neutralized);
        assert_eq!(read(dir.path(), GITIGNORE).await, "");
        assert_eq!(read(dir.path(), HGIGNORE).await, "");
    }

    #[tokio::test]
    async fn export_ignore_rules_are_dropped_and_crlf_kept() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            GITATTRIBUTES,
            "* text=auto\r\n/tests export-ignore\r\n/src/Keep.php -export-ignore\r\n\
             *.php diff=php\r\n/docs\texport-ignore",
        )
        .await;
        let report = neutralize_mirror_filters(dir.path(), &[]).await.unwrap();
        assert_eq!(report.export_ignore_rules_removed, 3);
        assert_eq!(
            read(dir.path(), GITATTRIBUTES).await,
            "* text=auto\r\n*.php diff=php\r\n"
        );
    }

    #[tokio::test]
    async fn attributes_without_export_ignore_are_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            GITATTRIBUTES,
            "* text=auto\nexport-ignore diff\n",
        )
        .await;
        write(dir.path(), GITIGNORE, "").await;
        let report = neutralize_mirror_filters(dir.path(), &[]).await.unwrap();
        assert!(!report.changed());
        assert_eq!(
            read(dir.path(), GITATTRIBUTES).await,
            "* text=auto\nexport-ignore diff\n"
        );
    }

    #[tokio::test]
    async fn a_patched_filter_file_that_needs_a_change_conflicts() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), GITATTRIBUTES, "/tests export-ignore\n").await;
        write(dir.path(), GITIGNORE, "/build\n").await;
        let err = neutralize_mirror_filters(dir.path(), &[GITATTRIBUTES.to_string()])
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            MirrorFilterError::PatchedFilterFile(GITATTRIBUTES)
        ));
        assert_eq!(
            read(dir.path(), GITIGNORE).await,
            "/build\n",
            "nothing written"
        );
        let neutral = tempfile::tempdir().unwrap();
        write(neutral.path(), GITATTRIBUTES, "* text=auto\n").await;
        let report = neutralize_mirror_filters(neutral.path(), &[GITATTRIBUTES.to_string()])
            .await
            .unwrap();
        assert!(
            !report.changed(),
            "a patched but neutral file is no conflict"
        );
    }

    #[tokio::test]
    async fn neutralization_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), GITIGNORE, "/src\n").await;
        write(
            dir.path(),
            GITATTRIBUTES,
            "/tests export-ignore\n* text=auto\n",
        )
        .await;
        assert!(neutralize_mirror_filters(dir.path(), &[])
            .await
            .unwrap()
            .changed());
        let again = neutralize_mirror_filters(dir.path(), &[]).await.unwrap();
        assert!(!again.changed(), "{again:?}");
        assert_eq!(read(dir.path(), GITATTRIBUTES).await, "* text=auto\n");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlinked_filter_file_is_replaced_not_followed() {
        let outside = tempfile::tempdir().unwrap();
        write(outside.path(), "target", "/src\n").await;
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path().join("target"), dir.path().join(GITIGNORE))
            .unwrap();
        let report = neutralize_mirror_filters(dir.path(), &[]).await.unwrap();
        assert!(report.gitignore_neutralized);
        let meta = std::fs::symlink_metadata(dir.path().join(GITIGNORE)).unwrap();
        assert!(meta.is_file());
        assert_eq!(read(outside.path(), "target").await, "/src\n");
    }
}
