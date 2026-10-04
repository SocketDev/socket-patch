//! One fan-out over the pnpm/vlt store peer-variant copies of an npm
//! package, shared by agent-mode apply and rollback.
//!
//! pnpm and vlt materialize a separate store copy per peer-dependency (or
//! vlt modifier) combination (`.pnpm/foo@1.0.0(react@17…)/` and
//! `…(react@18…)/`, or `.vlt/~npm~foo@1.0.0~peer.2/` and `~peer.3/`), all
//! real, runtime-loaded dirs, while the purl-keyed resolver hands the
//! engine exactly one primary path. [`fan_out`] runs the single-copy
//! engine on the primary and then on every other physical copy, folding
//! each copy into the primary's result with one rule for both directions:
//!
//! - A failed copy fails the whole result (`store copy <path> failed to
//!   <verb>: …`). Claiming the CVE fixed (or reverted) while a physical
//!   copy is untouched is the fail-open this closes.
//! - A copy's per-file records are merged into the primary's, each file
//!   qualified by the copy's on-disk path, so a write that landed only in
//!   a twin is visible to the CLI's event classification and tallies.
//! - Of a successful copy's advisory, only the ownership note is carried
//!   (it already names the copy's file). Any other success note (apply's
//!   `--force` all-skipped note) describes the copy alone and would
//!   mislead on the primary.

use std::future::Future;
use std::path::{Path, PathBuf};

use crate::patch::apply::{normalize_file_path, OWNERSHIP_NOT_RESTORED_MARKER};

/// A single-copy engine result that [`fan_out`] can fold copies into.
pub(crate) trait CopyFold: Sized {
    /// The verb in a failed copy's note ("patch", "roll back").
    const VERB: &'static str;
    fn success(&self) -> bool;
    fn mark_failed(&mut self);
    fn error_mut(&mut self) -> &mut Option<String>;
    /// Move `copy_result`'s per-file records into `self`, renaming each
    /// file with `qualify`.
    fn extend_files(&mut self, copy_result: &mut Self, qualify: &dyn Fn(&str) -> String);
}

/// Run `engine` on `pkg_path`, then (for a successful npm result) on every
/// other pnpm/vlt store copy of the same package, folding each copy in.
/// Copies are visited even when the primary was already done: that is the
/// state a single-copy run leaves behind (done primary, untouched twin).
pub(crate) async fn fan_out<R, F, Fut>(package_key: &str, pkg_path: &Path, engine: F) -> R
where
    R: CopyFold,
    F: Fn(PathBuf) -> Fut,
    Fut: Future<Output = R>,
{
    let mut result = engine(pkg_path.to_path_buf()).await;
    // Only npm purls can name pnpm or vlt store copies; everything else
    // skips the (already cheap) discovery outright.
    if result.success() && package_key.starts_with("pkg:npm/") {
        for copy in crate::crawlers::npm_crawler::find_store_peer_variant_copies(pkg_path).await {
            let copy_result = engine(copy.clone()).await;
            fold(&mut result, &copy, copy_result);
        }
    }
    result
}

/// Merge one store copy's result into the primary's (see the module docs).
pub(crate) fn fold<R: CopyFold>(result: &mut R, copy: &Path, mut copy_result: R) {
    let qualify = |file: &str| copy.join(normalize_file_path(file)).display().to_string();
    result.extend_files(&mut copy_result, &qualify);
    let note = if copy_result.success() {
        match copy_result.error_mut().take() {
            Some(advisory) if advisory.contains(OWNERSHIP_NOT_RESTORED_MARKER) => advisory,
            _ => return,
        }
    } else {
        result.mark_failed();
        format!(
            "store copy {} failed to {}: {}",
            copy.display(),
            R::VERB,
            copy_result
                .error_mut()
                .take()
                .unwrap_or_else(|| "unknown error".to_string())
        )
    };
    let error = result.error_mut();
    *error = Some(match error.take() {
        Some(prev) => format!("{prev}; {note}"),
        None => note,
    });
}

#[cfg(all(test, unix))]
mod regression_tests {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::PatchFileInfo;
    use crate::patch::apply::{apply_package_patch, MismatchPolicy, PatchSources, VerifyStatus};
    use crate::patch::rollback::{rollback_package_patch, VerifyRollbackStatus};

    const ORIGINAL: &[u8] = b"module.exports = 'upstream';\n";
    const PATCHED: &[u8] = b"module.exports = 'patched';\n";

    /// A pnpm store with two peer-variant copies of `foo@1.0.0`, the
    /// importer's `node_modules/foo` linked to the first (the primary the
    /// resolver hands apply/rollback). Returns `(root, primary, copies,
    /// blobs, files)`.
    async fn pnpm_twins(
        primary_bytes: &[u8],
        twin_bytes: &[u8],
    ) -> (
        tempfile::TempDir,
        PathBuf,
        [PathBuf; 2],
        PathBuf,
        HashMap<String, PatchFileInfo>,
    ) {
        let root = tempfile::tempdir().unwrap();
        let nm = root.path().join("node_modules");
        let store = nm.join(".pnpm");
        let copies = [
            store.join("foo@1.0.0_react@18.2.0/node_modules/foo"),
            store.join("foo@1.0.0_react@18.3.1/node_modules/foo"),
        ];
        for (copy, bytes) in copies.iter().zip([primary_bytes, twin_bytes]) {
            tokio::fs::create_dir_all(copy).await.unwrap();
            tokio::fs::write(
                copy.join("package.json"),
                r#"{"name":"foo","version":"1.0.0"}"#,
            )
            .await
            .unwrap();
            tokio::fs::write(copy.join("index.js"), bytes)
                .await
                .unwrap();
        }
        std::os::unix::fs::symlink(&copies[0], nm.join("foo")).unwrap();
        let primary = nm.join("foo");

        let blobs = root.path().join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        let before_hash = compute_git_sha256_from_bytes(ORIGINAL);
        let after_hash = compute_git_sha256_from_bytes(PATCHED);
        tokio::fs::write(blobs.join(&before_hash), ORIGINAL)
            .await
            .unwrap();
        tokio::fs::write(blobs.join(&after_hash), PATCHED)
            .await
            .unwrap();
        let mut files = HashMap::new();
        files.insert(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash,
                after_hash,
            },
        );
        (root, primary, copies, blobs, files)
    }

    async fn read(path: &Path) -> Vec<u8> {
        tokio::fs::read(path).await.unwrap()
    }

    /// #756: the primary is already patched and only the twin is not.
    /// Apply writes the twin, and the result must say so: the twin's file
    /// is in `files_patched` (qualified by the copy path, with its
    /// `applied_via`), and its verify record is `Ready`, so the CLI
    /// classifies the package as applied, not `already_patched`.
    #[tokio::test]
    async fn apply_reports_a_write_to_an_unpatched_twin_copy() {
        let (_root, primary, copies, blobs, files) = pnpm_twins(PATCHED, ORIGINAL).await;
        let result = apply_package_patch(
            "pkg:npm/foo@1.0.0",
            &primary,
            &files,
            &PatchSources::blobs_only(&blobs),
            None,
            false,
            MismatchPolicy::Warn,
        )
        .await;
        assert!(result.success, "{:?}", result.error);
        assert_eq!(read(&copies[1].join("index.js")).await, PATCHED);

        let twin_file = copies[1].join("index.js").display().to_string();
        assert_eq!(result.files_patched, vec![twin_file.clone()]);
        assert!(result.applied_via.contains_key(&twin_file));
        assert!(
            result
                .files_verified
                .iter()
                .any(|v| v.file == twin_file && v.status == VerifyStatus::Ready),
            "the twin's verify record must be carried: {:?}",
            result.files_verified
        );
        assert!(
            !result
                .files_verified
                .iter()
                .all(|v| v.status == VerifyStatus::AlreadyPatched),
            "a run that wrote a copy is not all-already-patched"
        );
    }

    /// The dry-run twin of #756: a preview over a patched primary and an
    /// unpatched twin must not classify as all-already-patched either.
    #[tokio::test]
    async fn apply_dry_run_carries_an_unpatched_twin_verify_record() {
        let (_root, primary, copies, blobs, files) = pnpm_twins(PATCHED, ORIGINAL).await;
        let result = apply_package_patch(
            "pkg:npm/foo@1.0.0",
            &primary,
            &files,
            &PatchSources::blobs_only(&blobs),
            None,
            true,
            MismatchPolicy::Warn,
        )
        .await;
        assert!(result.success, "{:?}", result.error);
        assert_eq!(read(&copies[1].join("index.js")).await, ORIGINAL);
        assert!(result.files_patched.is_empty());
        assert!(result
            .files_verified
            .iter()
            .any(|v| v.status == VerifyStatus::Ready));
    }

    /// Both copies already patched: still `already_patched` (every carried
    /// record is AlreadyPatched, nothing written).
    #[tokio::test]
    async fn apply_over_patched_twins_stays_already_patched() {
        let (_root, primary, _copies, blobs, files) = pnpm_twins(PATCHED, PATCHED).await;
        let result = apply_package_patch(
            "pkg:npm/foo@1.0.0",
            &primary,
            &files,
            &PatchSources::blobs_only(&blobs),
            None,
            false,
            MismatchPolicy::Warn,
        )
        .await;
        assert!(result.success, "{:?}", result.error);
        assert!(result.files_patched.is_empty());
        assert_eq!(result.files_verified.len(), 2);
        assert!(result
            .files_verified
            .iter()
            .all(|v| v.status == VerifyStatus::AlreadyPatched));
    }

    /// #756 (rollback, from the issue's follow-up comment): the primary is
    /// already original and only the twin is patched. Rollback restores the
    /// twin and must report it in `files_rolled_back`, with a `Ready` verify
    /// record, so the CLI counts it as rolled back.
    #[tokio::test]
    async fn rollback_reports_a_restore_of_a_patched_twin_copy() {
        let (_root, primary, copies, blobs, files) = pnpm_twins(ORIGINAL, PATCHED).await;
        let result =
            rollback_package_patch("pkg:npm/foo@1.0.0", &primary, &files, &blobs, false).await;
        assert!(result.success, "{:?}", result.error);
        assert_eq!(read(&copies[1].join("index.js")).await, ORIGINAL);

        let twin_file = copies[1].join("index.js").display().to_string();
        assert_eq!(result.files_rolled_back, vec![twin_file.clone()]);
        assert!(
            result
                .files_verified
                .iter()
                .any(|v| v.file == twin_file && v.status == VerifyRollbackStatus::Ready),
            "the twin's verify record must be carried: {:?}",
            result.files_verified
        );
        assert!(!result
            .files_verified
            .iter()
            .all(|v| v.status == VerifyRollbackStatus::AlreadyOriginal));
    }

    /// Both copies already original: still `already_original`.
    #[tokio::test]
    async fn rollback_over_original_twins_stays_already_original() {
        let (_root, primary, _copies, blobs, files) = pnpm_twins(ORIGINAL, ORIGINAL).await;
        let result =
            rollback_package_patch("pkg:npm/foo@1.0.0", &primary, &files, &blobs, false).await;
        assert!(result.success, "{:?}", result.error);
        assert!(result.files_rolled_back.is_empty());
        assert_eq!(result.files_verified.len(), 2);
        assert!(result
            .files_verified
            .iter()
            .all(|v| v.status == VerifyRollbackStatus::AlreadyOriginal));
    }
}
