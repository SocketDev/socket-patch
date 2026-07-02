//! Leaf helpers shared by the vendor backends (and [`crate::patch::go_redirect`]).
//!
//! Each backend used to carry a private, byte-identical copy of these; they
//! are hoisted here so the shapes stay in lockstep.

use std::collections::HashMap;
use std::path::Path;

use crate::manifest::schema::PatchFileInfo;
use crate::patch::apply::{
    is_safe_relative_subpath, normalize_file_path, ApplyResult, VerifyResult, VerifyStatus,
};
use crate::patch::file_hash::compute_file_git_sha256;

use super::VendorOutcome;

/// Shared helper the vendor backends (and `go_redirect`) delegate to: a
/// [`VerifyResult`] reporting `file` as already patched.
pub(crate) fn already_patched_verify(file: &str) -> VerifyResult {
    VerifyResult {
        file: file.to_string(),
        status: VerifyStatus::AlreadyPatched,
        message: None,
        current_hash: None,
        expected_hash: None,
        target_hash: None,
    }
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
