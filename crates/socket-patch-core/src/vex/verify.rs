//! On-disk verification: which manifest entries are actually applied?
//!
//! A patch is "applied" iff every file the manifest claims it modified
//! currently hashes to its `afterHash`. Anything else — missing file,
//! hash mismatch, even one file ahead of expectations — disqualifies
//! the patch from the VEX document. Callers feed the failures into a
//! stderr warning + `--json` envelope warning list; the spec we agreed
//! on is "never emit `affected` or `under_investigation` — just omit".
//!
//! The CLI is responsible for resolving PURL → on-disk package path
//! (it already does this for `apply` / `scan` via the ecosystem
//! dispatcher). We accept a pre-built map so this module stays free of
//! ecosystem-crawler dependencies.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::manifest::schema::PatchManifest;
use crate::patch::apply::{verify_file_patch, VerifyStatus};

/// One entry per manifest PURL that did NOT pass verification. The
/// `reason` is a short snake_case tag the CLI can route on (matches
/// the `error_code` convention used by `json_envelope::PatchEvent`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedPatch {
    pub purl: String,
    pub reason: String,
}

/// Result of partitioning the manifest into applied vs failed sets.
#[derive(Debug, Clone, Default)]
pub struct VerifyOutcome {
    /// PURLs whose on-disk files all hash to their `afterHash`.
    pub applied: Vec<String>,
    /// PURLs whose verification failed (with a routing tag).
    pub failed: Vec<FailedPatch>,
}

/// Walk the manifest and bucket each PURL into `applied` / `failed`.
///
/// `package_paths` is the CLI-supplied `purl -> on-disk package dir`
/// map (from `find_packages_for_purls`). A PURL absent from the map is
/// recorded as `package_not_found` and ends up in `failed`.
pub async fn applied_patches(
    manifest: &PatchManifest,
    package_paths: &HashMap<String, PathBuf>,
) -> VerifyOutcome {
    let mut out = VerifyOutcome::default();

    for (purl, record) in &manifest.patches {
        let pkg_path = match package_paths.get(purl) {
            Some(p) => p,
            None => {
                out.failed.push(FailedPatch {
                    purl: purl.clone(),
                    reason: "package_not_found".to_string(),
                });
                continue;
            }
        };

        match verify_patch_record(pkg_path, record).await {
            Ok(()) => out.applied.push(purl.clone()),
            Err(reason) => out.failed.push(FailedPatch {
                purl: purl.clone(),
                reason,
            }),
        }
    }

    out
}

/// Returns `Ok(())` if every file in `record.files` is `AlreadyPatched`.
/// Otherwise returns a short routing tag describing the first failure.
async fn verify_patch_record(
    pkg_path: &Path,
    record: &crate::manifest::schema::PatchRecord,
) -> Result<(), String> {
    for (file_name, file_info) in &record.files {
        let result = verify_file_patch(pkg_path, file_name, file_info).await;
        match result.status {
            VerifyStatus::AlreadyPatched => continue,
            VerifyStatus::Ready => return Err("not_applied".to_string()),
            VerifyStatus::HashMismatch => return Err("hash_mismatch".to_string()),
            VerifyStatus::NotFound => return Err("file_not_found".to_string()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::{PatchFileInfo, PatchRecord};
    use std::collections::HashMap;

    fn record_with_one_file(after_hash: &str) -> PatchRecord {
        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash: "aaaa".to_string(),
                after_hash: after_hash.to_string(),
            },
        );
        PatchRecord {
            uuid: "u".to_string(),
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            files,
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    #[tokio::test]
    async fn applied_when_all_files_match_after_hash() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let patched = b"patched-content";
        let hash = compute_git_sha256_from_bytes(patched);
        tokio::fs::write(pkg_dir.path().join("index.js"), patched)
            .await
            .unwrap();

        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert("pkg:npm/x@1.0.0".to_string(), record_with_one_file(&hash));

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/x@1.0.0".to_string(), pkg_dir.path().to_path_buf());

        let out = applied_patches(&manifest, &paths).await;
        assert_eq!(out.applied, vec!["pkg:npm/x@1.0.0".to_string()]);
        assert!(out.failed.is_empty());
    }

    #[tokio::test]
    async fn missing_path_falls_into_failed() {
        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert("pkg:npm/x@1.0.0".to_string(), record_with_one_file("deadbeef"));

        let paths: HashMap<String, PathBuf> = HashMap::new();
        let out = applied_patches(&manifest, &paths).await;
        assert!(out.applied.is_empty());
        assert_eq!(out.failed.len(), 1);
        assert_eq!(out.failed[0].reason, "package_not_found");
    }

    #[tokio::test]
    async fn hash_mismatch_falls_into_failed() {
        let pkg_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(pkg_dir.path().join("index.js"), b"not the right content")
            .await
            .unwrap();

        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record_with_one_file("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        );

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/x@1.0.0".to_string(), pkg_dir.path().to_path_buf());

        let out = applied_patches(&manifest, &paths).await;
        assert!(out.applied.is_empty());
        assert_eq!(out.failed[0].reason, "hash_mismatch");
    }

    #[tokio::test]
    async fn missing_file_falls_into_failed() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record_with_one_file("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        );

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/x@1.0.0".to_string(), pkg_dir.path().to_path_buf());

        let out = applied_patches(&manifest, &paths).await;
        assert_eq!(out.failed[0].reason, "file_not_found");
    }

    #[tokio::test]
    async fn partial_apply_still_fails() {
        // Two files in the patch: only one is patched on disk → patch
        // is not "fully" applied → reported as failed (not_applied for
        // the second file).
        let pkg_dir = tempfile::tempdir().unwrap();
        let patched_a = b"AAA";
        let hash_a = compute_git_sha256_from_bytes(patched_a);
        let original_b = b"original-b";
        let before_b = compute_git_sha256_from_bytes(original_b);

        tokio::fs::write(pkg_dir.path().join("a.js"), patched_a)
            .await
            .unwrap();
        tokio::fs::write(pkg_dir.path().join("b.js"), original_b)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "a.js".to_string(),
            PatchFileInfo {
                before_hash: "aaaa".to_string(),
                after_hash: hash_a,
            },
        );
        files.insert(
            "b.js".to_string(),
            PatchFileInfo {
                before_hash: before_b,
                after_hash: "deadbeef".to_string(),
            },
        );

        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            PatchRecord {
                uuid: "u".to_string(),
                exported_at: String::new(),
                files,
                vulnerabilities: HashMap::new(),
                description: String::new(),
                license: String::new(),
                tier: String::new(),
            },
        );

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/x@1.0.0".to_string(), pkg_dir.path().to_path_buf());

        let out = applied_patches(&manifest, &paths).await;
        assert!(out.applied.is_empty());
        assert_eq!(out.failed[0].reason, "not_applied");
    }

    // ── Edge-case + degenerate-input coverage ─────────────────────

    /// `VerifyOutcome::default()` is the empty outcome — defaulting
    /// is used by the CLI's `--no-verify` path.
    #[test]
    fn outcome_default_is_empty() {
        let o = VerifyOutcome::default();
        assert!(o.applied.is_empty());
        assert!(o.failed.is_empty());
    }

    /// `FailedPatch` equality + clone for downstream consumers
    /// (the CLI emits these in `--json` warnings).
    #[test]
    fn failed_patch_value_semantics() {
        let a = FailedPatch {
            purl: "pkg:npm/x@1".to_string(),
            reason: "hash_mismatch".to_string(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    /// Empty manifest → empty outcome. No iteration, no panic.
    #[tokio::test]
    async fn empty_manifest_returns_empty_outcome() {
        let manifest = PatchManifest::new();
        let paths: HashMap<String, PathBuf> = HashMap::new();
        let out = applied_patches(&manifest, &paths).await;
        assert!(out.applied.is_empty());
        assert!(out.failed.is_empty());
    }

    /// A patch with `files = {}` is vacuously applied — the
    /// "all files match" predicate is `true` over an empty set.
    /// This is intentional behavior: a "patch" that touches no
    /// files is always-applied. Documented here so a future
    /// refactor that flips the predicate is forced to revisit it.
    #[tokio::test]
    async fn patch_record_with_zero_files_is_vacuously_applied() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/empty@1.0.0".to_string(),
            PatchRecord {
                uuid: "u".to_string(),
                exported_at: String::new(),
                files: HashMap::new(),
                vulnerabilities: HashMap::new(),
                description: String::new(),
                license: String::new(),
                tier: String::new(),
            },
        );

        let mut paths = HashMap::new();
        paths.insert(
            "pkg:npm/empty@1.0.0".to_string(),
            pkg_dir.path().to_path_buf(),
        );

        let out = applied_patches(&manifest, &paths).await;
        assert_eq!(out.applied, vec!["pkg:npm/empty@1.0.0".to_string()]);
        assert!(out.failed.is_empty());
    }

    /// Extra `package_paths` entries that aren't in the manifest
    /// are ignored — we iterate manifest entries, not the map.
    #[tokio::test]
    async fn extra_package_paths_are_ignored() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let patched = b"patched";
        let hash = compute_git_sha256_from_bytes(patched);
        tokio::fs::write(pkg_dir.path().join("index.js"), patched)
            .await
            .unwrap();

        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert("pkg:npm/x@1.0.0".to_string(), record_with_one_file(&hash));

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/x@1.0.0".to_string(), pkg_dir.path().to_path_buf());
        // Stray entry not in the manifest.
        paths.insert(
            "pkg:npm/stray@9.9.9".to_string(),
            pkg_dir.path().to_path_buf(),
        );

        let out = applied_patches(&manifest, &paths).await;
        assert_eq!(out.applied.len(), 1);
        assert_eq!(out.applied[0], "pkg:npm/x@1.0.0");
        assert!(out.failed.is_empty());
    }

    /// Multi-file patch where the FIRST file fails — the iteration
    /// halts after the first failure (we don't keep going to
    /// surface every reason). Lock this in so future refactors
    /// don't accidentally start running the second file's check.
    ///
    /// The patch lists two files. `a.js` has the wrong content (no
    /// match for before_hash or after_hash); `b.js` is fine. Order
    /// is non-deterministic across HashMap iteration, so we only
    /// assert "one failure reason", not which one.
    #[tokio::test]
    async fn multi_file_first_failure_short_circuits() {
        let pkg_dir = tempfile::tempdir().unwrap();
        // a.js: corrupt
        tokio::fs::write(pkg_dir.path().join("a.js"), b"garbage")
            .await
            .unwrap();
        // b.js: at the right after_hash so it would pass.
        let patched_b = b"patched-b";
        let hash_b = compute_git_sha256_from_bytes(patched_b);
        tokio::fs::write(pkg_dir.path().join("b.js"), patched_b)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "a.js".to_string(),
            PatchFileInfo {
                before_hash: "aaaa".to_string(),
                after_hash: "deadbeef".to_string(),
            },
        );
        files.insert(
            "b.js".to_string(),
            PatchFileInfo {
                before_hash: "cccc".to_string(),
                after_hash: hash_b,
            },
        );

        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            PatchRecord {
                uuid: "u".to_string(),
                exported_at: String::new(),
                files,
                vulnerabilities: HashMap::new(),
                description: String::new(),
                license: String::new(),
                tier: String::new(),
            },
        );

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/x@1.0.0".to_string(), pkg_dir.path().to_path_buf());

        let out = applied_patches(&manifest, &paths).await;
        assert!(out.applied.is_empty());
        assert_eq!(out.failed.len(), 1, "first failure must short-circuit");
        // Reason depends on iteration order, but it MUST be one of
        // the two failure tags (not the success path).
        let reason = &out.failed[0].reason;
        assert!(
            matches!(reason.as_str(), "hash_mismatch" | "not_applied"),
            "unexpected reason: {reason}"
        );
    }
}
