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
use crate::patch::vendor::state::VendorEntry;
use crate::patch::vendor::verify::verify_vendored_patch_record;

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
    /// The subset of `applied` that was attested via the committed
    /// vendor artifact (`.socket/vendor/…`) rather than the installed
    /// tree. Every member is also present in `applied`.
    pub vendored: Vec<String>,
}

/// Vendored-patch context for [`applied_patches_with_vendor`].
///
/// Built by the CLI from the committed `.socket/vendor/state.json` ledger
/// (plus the legacy `.socket/go-patches/` redirect synthesis); kept as plain
/// data so this module stays free of state-loading concerns.
#[derive(Debug, Clone, Default)]
pub struct VendorContext {
    /// Project root the vendor artifact paths are relative to.
    pub project_root: PathBuf,
    /// Vendor-state entries, keyed by manifest PURL (a manifest PURL also
    /// matches an entry whose `base_purl` equals it — qualified manifest
    /// keys resolve to the entry recorded under the base PURL).
    pub entries: HashMap<String, VendorEntry>,
    /// Legacy `apply`-redirect copies: PURL → absolute
    /// `.socket/go-patches/<module>@<version>` copy dir. These are verified
    /// with the ordinary dir-hash check (NOT the vendor artifact check —
    /// their paths live outside `.socket/vendor/`) and count as `applied`
    /// but not `vendored`.
    pub go_patches: HashMap<String, PathBuf>,
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
    applied_patches_with_vendor(manifest, package_paths, None).await
}

/// [`applied_patches`] with vendored-patch awareness.
///
/// Per-PURL precedence:
/// 1. A vendor-state entry (matched by map key or `base_purl`) means the
///    committed artifact is the SOLE evidence: success lands the PURL in
///    both `applied` and `vendored`; failure lands it in `failed` with the
///    vendor routing tag. There is deliberately no fallback to the
///    installed tree in either direction — an unpatched `node_modules` is
///    EXPECTED after vendoring and must not block attestation, and a
///    patched-looking installed tree must not launder a tampered vendor
///    artifact.
/// 2. A `go_patches` entry verifies the redirect copy dir with the normal
///    dir-hash check (`applied` only, not `vendored`); again no fallback —
///    an active redirect makes the copy dir the consumed bytes, while the
///    module cache stays pristine by design.
/// 3. Otherwise the installed-tree behavior of [`applied_patches`], verbatim.
pub async fn applied_patches_with_vendor(
    manifest: &PatchManifest,
    package_paths: &HashMap<String, PathBuf>,
    vendor: Option<&VendorContext>,
) -> VerifyOutcome {
    let mut out = VerifyOutcome::default();

    for (purl, record) in &manifest.patches {
        if let Some(ctx) = vendor {
            let entry = ctx
                .entries
                .get(purl)
                .or_else(|| ctx.entries.values().find(|e| e.base_purl == *purl));
            if let Some(entry) = entry {
                match verify_vendored_patch_record(&ctx.project_root, entry, record).await {
                    Ok(()) => {
                        out.applied.push(purl.clone());
                        out.vendored.push(purl.clone());
                    }
                    Err(reason) => out.failed.push(FailedPatch {
                        purl: purl.clone(),
                        reason,
                    }),
                }
                continue;
            }
            if let Some(copy_dir) = ctx.go_patches.get(purl) {
                match verify_patch_record(copy_dir, record).await {
                    Ok(()) => out.applied.push(purl.clone()),
                    Err(reason) => out.failed.push(FailedPatch {
                        purl: purl.clone(),
                        reason,
                    }),
                }
                continue;
            }
        }

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
///
/// A record with **no files** is *not* treated as applied. Verification
/// is the strict counterpart to `--no-verify`: it must produce positive
/// on-disk evidence before a patch is attested as `not_affected`. A
/// zero-file record offers nothing to hash, so — per the module's
/// "omit when unconfirmed" contract — it is reported as `no_files` and
/// dropped from the VEX document rather than vacuously attested.
async fn verify_patch_record(
    pkg_path: &Path,
    record: &crate::manifest::schema::PatchRecord,
) -> Result<(), String> {
    if record.files.is_empty() {
        return Err("no_files".to_string());
    }

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
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record_with_one_file("deadbeef"),
        );

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
            record_with_one_file(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
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
            record_with_one_file(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
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

    /// A patch with `files = {}` must NOT be treated as applied.
    /// Verification requires positive on-disk evidence before a patch
    /// is attested as `not_affected`; a zero-file record offers nothing
    /// to hash, so it is omitted with reason `no_files`. Attesting it as
    /// "fixed" would be an evidence-free claim, contradicting the
    /// module's "omit when unconfirmed" contract. (The `--no-verify`
    /// path, which trusts the manifest wholesale, is unaffected — it
    /// never calls this function.)
    #[tokio::test]
    async fn patch_record_with_zero_files_is_not_applied() {
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
        assert!(
            out.applied.is_empty(),
            "a zero-file patch must not be attested as applied"
        );
        assert_eq!(out.failed.len(), 1);
        assert_eq!(out.failed[0].purl, "pkg:npm/empty@1.0.0");
        assert_eq!(out.failed[0].reason, "no_files");
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

    /// A new-file patch (empty `beforeHash`) whose file exists on disk
    /// at the `afterHash` content counts as applied. `verify_file_patch`
    /// returns `AlreadyPatched` before its is-new-file `Ready` branch, so
    /// the created-and-applied case is not misreported as `not_applied`.
    #[tokio::test]
    async fn new_file_present_at_after_hash_is_applied() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let created = b"freshly-created-file";
        let hash = compute_git_sha256_from_bytes(created);
        tokio::fs::write(pkg_dir.path().join("new.js"), created)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "new.js".to_string(),
            PatchFileInfo {
                before_hash: String::new(), // new file
                after_hash: hash,
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
        assert_eq!(out.applied, vec!["pkg:npm/x@1.0.0".to_string()]);
        assert!(out.failed.is_empty());
    }

    /// A new-file patch whose file is absent on disk is `not_applied`
    /// (the creation hasn't happened yet) — NOT `file_not_found`. The
    /// empty `beforeHash` routes through the `Ready` branch.
    #[tokio::test]
    async fn new_file_absent_is_not_applied() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let mut files = HashMap::new();
        files.insert(
            "new.js".to_string(),
            PatchFileInfo {
                before_hash: String::new(), // new file, not yet created
                after_hash:
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                        .to_string(),
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

    /// A no-op patch where `beforeHash == afterHash` and the file is at
    /// that content is applied — `verify_file_patch` checks `afterHash`
    /// first, so it never mistakes the file for the un-patched `Ready`
    /// state.
    #[tokio::test]
    async fn noop_patch_before_equals_after_is_applied() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let content = b"unchanged-content";
        let hash = compute_git_sha256_from_bytes(content);
        tokio::fs::write(pkg_dir.path().join("index.js"), content)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash: hash.clone(),
                after_hash: hash,
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
        assert_eq!(out.applied, vec!["pkg:npm/x@1.0.0".to_string()]);
        assert!(out.failed.is_empty());
    }

    /// A multi-file patch where EVERY file is at its `afterHash` is
    /// applied — the loop must run to completion (no early `Ok`) and
    /// bucket the PURL into `applied`.
    #[tokio::test]
    async fn multi_file_all_patched_is_applied() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let a = b"patched-a";
        let b = b"patched-b";
        let hash_a = compute_git_sha256_from_bytes(a);
        let hash_b = compute_git_sha256_from_bytes(b);
        tokio::fs::write(pkg_dir.path().join("a.js"), a).await.unwrap();
        tokio::fs::write(pkg_dir.path().join("b.js"), b).await.unwrap();

        let mut files = HashMap::new();
        files.insert(
            "a.js".to_string(),
            PatchFileInfo { before_hash: "aaaa".to_string(), after_hash: hash_a },
        );
        files.insert(
            "b.js".to_string(),
            PatchFileInfo { before_hash: "bbbb".to_string(), after_hash: hash_b },
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
        assert_eq!(out.applied, vec!["pkg:npm/x@1.0.0".to_string()]);
        assert!(out.failed.is_empty());
    }

    /// A manifest with both an applied PURL and a failing PURL splits
    /// cleanly across the two buckets. Order is HashMap-nondeterministic,
    /// so we assert membership, not index.
    #[tokio::test]
    async fn mixed_manifest_splits_into_both_buckets() {
        let ok_dir = tempfile::tempdir().unwrap();
        let patched = b"patched-content";
        let hash = compute_git_sha256_from_bytes(patched);
        tokio::fs::write(ok_dir.path().join("index.js"), patched)
            .await
            .unwrap();

        // Failing package: file present but at the wrong content.
        let bad_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(bad_dir.path().join("index.js"), b"wrong")
            .await
            .unwrap();

        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert("pkg:npm/ok@1.0.0".to_string(), record_with_one_file(&hash));
        manifest.patches.insert(
            "pkg:npm/bad@1.0.0".to_string(),
            record_with_one_file(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
        );

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/ok@1.0.0".to_string(), ok_dir.path().to_path_buf());
        paths.insert("pkg:npm/bad@1.0.0".to_string(), bad_dir.path().to_path_buf());

        let out = applied_patches(&manifest, &paths).await;
        assert_eq!(out.applied, vec!["pkg:npm/ok@1.0.0".to_string()]);
        assert_eq!(out.failed.len(), 1);
        assert_eq!(out.failed[0].purl, "pkg:npm/bad@1.0.0");
        assert_eq!(out.failed[0].reason, "hash_mismatch");
    }

    /// SECURITY: a path-escaping manifest key (`../evil.js`) must NEVER
    /// be attested as applied — even when the out-of-tree file it points
    /// at happens to hash to the record's `afterHash`. `verify_file_patch`
    /// fail-closes on the `is_safe_relative_subpath` guard *before* reading
    /// anything, so a poisoned manifest cannot launder an arbitrary
    /// on-disk file into a `not_affected` VEX attestation.
    #[tokio::test]
    async fn path_escaping_key_is_never_applied() {
        let root = tempfile::tempdir().unwrap();
        let pkg_dir = root.path().join("pkg");
        tokio::fs::create_dir(&pkg_dir).await.unwrap();

        // An out-of-tree file whose content matches the after_hash we
        // will claim. If the guard were missing, verification would read
        // this and wrongly report the patch as applied.
        let out_of_tree = b"out-of-tree-content";
        let hash = compute_git_sha256_from_bytes(out_of_tree);
        tokio::fs::write(root.path().join("evil.js"), out_of_tree)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "../evil.js".to_string(),
            PatchFileInfo {
                before_hash: "aaaa".to_string(),
                after_hash: hash, // matches the out-of-tree file
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
        paths.insert("pkg:npm/x@1.0.0".to_string(), pkg_dir.clone());

        let out = applied_patches(&manifest, &paths).await;
        assert!(
            out.applied.is_empty(),
            "a path-escaping key must never be attested as applied"
        );
        assert_eq!(out.failed.len(), 1);
        assert_eq!(out.failed[0].reason, "file_not_found");
    }

    /// A directory sitting where the manifest expects a file is reported
    /// as `file_not_found`, not applied — `verify_file_patch` rejects
    /// non-regular files (the hashing step refuses to read a directory).
    #[tokio::test]
    async fn directory_at_file_path_is_not_applied() {
        let pkg_dir = tempfile::tempdir().unwrap();
        // Create a directory named "index.js" where a file is expected.
        tokio::fs::create_dir(pkg_dir.path().join("index.js"))
            .await
            .unwrap();

        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record_with_one_file(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
        );

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/x@1.0.0".to_string(), pkg_dir.path().to_path_buf());

        let out = applied_patches(&manifest, &paths).await;
        assert!(out.applied.is_empty());
        assert_eq!(out.failed.len(), 1);
        assert_eq!(out.failed[0].reason, "file_not_found");
    }

    /// Two independently failing PURLs each produce exactly one
    /// `FailedPatch` — the failed bucket accumulates across PURLs (one
    /// failure per PURL, not collapsed or duplicated).
    #[tokio::test]
    async fn multiple_failing_purls_each_recorded() {
        // bad1: file present at wrong content → hash_mismatch.
        let bad1 = tempfile::tempdir().unwrap();
        tokio::fs::write(bad1.path().join("index.js"), b"wrong")
            .await
            .unwrap();
        // bad2: file absent → file_not_found.
        let bad2 = tempfile::tempdir().unwrap();

        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/bad1@1.0.0".to_string(),
            record_with_one_file(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
        );
        manifest.patches.insert(
            "pkg:npm/bad2@1.0.0".to_string(),
            record_with_one_file(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
        );

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/bad1@1.0.0".to_string(), bad1.path().to_path_buf());
        paths.insert("pkg:npm/bad2@1.0.0".to_string(), bad2.path().to_path_buf());

        let out = applied_patches(&manifest, &paths).await;
        assert!(out.applied.is_empty());
        assert_eq!(out.failed.len(), 2, "one FailedPatch per failing PURL");

        let mut reasons: Vec<&str> = out.failed.iter().map(|f| f.reason.as_str()).collect();
        reasons.sort_unstable();
        assert_eq!(reasons, vec!["file_not_found", "hash_mismatch"]);
    }

    /// At most ONE `FailedPatch` is recorded per PURL even when several
    /// files would fail — `verify_patch_record` returns on the first
    /// failure. Two distinct failing files, single failure recorded.
    #[tokio::test]
    async fn at_most_one_failure_recorded_per_purl() {
        let pkg_dir = tempfile::tempdir().unwrap();
        // a.js: hash mismatch (neither before nor after).
        tokio::fs::write(pkg_dir.path().join("a.js"), b"garbage")
            .await
            .unwrap();
        // b.js: absent → would be file_not_found.

        let mut files = HashMap::new();
        files.insert(
            "a.js".to_string(),
            PatchFileInfo { before_hash: "aaaa".to_string(), after_hash: "deadbeef".to_string() },
        );
        files.insert(
            "b.js".to_string(),
            PatchFileInfo { before_hash: "bbbb".to_string(), after_hash: "deadbeef".to_string() },
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
        assert_eq!(out.failed.len(), 1, "one FailedPatch per PURL, not per file");
        assert!(
            matches!(out.failed[0].reason.as_str(), "hash_mismatch" | "file_not_found"),
            "unexpected reason: {}",
            out.failed[0].reason
        );
    }

    // ── Vendored-patch awareness (`applied_patches_with_vendor`) ──

    use crate::patch::vendor::state::{VendorArtifact, VendorEntry};

    /// Canonical-grammar patch UUID — `verify_vendored_patch_record`
    /// validates the uuid path level, so vendor fixtures must use a real
    /// uuid (unlike the `"u"` shorthand of the installed-tree tests).
    const VUUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    fn vendor_entry(purl: &str, rel_path: &str) -> VendorEntry {
        VendorEntry {
            ecosystem: "cargo".to_string(),
            base_purl: purl.to_string(),
            uuid: VUUID.to_string(),
            artifact: VendorArtifact {
                path: rel_path.to_string(),
                sha256: String::new(),
                size: None,
                platform_locked: None,
            },
            wiring: Vec::new(),
            lock: None,
            took_over_go_patches: false,
            flavor: None,
            uv: None,
        }
    }

    /// `applied_patches` must be exactly `applied_patches_with_vendor(.., None)`
    /// on a mixed fixture (one applied, one failed) — the wrapper carries the
    /// pre-vendor contract verbatim, with an empty `vendored` set.
    #[tokio::test]
    async fn wrapper_equals_with_vendor_none() {
        let ok_dir = tempfile::tempdir().unwrap();
        let patched = b"patched-content";
        let hash = compute_git_sha256_from_bytes(patched);
        tokio::fs::write(ok_dir.path().join("index.js"), patched)
            .await
            .unwrap();

        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert("pkg:npm/ok@1.0.0".to_string(), record_with_one_file(&hash));
        manifest.patches.insert(
            "pkg:npm/missing@2.0.0".to_string(),
            record_with_one_file("deadbeef"),
        );

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/ok@1.0.0".to_string(), ok_dir.path().to_path_buf());

        let a = applied_patches(&manifest, &paths).await;
        let b = applied_patches_with_vendor(&manifest, &paths, None).await;
        assert_eq!(a.applied, b.applied);
        assert_eq!(a.failed, b.failed);
        assert!(a.vendored.is_empty());
        assert!(b.vendored.is_empty());
    }

    /// Happy path: a vendor-state entry + healthy vendored dir attests the
    /// PURL with the installed tree entirely ABSENT (`package_paths` empty —
    /// the post-vendor `node_modules`-less checkout). The PURL lands in BOTH
    /// `applied` and `vendored`.
    #[tokio::test]
    async fn vendored_dir_attests_without_installed_tree() {
        let root = tempfile::tempdir().unwrap();
        let purl = "pkg:cargo/serde@1.0.0";
        let rel = format!(".socket/vendor/cargo/{VUUID}/serde-1.0.0");
        let patched = b"patched-content";
        let hash = compute_git_sha256_from_bytes(patched);
        let dir = root.path().join(&rel);
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("index.js"), patched).await.unwrap();

        let mut rec = record_with_one_file(&hash);
        rec.uuid = VUUID.to_string();
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(purl.to_string(), rec);

        let mut entries = HashMap::new();
        entries.insert(purl.to_string(), vendor_entry(purl, &rel));
        let ctx = VendorContext {
            project_root: root.path().to_path_buf(),
            entries,
            go_patches: HashMap::new(),
        };

        let paths: HashMap<String, PathBuf> = HashMap::new(); // no installed tree
        let out = applied_patches_with_vendor(&manifest, &paths, Some(&ctx)).await;
        assert_eq!(out.applied, vec![purl.to_string()]);
        assert_eq!(out.vendored, vec![purl.to_string()]);
        assert!(out.failed.is_empty());
    }

    /// A manifest PURL matches a vendor entry recorded under a different map
    /// key when `entry.base_purl` equals it (qualified-key manifests resolve
    /// to the base-PURL ledger entry).
    #[tokio::test]
    async fn vendor_entry_matched_by_base_purl() {
        let root = tempfile::tempdir().unwrap();
        let purl = "pkg:cargo/serde@1.0.0";
        let rel = format!(".socket/vendor/cargo/{VUUID}/serde-1.0.0");
        let patched = b"patched-content";
        let hash = compute_git_sha256_from_bytes(patched);
        let dir = root.path().join(&rel);
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("index.js"), patched).await.unwrap();

        let mut rec = record_with_one_file(&hash);
        rec.uuid = VUUID.to_string();
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(purl.to_string(), rec);

        // Keyed by some other (qualified) string; base_purl carries the match.
        let mut entries = HashMap::new();
        entries.insert(
            "pkg:cargo/serde@1.0.0?qualifier=x".to_string(),
            vendor_entry(purl, &rel),
        );
        let ctx = VendorContext {
            project_root: root.path().to_path_buf(),
            entries,
            go_patches: HashMap::new(),
        };

        let out =
            applied_patches_with_vendor(&manifest, &HashMap::new(), Some(&ctx)).await;
        assert_eq!(out.applied, vec![purl.to_string()]);
        assert_eq!(out.vendored, vec![purl.to_string()]);
    }

    /// Precedence, healthy direction: the installed tree still holds the
    /// UN-patched bytes (expected after vendoring — the lockfile points at
    /// the vendored copy now) while the vendor artifact is healthy. The
    /// vendor path must win: applied + vendored, no `not_applied` failure.
    #[tokio::test]
    async fn healthy_vendor_beats_unpatched_installed_tree() {
        let root = tempfile::tempdir().unwrap();
        let purl = "pkg:cargo/serde@1.0.0";
        let rel = format!(".socket/vendor/cargo/{VUUID}/serde-1.0.0");
        let original = b"original-unpatched";
        let patched = b"patched-content";
        let before = compute_git_sha256_from_bytes(original);
        let after = compute_git_sha256_from_bytes(patched);

        // Vendored copy: patched.
        let vdir = root.path().join(&rel);
        tokio::fs::create_dir_all(&vdir).await.unwrap();
        tokio::fs::write(vdir.join("index.js"), patched).await.unwrap();
        // Installed tree: still original.
        let installed = root.path().join("installed");
        tokio::fs::create_dir_all(&installed).await.unwrap();
        tokio::fs::write(installed.join("index.js"), original)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash: before,
                after_hash: after,
            },
        );
        let rec = PatchRecord {
            uuid: VUUID.to_string(),
            exported_at: String::new(),
            files,
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        };
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(purl.to_string(), rec);

        let mut entries = HashMap::new();
        entries.insert(purl.to_string(), vendor_entry(purl, &rel));
        let ctx = VendorContext {
            project_root: root.path().to_path_buf(),
            entries,
            go_patches: HashMap::new(),
        };
        let mut paths = HashMap::new();
        paths.insert(purl.to_string(), installed);

        let out = applied_patches_with_vendor(&manifest, &paths, Some(&ctx)).await;
        assert_eq!(
            out.applied,
            vec![purl.to_string()],
            "the unpatched installed tree must not block a healthy vendor attestation"
        );
        assert_eq!(out.vendored, vec![purl.to_string()]);
        assert!(out.failed.is_empty());
    }

    /// Precedence, fail-closed direction: a TAMPERED vendor artifact fails
    /// with `vendor_hash_mismatch` even though the installed tree happens to
    /// look patched — a patched-looking tree must not launder a tampered
    /// committed artifact into an attestation.
    #[tokio::test]
    async fn tampered_vendor_not_laundered_by_patched_installed_tree() {
        let root = tempfile::tempdir().unwrap();
        let purl = "pkg:cargo/serde@1.0.0";
        let rel = format!(".socket/vendor/cargo/{VUUID}/serde-1.0.0");
        let patched = b"patched-content";
        let hash = compute_git_sha256_from_bytes(patched);

        // Vendored copy: tampered.
        let vdir = root.path().join(&rel);
        tokio::fs::create_dir_all(&vdir).await.unwrap();
        tokio::fs::write(vdir.join("index.js"), b"tampered").await.unwrap();
        // Installed tree: at afterHash (would verify if consulted).
        let installed = root.path().join("installed");
        tokio::fs::create_dir_all(&installed).await.unwrap();
        tokio::fs::write(installed.join("index.js"), patched)
            .await
            .unwrap();

        let mut rec = record_with_one_file(&hash);
        rec.uuid = VUUID.to_string();
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(purl.to_string(), rec);

        let mut entries = HashMap::new();
        entries.insert(purl.to_string(), vendor_entry(purl, &rel));
        let ctx = VendorContext {
            project_root: root.path().to_path_buf(),
            entries,
            go_patches: HashMap::new(),
        };
        let mut paths = HashMap::new();
        paths.insert(purl.to_string(), installed);

        let out = applied_patches_with_vendor(&manifest, &paths, Some(&ctx)).await;
        assert!(
            out.applied.is_empty(),
            "a tampered vendor artifact must never be attested"
        );
        assert!(out.vendored.is_empty());
        assert_eq!(out.failed.len(), 1);
        assert_eq!(out.failed[0].reason, "vendor_hash_mismatch");
    }

    /// The `go_patches` map verifies the redirect copy dir with the normal
    /// dir-hash check: success → `applied` (NOT `vendored`); a stale/
    /// unpatched copy → failed. No installed-tree fallback either way.
    #[tokio::test]
    async fn go_patches_copy_dir_verifies_as_applied_not_vendored() {
        let root = tempfile::tempdir().unwrap();
        let purl = "pkg:golang/github.com/foo/bar@v1.4.2";
        let patched = b"patched-go-source";
        let hash = compute_git_sha256_from_bytes(patched);
        let copy_dir = root
            .path()
            .join(".socket/go-patches/github.com/foo/bar@v1.4.2");
        tokio::fs::create_dir_all(&copy_dir).await.unwrap();
        tokio::fs::write(copy_dir.join("index.js"), patched)
            .await
            .unwrap();

        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert(purl.to_string(), record_with_one_file(&hash));

        let mut go_patches = HashMap::new();
        go_patches.insert(purl.to_string(), copy_dir.clone());
        let ctx = VendorContext {
            project_root: root.path().to_path_buf(),
            entries: HashMap::new(),
            go_patches,
        };

        // No installed tree (module cache absent) — the redirect copy is
        // the consumed bytes.
        let out =
            applied_patches_with_vendor(&manifest, &HashMap::new(), Some(&ctx)).await;
        assert_eq!(out.applied, vec![purl.to_string()]);
        assert!(
            out.vendored.is_empty(),
            "go-patches redirects are applied, not vendored"
        );
        assert!(out.failed.is_empty());

        // Tamper the copy dir → failed with the dir-hash reason, never
        // attested.
        tokio::fs::write(copy_dir.join("index.js"), b"tampered")
            .await
            .unwrap();
        let out =
            applied_patches_with_vendor(&manifest, &HashMap::new(), Some(&ctx)).await;
        assert!(out.applied.is_empty());
        assert_eq!(out.failed.len(), 1);
        assert_eq!(out.failed[0].reason, "hash_mismatch");
    }
}
