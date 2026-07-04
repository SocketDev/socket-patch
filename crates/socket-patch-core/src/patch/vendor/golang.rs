//! The golang vendor backend: committable `replace`-directive vendoring.
//!
//! Wraps the project-local Go redirect engine
//! ([`crate::patch::go_redirect`]) with a vendor copy base: the patched module
//! copy lands under `.socket/vendor/golang/<patch-uuid>/<module>@<version>/`
//! and the `go.mod` `replace` points at it ([`ReplaceOwner::Vendor`]). A
//! directory `replace` target bypasses the module cache, sumdb, and `go.sum`
//! entirely, so a fresh checkout builds the patched module fully offline and
//! survives `go mod tidy` (spike-verified — `spikes/PHASE0-FINDINGS.txt`).
//!
//! ## Takeover of an `apply` redirect
//! `ensure_replace_entry`'s cross-owner upsert rewrites an existing
//! `.socket/go-patches/` (apply-owned) directive in place — one atomic
//! `go.mod` write repoints the build at the vendor copy with no remove+add
//! window. The stale go-patches copy is then deleted and the takeover is
//! recorded ([`VendorEntry::took_over_go_patches`]) so `--revert` can tell
//! the user the redirect is NOT restored (re-run `apply` for that).

use std::path::Path;

use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{MismatchPolicy, PatchSources};
use crate::patch::copy_tree::remove_tree;
use crate::patch::go_mod_edit::{
    self, read_replace_entries, replace_target_path, ReplaceOwner, GO_PATCHES_DIR,
};
use crate::patch::go_redirect::{
    apply_go_redirect, are_safe_redirect_coords, copy_dir_for, ensure_module_go_mod,
};
use crate::utils::purl::{parse_golang_purl, strip_purl_qualifiers};

use super::common::{
    already_patched_result, copy_matches_after_hashes, done, failed_result, refused,
    service_offline_conflict,
};
use super::path::vendor_uuid_dir_rel;
use super::registry_fetch::extract_zip_with_prefix;
use super::service_fetch::{fetch_verified_archive, ServiceArtifact};
use super::state::{
    write_marker, VendorArtifact, VendorEntry, VendorMarker, WiringAction, WiringRecord,
};
use super::{RevertOutcome, VendorOutcome, VendorServiceConfig, VendorWarning};

/// Vendor one Go module: patched copy in the uuid dir + a vendor-owned
/// `replace` directive + marker, returning the ledger entry to persist.
///
/// * `pristine_src` — the crawler's module-cache dir (case-encoded on disk).
///   It is copied, never mutated.
/// * `vendored_at` — caller-formatted RFC3339 timestamp for the marker.
///
/// `dry_run` writes nothing (read-only verify against `pristine_src`);
/// `entry` is then `None`. A user-authored `replace` for the same
/// module+version surfaces as a failed result (the engine's `go.mod` editor
/// refuses it), not a refusal — the verify report is still useful.
#[allow(clippy::too_many_arguments)]
pub async fn vendor_go_module(
    purl: &str,
    pristine_src: &Path,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
    service: Option<&VendorServiceConfig>,
) -> VendorOutcome {
    // ── coordinate validation (fail-closed, before any disk access) ──────
    let Some((module, version)) = parse_golang_purl(purl) else {
        return refused("unsafe_coordinates", format!("not a golang purl: {purl}"));
    };
    // SECURITY: `module`+`version` key the on-disk copy dir
    // (`.socket/vendor/golang/<uuid>/<module>@<version>/`) and the `replace`
    // target path. A `..` segment / absolute path / backslash from a tampered
    // manifest PURL would let the copy escape `.socket/vendor/` — refuse
    // before any disk access (same guard the redirect engine applies).
    if !are_safe_redirect_coords(module, version) {
        return refused(
            "unsafe_coordinates",
            format!(
                "refusing to vendor unsafe golang coordinates `{module}`/`{version}` \
                 (a `..` segment, absolute path, or separator would escape \
                 .socket/vendor/golang/)"
            ),
        );
    }
    // SECURITY: the uuid is a dedicated path level created here and deleted by
    // `--revert`; anything but the canonical UUID grammar is rejected.
    let Some(base_rel) = vendor_uuid_dir_rel("golang", &record.uuid) else {
        return refused(
            "unsafe_coordinates",
            format!(
                "refusing to vendor {purl}: patch uuid `{}` is not a canonical uuid",
                record.uuid
            ),
        );
    };

    // Detect an existing socket-owned directive BEFORE the engine rewrites it:
    // a go-patches owner means vendor is taking over an `apply` redirect; any
    // prior socket path becomes the wiring record's `original`.
    let prior = read_replace_entries(project_root)
        .await
        .into_iter()
        .find(|e| e.module == module && e.socket_owned());
    let takeover = prior
        .as_ref()
        .is_some_and(|e| e.owner == Some(ReplaceOwner::GoPatches));
    let prior_path = prior.as_ref().and_then(|e| e.path.clone());

    // Re-run shape detection: the replace already points at THIS uuid's copy.
    // The engine rebuilds a missing/stale copy and its replace upsert is a
    // byte-stable no-op, so a wired re-run must return `entry: None` — the
    // first run's ledger entry holds the only pre-vendor original, and the
    // `prior_path` recorded here would be our own vendored pointer.
    let wired =
        prior_path.as_deref() == Some(replace_target_path(&base_rel, module, version).as_str());
    let copy_dir = copy_dir_for(project_root, &base_rel, module, version);
    let copy_was_ok = wired && copy_matches_after_hashes(&copy_dir, &record.files).await;

    let mut warnings: Vec<VendorWarning> = Vec::new();
    if let Some(refusal) = service_offline_conflict(service) {
        return refusal;
    }

    // Acquire the patched module: prefer the prebuilt module zip from the patch
    // service (download → verify → extract → wire the `replace`, no pristine
    // source needed); else let the engine copy the pristine source, patch it,
    // and wire the `replace`.
    let result = match go_service_redirect(
        service,
        record,
        module,
        version,
        &base_rel,
        &copy_dir,
        project_root,
        &mut warnings,
    )
    .await
    {
        GoServiceRedirect::Used => {
            // No local apply to verify (the downloaded zip IS the patched
            // module), so every patched file reads as `AlreadyPatched` — trust
            // is the verified service integrity (sha512 + the `h1:` dirhash).
            already_patched_result(purl, &copy_dir, &record.files)
        }
        GoServiceRedirect::HardFail(outcome) => return *outcome,
        GoServiceRedirect::FallBack => {
            // Vendor auto-force policy (the engine's copy is staged from the
            // pristine source, never the user's tree — see `force_apply_staged`):
            // missing patch targets still fail closed unless the caller's own
            // `--force` asked for the skip tolerance, then the engine apply runs
            // forced so a beforeHash mismatch (already-applied module, or a
            // patch built against different bytes) overwrites with the verified
            // patched content. The engine is shared with the in-place `apply`
            // redirect path, whose strict semantics stay unchanged.
            if !force {
                let missing =
                    super::missing_existing_patch_files(pristine_src, &record.files).await;
                if let Some(first) = missing.first() {
                    return done(
                        failed_result(
                            purl,
                            Path::new(""),
                            format!("Cannot apply patch: {first} - File not found"),
                        ),
                        None,
                        warnings,
                    );
                }
            }
            // The engine does the heavy lifting: fresh copy → hardened apply
            // pipeline → `replace` upsert (refuses a user-authored same-version
            // pin).
            let result = apply_go_redirect(
                purl,
                module,
                version,
                pristine_src,
                project_root,
                &base_rel,
                &record.files,
                sources,
                Some(&record.uuid),
                dry_run,
                MismatchPolicy::Force,
            )
            .await;
            if result.success {
                warnings.extend(super::mismatch_overwrite_warnings(&result, module, version));
            }
            result
        }
    };

    if dry_run {
        return done(result, None, warnings);
    }
    if !result.success {
        // The engine already rolled back a half-built copy, but its rollback
        // removes only the module leaf — clear the whole uuid dir so no empty
        // path husks (or a copy left by a failed `replace` upsert) linger
        // under `.socket/vendor/golang/`.
        let _ = remove_tree(&project_root.join(&base_rel)).await;
        return done(result, None, warnings);
    }
    // A patch with no files is a no-op success: the engine wrote no copy and
    // no `replace`, so there is nothing to record or mark.
    if record.files.is_empty() {
        return done(result, None, warnings);
    }

    if wired {
        // Already wired to this uuid: either the engine's in-sync hot path
        // (copy intact) or an artifact-only rebuild (copy was missing/stale).
        // Never re-record the ledger entry.
        if !copy_was_ok {
            // A wholesale-deleted uuid dir lost the informational marker;
            // restore it alongside the rebuilt copy (never a trust input —
            // a failed write only warns).
            let marker =
                VendorMarker::new("golang", strip_purl_qualifiers(purl), record, vendored_at);
            if let Err(e) = write_marker(&project_root.join(&base_rel), &marker).await {
                warnings.push(VendorWarning::new(
                    "marker_write_failed",
                    format!("could not write the vendor marker: {e}"),
                ));
            }
            warnings.push(VendorWarning::new(
                "vendor_artifact_rebuilt",
                format!(
                    "the committed vendored copy for {module}@{version} was missing or \
                     stale; rebuilt under {base_rel} (go.mod untouched)"
                ),
            ));
        }
        return done(result, None, warnings);
    }

    if takeover {
        // The `replace` line was already atomically repointed by the upsert;
        // the apply backend's copy is now unreachable — delete it (built from
        // OUR validated coordinates, never from the go.mod string). NotFound
        // is fine (the user may have cleaned it already).
        let stale = copy_dir_for(project_root, GO_PATCHES_DIR, module, version);
        let _ = remove_tree(&stale).await;
        // Prune now-empty parent husks (`<go-patches>/example.com/`) up to
        // and including the go-patches root. `remove_dir` is non-recursive:
        // a parent still holding another module's copy fails harmlessly.
        let go_patches_root = project_root.join(GO_PATCHES_DIR);
        let mut parent = stale.parent().map(|p| p.to_path_buf());
        while let Some(dir) = parent {
            if !dir.starts_with(&go_patches_root) || dir < go_patches_root {
                break;
            }
            if tokio::fs::remove_dir(&dir).await.is_err() {
                break; // non-empty (or already gone) — stop pruning
            }
            parent = dir.parent().map(|p| p.to_path_buf());
        }
        let _ = tokio::fs::remove_dir(&go_patches_root).await;
        warnings.push(VendorWarning::new(
            "vendor_takeover",
            format!(
                "took over the `.socket/go-patches/` redirect for `{module}`; \
                 `socket-patch apply` will restore it after `vendor --revert`"
            ),
        ));
    }

    // ── marker + ledger entry ─────────────────────────────────────────────
    let base_purl = strip_purl_qualifiers(purl).to_string();
    let marker = VendorMarker::new("golang", &base_purl, record, vendored_at);
    if let Err(e) = write_marker(&project_root.join(&base_rel), &marker).await {
        // The marker is belt-and-braces metadata (never a trust input); a
        // failed write must not undo a fully-wired vendor — surface it.
        warnings.push(VendorWarning::new(
            "marker_write_failed",
            format!("could not write the vendor marker: {e}"),
        ));
    }

    let entry = VendorEntry {
        ecosystem: "golang".to_string(),
        base_purl,
        uuid: record.uuid.clone(),
        artifact: VendorArtifact {
            path: format!("{base_rel}/{module}@{version}"),
            sha256: String::new(), // dir-shaped: integrity is per-file afterHashes
            size: None,
            platform_locked: None,
        },
        wiring: vec![WiringRecord {
            file: "go.mod".to_string(),
            kind: "go_replace".to_string(),
            // Rewritten whenever ANY socket-owned directive pre-existed (the
            // go-patches takeover, or a re-vendor refreshing an older uuid).
            action: if prior_path.is_some() {
                WiringAction::Rewritten
            } else {
                WiringAction::Added
            },
            key: Some(module.to_string()),
            original: prior_path.map(serde_json::Value::from),
            new: Some(serde_json::Value::from(replace_target_path(
                &base_rel, module, version,
            ))),
        }],
        lock: None,
        took_over_go_patches: takeover,
        detached: false,
        record: None,
        flavor: None,
        uv: None,
        pnpm: None,
        poetry: None,
        pdm: None,
        pipenv: None,
    };

    done(result, Some(entry), warnings)
}

/// Outcome of attempting to materialise the go copy from the patch service.
enum GoServiceRedirect {
    /// The prebuilt module zip was extracted and the `replace` wired.
    Used,
    /// Bubble this terminal outcome (boxed — `VendorOutcome` is large).
    HardFail(Box<VendorOutcome>),
    /// Fall back to copying + patching the pristine module source.
    FallBack,
}

/// Download the prebuilt module zip, verify it (sha512 + the `h1:` dirhash,
/// done by `fetch_verified_archive`), extract it into `copy_dir` (stripping its
/// `{module}@{version}/` prefix), ensure a `go.mod`, and wire the `replace`
/// directive — the same end state `apply_go_redirect` produces, minus the copy
/// + local apply. Maps each service outcome onto the `auto` / `service` policy.
#[allow(clippy::too_many_arguments)]
async fn go_service_redirect(
    service: Option<&VendorServiceConfig>,
    record: &PatchRecord,
    module: &str,
    version: &str,
    base_rel: &str,
    copy_dir: &Path,
    project_root: &Path,
    warnings: &mut Vec<VendorWarning>,
) -> GoServiceRedirect {
    let Some(cfg) = service else {
        return GoServiceRedirect::FallBack;
    };
    // An empty-files patch is a degenerate no-op; let the engine's empty
    // handling deal with it rather than downloading anything.
    if !cfg.service_enabled() || record.files.is_empty() {
        return GoServiceRedirect::FallBack;
    }
    fn hard(code: &'static str, detail: String) -> GoServiceRedirect {
        GoServiceRedirect::HardFail(Box::new(refused(code, detail)))
    }
    let miss = |warnings: &mut Vec<VendorWarning>, code: &'static str, reason: String| {
        if cfg.source.requires_service() {
            hard("vendor_prebuilt_required", reason)
        } else {
            warnings.push(VendorWarning::new(
                code,
                format!("{reason}; building locally instead"),
            ));
            GoServiceRedirect::FallBack
        }
    };
    match fetch_verified_archive(cfg, &record.uuid).await {
        ServiceArtifact::Ready(archive) => {
            // Clean copy dir; extract the module zip (strip its literal
            // `{module}@{version}/` prefix) into it.
            let _ = remove_tree(copy_dir).await;
            if let Err(e) = tokio::fs::create_dir_all(copy_dir).await {
                return hard(
                    "vendor_prebuilt_write_failed",
                    format!("cannot create {}: {e}", copy_dir.display()),
                );
            }
            let prefix = format!("{module}@{version}/");
            if let Err(e) = extract_zip_with_prefix(&archive.bytes, copy_dir, &prefix) {
                let _ = remove_tree(&project_root.join(base_rel)).await;
                return hard(
                    "vendor_prebuilt_extract_failed",
                    format!("cannot extract the prebuilt module zip: {e}"),
                );
            }
            // A `replace` target needs a go.mod declaring the module path;
            // pre-modules zips may lack one — synthesize the minimal form.
            if let Err(e) = ensure_module_go_mod(copy_dir, module).await {
                let _ = remove_tree(&project_root.join(base_rel)).await;
                return hard(
                    "vendor_prebuilt_write_failed",
                    format!("cannot synthesize go.mod for the copy: {e}"),
                );
            }
            if let Err(e) =
                go_mod_edit::ensure_replace_entry(project_root, module, version, base_rel, false)
                    .await
            {
                let _ = remove_tree(&project_root.join(base_rel)).await;
                return hard(
                    "vendor_prebuilt_wire_failed",
                    format!("failed to update go.mod: {e}"),
                );
            }
            warnings.push(VendorWarning::new(
                "vendor_prebuilt_downloaded",
                format!(
                    "vendored {module} from the patch service ({})",
                    archive.source_url
                ),
            ));
            GoServiceRedirect::Used
        }
        ServiceArtifact::IntegrityMismatch(reason) => miss(
            warnings,
            "vendor_prebuilt_integrity_mismatch",
            format!("prebuilt module zip failed integrity ({reason})"),
        ),
        ServiceArtifact::Pending => miss(
            warnings,
            "vendor_prebuilt_pending",
            "prebuilt module zip is still building".to_string(),
        ),
        ServiceArtifact::Unavailable(reason) => {
            if cfg.source.requires_service() {
                hard(
                    "vendor_prebuilt_required",
                    format!("prebuilt module zip unavailable: {reason}"),
                )
            } else {
                GoServiceRedirect::FallBack
            }
        }
        ServiceArtifact::Failed(reason) => miss(
            warnings,
            "vendor_prebuilt_unavailable",
            format!("patch service request failed ({reason})"),
        ),
    }
}

/// Revert one vendored Go module: drop the vendor-owned `replace` directive
/// and remove the uuid dir. A taken-over go-patches redirect is **not**
/// restored (warned: re-run `socket-patch apply`).
pub async fn revert_go_vendor(
    entry: &VendorEntry,
    project_root: &Path,
    dry_run: bool,
) -> RevertOutcome {
    // SECURITY: the coordinates and uuid come from a committed, tamper-able
    // state.json and key a directory we are about to delete — re-validate
    // fail-closed before any disk access (mirrors the vendor-side guard).
    let Some(base_rel) = vendor_uuid_dir_rel("golang", &entry.uuid) else {
        return RevertOutcome::failed(format!(
            "refusing to revert: `{}` is not a canonical patch uuid",
            entry.uuid
        ));
    };
    let Some((module, version)) = parse_golang_purl(&entry.base_purl) else {
        return RevertOutcome::failed(format!("not a golang purl: {}", entry.base_purl));
    };
    if !are_safe_redirect_coords(module, version) {
        return RevertOutcome::failed(format!(
            "refusing to revert unsafe golang coordinates `{module}`/`{version}`"
        ));
    }

    let mut out = RevertOutcome::ok();

    // Owner-filtered: a go-patches or user-authored directive for the same
    // module is never touched here.
    if let Err(e) =
        go_mod_edit::drop_replace_entry(project_root, module, ReplaceOwner::Vendor, dry_run).await
    {
        return RevertOutcome::failed(format!("failed to update go.mod: {e}"));
    }

    if !dry_run {
        let uuid_dir = project_root.join(&base_rel);
        let _ = remove_tree(&uuid_dir).await; // ignore NotFound
                                              // Best-effort: prune the now-empty `.socket/vendor/golang/` level so a
                                              // fully-reverted project carries no vendor residue (`save_state` then
                                              // prunes `.socket/vendor/` itself). `remove_dir` fails on non-empty.
        if let Some(eco_dir) = uuid_dir.parent() {
            let _ = tokio::fs::remove_dir(eco_dir).await;
        }
    }

    if entry.took_over_go_patches {
        out.warnings.push(VendorWarning::new(
            "takeover_not_restored",
            format!(
                "the `.socket/go-patches/` redirect for `{module}` that vendoring \
                 took over was not restored; run `socket-patch apply` to restore it"
            ),
        ));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::{PatchFileInfo, VulnerabilityInfo};
    use crate::patch::apply::ApplyResult;
    use crate::patch::vendor::state::VENDOR_MARKER_FILE;
    use std::collections::HashMap;
    use std::path::PathBuf;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const PRISTINE: &[u8] = b"package bar\n\nfunc Hello() string { return \"hi\" }\n";
    const PATCHED: &[u8] = b"package bar\n\nfunc Hello() string { return \"patched\" }\n";
    const MODULE: &str = "github.com/foo/bar";
    const VERSION: &str = "v1.4.2";
    const PURL: &str = "pkg:golang/github.com/foo/bar@v1.4.2";

    fn git_sha(bytes: &[u8]) -> String {
        compute_git_sha256_from_bytes(bytes)
    }

    fn copy_rel() -> String {
        format!(".socket/vendor/golang/{UUID}/{MODULE}@{VERSION}")
    }

    fn record_with(files: HashMap<String, PatchFileInfo>) -> PatchRecord {
        let mut vulnerabilities = HashMap::new();
        vulnerabilities.insert(
            "GHSA-xxxx-yyyy-zzzz".to_string(),
            VulnerabilityInfo {
                cves: vec!["CVE-2026-0001".into()],
                summary: "s".into(),
                severity: "high".into(),
                description: "d".into(),
            },
        );
        PatchRecord {
            uuid: UUID.into(),
            exported_at: "t".into(),
            files,
            vulnerabilities,
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    /// Build a pristine module-cache-style dir, a blobs dir carrying the
    /// patched bytes, and a consumer project go.mod. Returns
    /// (tmp, blobs, pristine, record).
    async fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PatchRecord) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();

        let pristine = root.join("cache/github.com/foo/bar@v1.4.2");
        tokio::fs::create_dir_all(&pristine).await.unwrap();
        tokio::fs::write(pristine.join("bar.go"), PRISTINE)
            .await
            .unwrap();
        tokio::fs::write(
            pristine.join("go.mod"),
            "module github.com/foo/bar\n\ngo 1.21\n",
        )
        .await
        .unwrap();

        let after = git_sha(PATCHED);
        let blobs = root.join(".socket/blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        tokio::fs::write(blobs.join(&after), PATCHED).await.unwrap();

        let mut files = HashMap::new();
        files.insert(
            "package/bar.go".to_string(),
            PatchFileInfo {
                before_hash: git_sha(PRISTINE),
                after_hash: after,
            },
        );

        tokio::fs::write(
            root.join("go.mod"),
            "module example.com/app\n\ngo 1.21\n\nrequire github.com/foo/bar v1.4.2\n",
        )
        .await
        .unwrap();

        (dir, blobs, pristine, record_with(files))
    }

    async fn run_vendor(
        purl: &str,
        root: &Path,
        blobs: &Path,
        pristine: &Path,
        record: &PatchRecord,
        dry_run: bool,
    ) -> VendorOutcome {
        let sources = PatchSources::blobs_only(blobs);
        vendor_go_module(
            purl,
            pristine,
            root,
            record,
            &sources,
            "2026-06-09T00:00:00Z",
            dry_run,
            false,
            None,
        )
        .await
    }

    fn expect_done(
        outcome: VendorOutcome,
    ) -> (ApplyResult, Option<VendorEntry>, Vec<VendorWarning>) {
        match outcome {
            VendorOutcome::Done {
                result,
                entry,
                warnings,
            } => (result, entry, warnings),
            VendorOutcome::Refused { code, detail } => {
                panic!("expected Done, got Refused({code}): {detail}")
            }
        }
    }

    fn expect_refused(outcome: VendorOutcome, want_code: &str) -> String {
        match outcome {
            VendorOutcome::Refused { code, detail } => {
                assert_eq!(code, want_code, "refusal code: {detail}");
                detail
            }
            VendorOutcome::Done { result, .. } => {
                panic!(
                    "expected Refused({want_code}), got Done (success={})",
                    result.success
                )
            }
        }
    }

    #[tokio::test]
    async fn test_happy_path_wires_copy_replace_and_marker() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        // A qualified PURL must collapse to the base in the ledger/marker.
        let qualified = format!("{PURL}?type=module");
        let (result, entry, warnings) =
            expect_done(run_vendor(&qualified, root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");

        // Copy holds the patched bytes inside the uuid dir.
        let copy = root.join(copy_rel());
        assert_eq!(tokio::fs::read(copy.join("bar.go")).await.unwrap(), PATCHED);
        assert!(copy.join("go.mod").exists());
        // The module cache pristine is untouched.
        assert_eq!(
            tokio::fs::read(pristine.join("bar.go")).await.unwrap(),
            PRISTINE
        );

        // The replace directive is vendor-owned and points at the uuid path.
        let entries = read_replace_entries(root).await;
        let e = entries.iter().find(|e| e.module == MODULE).unwrap();
        assert_eq!(e.owner, Some(ReplaceOwner::Vendor));
        assert_eq!(
            e.path.as_deref(),
            Some(format!("./{}", copy_rel()).as_str())
        );
        assert_eq!(e.version.as_deref(), Some(VERSION));

        // Marker sits in the uuid dir, carrying the vuln + uuid + base purl.
        let marker = tokio::fs::read_to_string(
            root.join(format!(".socket/vendor/golang/{UUID}/{VENDOR_MARKER_FILE}")),
        )
        .await
        .unwrap();
        assert!(marker.contains(UUID));
        assert!(marker.contains("GHSA-xxxx-yyyy-zzzz"));
        assert!(
            marker.contains(&format!("\"purl\": \"{PURL}\"")),
            "{marker}"
        );

        // Ledger entry shape.
        let entry = entry.expect("entry on success");
        assert_eq!(entry.ecosystem, "golang");
        assert_eq!(entry.base_purl, PURL, "qualifiers stripped");
        assert_eq!(entry.uuid, UUID);
        assert_eq!(entry.artifact.path, copy_rel());
        assert_eq!(entry.artifact.sha256, "", "dir-shaped artifact");
        assert!(!entry.took_over_go_patches);
        assert_eq!(entry.lock, None);
        assert_eq!(entry.wiring.len(), 1);
        let w = &entry.wiring[0];
        assert_eq!((w.file.as_str(), w.kind.as_str()), ("go.mod", "go_replace"));
        assert_eq!(w.action, WiringAction::Added);
        assert_eq!(w.key.as_deref(), Some(MODULE));
        assert_eq!(w.original, None);
        assert_eq!(
            w.new,
            Some(serde_json::Value::from(format!("./{}", copy_rel())))
        );
    }

    #[tokio::test]
    async fn test_takeover_repoints_replace_and_removes_stale_redirect() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        // Pre-seed an `apply` redirect through the engine itself.
        let sources = PatchSources::blobs_only(&blobs);
        let pre = apply_go_redirect(
            PURL,
            MODULE,
            VERSION,
            &pristine,
            root,
            GO_PATCHES_DIR,
            &record.files,
            &sources,
            Some(UUID),
            false,
            MismatchPolicy::Warn,
        )
        .await;
        assert!(pre.success, "fixture redirect failed: {:?}", pre.error);
        let stale = root.join(".socket/go-patches/github.com/foo/bar@v1.4.2");
        assert!(stale.exists());

        let (result, entry, warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(
            warnings.iter().any(|w| w.code == "vendor_takeover"),
            "takeover surfaced: {warnings:?}"
        );
        assert!(!stale.exists(), "stale go-patches copy removed");

        // Exactly ONE directive for the module, now vendor-owned.
        let entries = read_replace_entries(root).await;
        let mine: Vec<_> = entries.iter().filter(|e| e.module == MODULE).collect();
        assert_eq!(
            mine.len(),
            1,
            "single directive after takeover: {entries:?}"
        );
        assert_eq!(mine[0].owner, Some(ReplaceOwner::Vendor));

        let entry = entry.unwrap();
        assert!(entry.took_over_go_patches);
        let w = &entry.wiring[0];
        assert_eq!(w.action, WiringAction::Rewritten);
        assert_eq!(
            w.original,
            Some(serde_json::Value::from(
                "./.socket/go-patches/github.com/foo/bar@v1.4.2"
            )),
            "the old replace target is recorded verbatim"
        );
    }

    /// Wired go.mod with a deleted committed copy: the module copy is
    /// rebuilt, go.mod stays byte-identical, no fresh ledger entry.
    #[tokio::test]
    async fn test_wired_missing_copy_rebuilds_artifact_only() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);

        let copy = root.join(copy_rel()).join("bar.go");
        let gomod = root.join("go.mod");
        let copy1 = tokio::fs::read(&copy).await.unwrap();
        let mod1 = tokio::fs::read(&gomod).await.unwrap();

        remove_tree(&root.join(copy_rel())).await.unwrap();

        let (result, entry, warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(
            entry.is_none(),
            "artifact-only rebuild must not re-record (prior_path is our own \
             vendored pointer here, not a pre-vendor original)"
        );
        assert!(
            warnings.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
            "rebuild is surfaced: {warnings:?}"
        );
        assert_eq!(
            tokio::fs::read(&copy).await.unwrap(),
            copy1,
            "rebuilt copy carries the patched bytes"
        );
        assert_eq!(
            tokio::fs::read(&gomod).await.unwrap(),
            mod1,
            "go.mod byte-stable across the rebuild"
        );
    }

    #[tokio::test]
    async fn test_idempotent_rerun_is_byte_stable() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);

        let copy = root.join(copy_rel()).join("bar.go");
        let gomod = root.join("go.mod");
        let copy1 = tokio::fs::read(&copy).await.unwrap();
        let mod1 = tokio::fs::read(&gomod).await.unwrap();

        let (result, entry, warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success);
        assert!(
            result.files_patched.is_empty(),
            "in-sync re-run patches nothing"
        );
        assert!(
            entry.is_none(),
            "an in-sync re-run records no entry — the first run's ledger \
             entry holds the only pre-vendor original"
        );
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(
            tokio::fs::read(&copy).await.unwrap(),
            copy1,
            "copy unchanged"
        );
        assert_eq!(
            tokio::fs::read(&gomod).await.unwrap(),
            mod1,
            "go.mod byte-stable"
        );
    }

    #[tokio::test]
    async fn test_dry_run_writes_nothing() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let gomod_before = tokio::fs::read_to_string(root.join("go.mod"))
            .await
            .unwrap();

        let (result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, true).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_none(), "dry-run emits no entry");
        assert!(!root.join(format!(".socket/vendor/golang/{UUID}")).exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join("go.mod"))
                .await
                .unwrap(),
            gomod_before,
            "go.mod untouched"
        );
    }

    #[tokio::test]
    async fn test_user_replace_conflict_fails_without_litter() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        // A user-authored replace pins the same module+version: the engine's
        // go.mod editor refuses, surfacing as a failed result (not a refusal).
        tokio::fs::write(
            root.join("go.mod"),
            "module example.com/app\n\ngo 1.21\n\nrequire github.com/foo/bar v1.4.2\n\nreplace github.com/foo/bar v1.4.2 => ../fork\n",
        )
        .await
        .unwrap();
        let gomod_before = tokio::fs::read_to_string(root.join("go.mod"))
            .await
            .unwrap();

        let (result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(!result.success);
        assert!(entry.is_none());
        // go.mod untouched and the failed copy fully unwound (no uuid husks).
        assert_eq!(
            tokio::fs::read_to_string(root.join("go.mod"))
                .await
                .unwrap(),
            gomod_before
        );
        assert!(!root.join(format!(".socket/vendor/golang/{UUID}")).exists());
    }

    #[tokio::test]
    async fn test_revert_round_trip() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let (_result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        let entry = entry.unwrap();

        let out = revert_go_vendor(&entry, root, false).await;
        assert!(out.success, "{:?}", out.error);
        assert!(out.warnings.is_empty(), "{:?}", out.warnings);

        // Directive gone, the user's require survives.
        assert!(read_replace_entries(root).await.is_empty());
        assert!(tokio::fs::read_to_string(root.join("go.mod"))
            .await
            .unwrap()
            .contains("require github.com/foo/bar v1.4.2"));
        // The uuid dir is gone, and the empty eco level pruned with it.
        assert!(!root.join(format!(".socket/vendor/golang/{UUID}")).exists());
        assert!(!root.join(".socket/vendor/golang").exists());
    }

    #[tokio::test]
    async fn test_revert_does_not_restore_go_patches() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        // Vendor takes over an apply redirect, then is reverted.
        let sources = PatchSources::blobs_only(&blobs);
        apply_go_redirect(
            PURL,
            MODULE,
            VERSION,
            &pristine,
            root,
            GO_PATCHES_DIR,
            &record.files,
            &sources,
            Some(UUID),
            false,
            MismatchPolicy::Warn,
        )
        .await;
        let (_result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        let entry = entry.unwrap();
        assert!(entry.took_over_go_patches);

        let out = revert_go_vendor(&entry, root, false).await;
        assert!(out.success, "{:?}", out.error);
        assert!(
            out.warnings
                .iter()
                .any(|w| w.code == "takeover_not_restored"),
            "{:?}",
            out.warnings
        );
        // Neither the vendor directive nor the go-patches one remains: the
        // module is back on the pristine cache until `apply` is re-run.
        assert!(read_replace_entries(root).await.is_empty());
        assert!(!root
            .join(".socket/go-patches/github.com/foo/bar@v1.4.2")
            .exists());
    }

    // ── filesystem-safety: coordinate traversal ──────────────────────────

    /// SECURITY regression: tampered manifest coordinates must be refused
    /// before any disk access — no copy outside `.socket/vendor/golang/`, no
    /// go.mod edit.
    #[tokio::test]
    async fn test_refuses_traversal_coordinates() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let gomod_before = tokio::fs::read_to_string(root.join("go.mod"))
            .await
            .unwrap();
        let escaped = root.parent().unwrap().join("escape@v1.0.0");
        let _ = remove_tree(&escaped).await;

        expect_refused(
            run_vendor(
                "pkg:golang/../../../escape@v1.0.0",
                root,
                &blobs,
                &pristine,
                &record,
                false,
            )
            .await,
            "unsafe_coordinates",
        );
        expect_refused(
            run_vendor(
                "pkg:golang/github.com/foo/bar@../../../evil",
                root,
                &blobs,
                &pristine,
                &record,
                false,
            )
            .await,
            "unsafe_coordinates",
        );
        expect_refused(
            run_vendor(
                "pkg:cargo/not-golang@1.0.0",
                root,
                &blobs,
                &pristine,
                &record,
                false,
            )
            .await,
            "unsafe_coordinates",
        );
        assert!(!escaped.exists(), "no copy outside the project");
        assert_eq!(
            tokio::fs::read_to_string(root.join("go.mod"))
                .await
                .unwrap(),
            gomod_before,
            "go.mod untouched"
        );
        let _ = remove_tree(&escaped).await;
    }

    /// SECURITY regression: a poisoned record uuid (`..`, traversal,
    /// uppercase) must be refused — it keys the dir vendor creates and
    /// `--revert` deletes.
    #[tokio::test]
    async fn test_refuses_poisoned_uuid() {
        let (dir, blobs, pristine, mut record) = fixture().await;
        let root = dir.path();
        for bad in ["..", "../../../etc", "9F6B2C4E-1D3A-4F6B-8C2D-7E5A9B1C3D5F"] {
            record.uuid = bad.to_string();
            let detail = expect_refused(
                run_vendor(PURL, root, &blobs, &pristine, &record, false).await,
                "unsafe_coordinates",
            );
            assert!(detail.contains("uuid"), "{detail}");
        }
        assert!(
            read_replace_entries(root).await.is_empty(),
            "go.mod untouched"
        );
    }

    /// SECURITY regression: revert re-validates the (tamper-able) ledger entry
    /// fail-closed rather than `remove_tree`-ing a poisoned path.
    #[tokio::test]
    async fn test_revert_refuses_traversal_entry() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let (_result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        let good = entry.unwrap();

        let mut bad_uuid = good.clone();
        bad_uuid.uuid = "../../../precious".to_string();
        assert!(!revert_go_vendor(&bad_uuid, root, false).await.success);

        let mut bad_purl = good.clone();
        bad_purl.base_purl = "pkg:golang/../../../escape@v1.0.0".to_string();
        assert!(!revert_go_vendor(&bad_purl, root, false).await.success);

        // The refusals deleted nothing: the vendored state is fully intact.
        assert!(root.join(copy_rel()).exists());
        assert!(read_replace_entries(root)
            .await
            .iter()
            .any(|e| e.module == MODULE && e.owner == Some(ReplaceOwner::Vendor)));
    }

    #[tokio::test]
    async fn test_empty_files_is_noop() {
        let (dir, blobs, pristine, mut record) = fixture().await;
        let root = dir.path();
        record.files = HashMap::new();
        let (result, entry, warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success);
        assert!(entry.is_none(), "nothing vendored, nothing recorded");
        assert!(warnings.is_empty());
        assert!(
            read_replace_entries(root).await.is_empty(),
            "no replace written"
        );
        assert!(!root.join(format!(".socket/vendor/golang/{UUID}")).exists());
    }

    // ─────────────── service-download path (Tier B: golang) ───────────────
    //
    // golang vendors a patched module DIRECTORY behind a go.mod `replace`, so
    // the service path downloads the prebuilt module zip, verifies it (sha512 +
    // the `h1:` dirhash), extracts it into the copy dir, and wires the replace.

    use crate::api::client::{ApiClient, ApiClientOptions};
    use crate::patch::vendor::{VendorServiceConfig, VendorSource};

    fn sri_sha512(bytes: &[u8]) -> String {
        use base64::Engine as _;
        use sha2::{Digest as _, Sha512};
        format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
        )
    }

    fn go_service_cfg(uri: &str, source: VendorSource, offline: bool) -> VendorServiceConfig {
        VendorServiceConfig {
            source,
            client: Some(ApiClient::new(ApiClientOptions {
                api_url: uri.to_string(),
                api_token: Some("sktsec_placeholder_value_for_tests_api".into()),
                use_public_proxy: false,
                org_slug: Some("acme".into()),
            })),
            use_public_proxy: false,
            vendor_url: None,
            patch_server_url: None,
            offline,
        }
    }

    /// Build a Go module zip (entries prefixed `{MODULE}@{VERSION}/`).
    fn make_module_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write as _;
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut zw = zip::ZipWriter::new(&mut cursor);
            let opts = zip::write::SimpleFileOptions::default();
            for (rel, content) in files {
                zw.start_file(format!("{MODULE}@{VERSION}/{rel}"), opts)
                    .unwrap();
                zw.write_all(content).unwrap();
            }
            zw.finish().unwrap();
        }
        cursor.into_inner()
    }

    async fn mount_go_granted(
        server: &wiremock::MockServer,
        sha512: &str,
        dirhash_h1: Option<&str>,
        zip_bytes: &[u8],
    ) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let serve_path = format!("/patch/golang/{MODULE}/{VERSION}/tok/{UUID}/bar-{VERSION}.zip");
        let serve_url = format!("{}{serve_path}", server.uri());
        let mut integrity = serde_json::json!({ "sha512": sha512 });
        if let Some(h1) = dirhash_h1 {
            integrity["dirhashH1"] = serde_json::Value::from(h1);
        }
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": { UUID: {
                    "status": "granted",
                    "url": serve_url,
                    "purl": PURL,
                    "artifacts": [{ "kind": "tarball", "url": serve_url, "integrity": integrity }]
                }}
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(serve_path))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_bytes.to_vec()))
            .mount(server)
            .await;
    }

    async fn mount_go_status(server: &wiremock::MockServer, status: &str) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": { UUID: { "status": status, "url": null, "artifacts": [] } }
            })))
            .mount(server)
            .await;
    }

    /// Service success: the prebuilt module zip is extracted into the copy dir
    /// (patched bytes), the go.mod `replace` is wired, and a
    /// `vendor_prebuilt_downloaded` advisory is emitted — WITHOUT touching the
    /// pristine source (a deliberately-missing path).
    #[tokio::test]
    async fn service_success_extracts_module_and_wires_replace() {
        let (dir, blobs, _pristine, record) = fixture().await;
        let root = dir.path();
        let zip = make_module_zip(&[
            ("go.mod", b"module github.com/foo/bar\n\ngo 1.21\n"),
            ("bar.go", PATCHED),
        ]);
        let sri = sri_sha512(&zip);
        let server = wiremock::MockServer::start().await;
        mount_go_granted(&server, &sri, None, &zip).await;
        let sources = PatchSources::blobs_only(&blobs);

        let bogus_pristine = root.join("no-such-cache");
        let outcome = vendor_go_module(
            PURL,
            &bogus_pristine,
            root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&go_service_cfg(&server.uri(), VendorSource::Service, false)),
        )
        .await;
        let (result, entry, warnings) = expect_done(outcome);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());
        let copy = root.join(copy_rel());
        assert_eq!(tokio::fs::read(copy.join("bar.go")).await.unwrap(), PATCHED);
        let entries = read_replace_entries(root).await;
        let e = entries
            .iter()
            .find(|e| e.module == MODULE)
            .expect("replace wired");
        assert_eq!(e.owner, Some(ReplaceOwner::Vendor));
        assert_eq!(
            e.path.as_deref(),
            Some(format!("./{}", copy_rel()).as_str())
        );
        assert!(warnings
            .iter()
            .any(|w| w.code == "vendor_prebuilt_downloaded"));
    }

    /// `service` mode + a wrong `h1:` dirhash hard-fails (verifies the
    /// golang-specific dirhash check), nothing wired.
    #[tokio::test]
    async fn service_wrong_dirhash_h1_service_mode_hard_fails() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let zip = make_module_zip(&[
            ("go.mod", b"module github.com/foo/bar\n\ngo 1.21\n"),
            ("bar.go", PATCHED),
        ]);
        let sri = sri_sha512(&zip); // correct sha512
        let server = wiremock::MockServer::start().await;
        mount_go_granted(
            &server,
            &sri,
            Some("h1:bogusdirhashvaluethatwontmatch="),
            &zip,
        )
        .await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = vendor_go_module(
            PURL,
            &pristine,
            root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&go_service_cfg(&server.uri(), VendorSource::Service, false)),
        )
        .await;
        expect_refused(outcome, "vendor_prebuilt_required");
        assert!(!root.join(format!(".socket/vendor/golang/{UUID}")).exists());
    }

    /// `auto` + a not-built service status falls back to the local build.
    #[tokio::test]
    async fn service_unavailable_auto_falls_back_to_build() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let server = wiremock::MockServer::start().await;
        mount_go_status(&server, "not_found").await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = vendor_go_module(
            PURL,
            &pristine,
            root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&go_service_cfg(&server.uri(), VendorSource::Auto, false)),
        )
        .await;
        let (result, entry, _) = expect_done(outcome);
        assert!(
            result.success,
            "auto must fall back to the local build: {:?}",
            result.error
        );
        assert!(entry.is_some());
        assert_eq!(
            tokio::fs::read(root.join(copy_rel()).join("bar.go"))
                .await
                .unwrap(),
            PATCHED
        );
    }

    /// `--offline` + `--vendor-source=service` refuses without any network.
    #[tokio::test]
    async fn offline_service_mode_refuses() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        let outcome = vendor_go_module(
            PURL,
            &pristine,
            root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&go_service_cfg(
                "http://127.0.0.1:1",
                VendorSource::Service,
                true,
            )),
        )
        .await;
        expect_refused(outcome, "vendor_service_offline_conflict");
    }
}
