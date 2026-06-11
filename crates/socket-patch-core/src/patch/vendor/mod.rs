//! The `vendor` backend: committable vendoring of patched dependencies.
//!
//! Where `apply` patches installed packages in place (machine-local state),
//! `vendor` ejects each patched package into a committed
//! `.socket/vendor/<eco>/<patch-uuid>/<artifact>` and rewires the ecosystem's
//! lockfile/config so the project consumes the vendored copy. After
//! committing `.socket/vendor/` + the lockfile edits, a fresh checkout builds
//! with the patched dependency on machines with no socket-patch installed and
//! no Socket API access (spike-proven per ecosystem against real package
//! managers — see `spikes/PHASE0-FINDINGS.txt`).
//!
//! ## Per-ecosystem wiring
//!
//! | eco      | artifact            | wiring                                         |
//! |----------|---------------------|------------------------------------------------|
//! | npm      | deterministic tgz   | package-lock.json `resolved`+`integrity` only  |
//! | cargo    | crate dir           | `.cargo/config.toml` `[patch.crates-io]` + Cargo.lock surgery |
//! | golang   | module dir          | `go.mod` `replace` ([`ReplaceOwner::Vendor`])  |
//! | composer | package dir         | composer.lock `dist` → `{type: path}`          |
//! | gem      | gem dir (+gemspec)  | Gemfile `path:` + Gemfile.lock PATH pair       |
//! | pypi     | rebuilt wheel       | uv: pyproject+uv.lock pair; pip: requirements  |
//!
//! npm requests route through [`npm_flavor`], which content-sniffs the
//! project's lockfile (package-lock / yarn / pnpm / bun) and dispatches to
//! the matching backend — today only the package-lock backend exists and
//! the other flavors refuse with stable reason codes.
//!
//! ## Ownership & reversal
//!
//! `.socket/vendor/state.json` (committed) records the verbatim original
//! lockfile fragments every wire replaced; `vendor --revert` restores them
//! and removes the artifacts. The rest of the CLI yields ownership of
//! ledger-recorded purls (`apply`/`rollback` skip them, `scan --prune`
//! exempts them) and `remove` reverts vendoring as part of removing a
//! patch. Detached entries (`scan --vendor --detached`) carry an embedded
//! patch record instead of a manifest entry. The path-level UUID makes "is
//! this Socket-vendored, by which patch" recoverable from the lockfile
//! string alone ([`path`]).
//!
//! [`ReplaceOwner::Vendor`]: crate::patch::go_mod_edit::ReplaceOwner

pub mod path;
pub mod state;

mod berry_zip;
pub mod bun_lock;
#[cfg(feature = "cargo")]
pub mod cargo;
#[cfg(feature = "cargo")]
pub mod cargo_config;
#[cfg(feature = "cargo")]
pub mod cargo_lock;
#[cfg(feature = "composer")]
pub mod composer_lock;
pub mod gem;
pub mod lock_inventory;
pub mod registry_fetch;
#[cfg(feature = "golang")]
pub mod golang;
mod npm_common;
pub mod npm_flavor;
pub mod npm_lock;
pub mod npm_pack;
pub mod pnpm_lock;
pub mod pypi;
pub mod pypi_pdm;
pub mod pypi_pipenv;
pub mod pypi_poetry;
pub mod pypi_requirements;
pub mod pypi_uv;
pub mod pypi_wheel;
mod toml_surgery;
pub mod verify;
pub mod yarn_berry_lock;
pub mod yarn_classic_lock;

pub use path::{ecosystem_dir_for_purl, parse_vendor_path, VendorPathParts, VENDOR_DIR};
pub use state::{load_state, save_state, VendorEntry, VendorState, VENDOR_STATE_REL};

use std::collections::HashMap;
use std::path::Path;

use crate::manifest::schema::{PatchFileInfo, PatchRecord};
use crate::patch::apply::{
    apply_package_patch, is_safe_relative_subpath, normalize_file_path, ApplyResult, PatchSources,
    VerifyStatus,
};

/// A non-fatal advisory surfaced as a warning event (`code` is a stable
/// reason tag from the CLI contract; `detail` is human text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorWarning {
    pub code: &'static str,
    pub detail: String,
}

impl VendorWarning {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// One warning per staged file whose pre-patch content matched NEITHER
/// `beforeHash` nor `afterHash` and was overwritten with the verified
/// patched content (vendor staging always force-applies — the stage is a
/// private copy, and every apply write path is hash-gated to exactly
/// `afterHash`).
///
/// Detection rides the verify signature `apply_package_patch` leaves
/// behind: a force-promoted file keeps `status: Ready` WITH
/// `expected_hash: Some(..)` and a differing `current_hash`, whereas a
/// cleanly-verified file carries `expected_hash: None` (see
/// `verify_file_patch`).
pub(crate) fn mismatch_overwrite_warnings(
    result: &ApplyResult,
    name: &str,
    version: &str,
) -> Vec<VendorWarning> {
    let mut warnings: Vec<VendorWarning> = result
        .files_verified
        .iter()
        .filter(|v| {
            v.status == VerifyStatus::Ready
                && v.expected_hash.is_some()
                && v.current_hash != v.expected_hash
        })
        .map(|v| {
            VendorWarning::new(
                "vendor_content_mismatch_overwritten",
                format!(
                    "installed {name}@{version} does not match this patch's expected original \
                     ({}); vendored the patched content anyway",
                    v.file
                ),
            )
        })
        .collect();
    // HashMap-driven verify order is randomized; keep warning order stable.
    warnings.sort_by(|a, b| a.detail.cmp(&b.detail));
    warnings
}

/// Patch-target files (non-empty `beforeHash`) absent from the staged
/// copy. Vendor staging force-applies (see [`force_apply_staged`]), and
/// force silently SKIPS missing files — which would pack an artifact
/// without the fix. This pre-check restores the strict apply's
/// fail-closed behavior for the non-`--force` path. Unsafe keys are
/// skipped here: the apply pipeline itself rejects them fail-closed.
pub(crate) async fn missing_existing_patch_files(
    staged_dir: &Path,
    files: &HashMap<String, PatchFileInfo>,
) -> Vec<String> {
    let mut missing: Vec<String> = Vec::new();
    for (file_name, info) in files {
        if info.before_hash.is_empty() {
            continue; // a new file is expected to not exist yet
        }
        let normalized = normalize_file_path(file_name);
        if !is_safe_relative_subpath(normalized) {
            continue;
        }
        if tokio::fs::metadata(staged_dir.join(normalized)).await.is_err() {
            missing.push(file_name.clone());
        }
    }
    missing.sort();
    missing
}

/// A failed synthesized [`ApplyResult`] in the shape the strict apply
/// pipeline would have produced (success=false, `error` set, no files).
pub(crate) fn failed_apply_result(purl: &str, error: String) -> ApplyResult {
    ApplyResult {
        package_key: purl.to_string(),
        package_path: String::new(),
        success: false,
        files_verified: Vec::new(),
        files_patched: Vec::new(),
        applied_via: HashMap::new(),
        error: Some(error),
        sidecar: None,
    }
}

/// Run the hardened apply pipeline against a vendor stage/copy with the
/// vendor auto-force policy:
///
/// * Missing patch-target files fail closed unless the caller's own
///   `--force` asked for that skip tolerance.
/// * The apply itself ALWAYS forces: the stage is a private copy (never
///   the user's tree), and every apply write path is hash-gated to
///   exactly `afterHash` (the archive and blob paths verify content
///   BEFORE writing; the diff path self-disables on a base mismatch) —
///   forcing can only produce the verified patched content or fail
///   closed. This is what lets vendor succeed on a package already
///   patched in place by `apply`, or on a patch whose `beforeHash` was
///   built against different bytes than the installed artifact.
/// * Every force-overwritten file (content matched NEITHER hash) emits a
///   `vendor_content_mismatch_overwritten` warning — including on dry
///   runs, so previews predict the real outcome.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn force_apply_staged(
    purl: &str,
    staged_dir: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    dry_run: bool,
    force: bool,
    name: &str,
    version: &str,
    warnings: &mut Vec<VendorWarning>,
) -> ApplyResult {
    if !force {
        let missing = missing_existing_patch_files(staged_dir, &record.files).await;
        if let Some(first) = missing.first() {
            return failed_apply_result(
                purl,
                format!("Cannot apply patch: {first} - File not found"),
            );
        }
    }
    let result = apply_package_patch(
        purl,
        staged_dir,
        &record.files,
        sources,
        Some(&record.uuid),
        dry_run,
        // The stage is private and every write path is afterHash-gated;
        // Force additionally covers the caller's --force NotFound-skip
        // (the missing-file pre-check above handles the default case).
        crate::patch::apply::MismatchPolicy::Force,
    )
    .await;
    if result.success {
        warnings.extend(mismatch_overwrite_warnings(&result, name, version));
    }
    result
}

/// The result of one backend `vendor_*` call.
//
// `large_enum_variant`: `Done` is much bigger than `Refused` because it carries
// the full `ApplyResult` plus an `Option<VendorEntry>` (which itself holds the
// per-ecosystem `*Meta` records). That asymmetry is harmless here — a
// `VendorOutcome` is a one-shot return value, built once per backend call and
// consumed immediately by the router; it is never stored in a collection or a
// hot loop. Boxing both large fields (what the lint asks for) would only spray
// deref churn across every backend, router, and the CLI for no runtime benefit.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum VendorOutcome {
    /// Refused before any write (wrong package manager, unsupported lockfile
    /// flavor, unsafe coordinates, …). `code` is the stable reason tag.
    Refused { code: &'static str, detail: String },
    /// The backend ran. `result` carries the per-file verify/patch outcome
    /// (the same [`ApplyResult`] contract as apply); `entry` is the state
    /// record to persist — present iff `result.success` and not a dry run.
    Done {
        result: ApplyResult,
        entry: Option<VendorEntry>,
        warnings: Vec<VendorWarning>,
    },
}

/// The result of one backend `revert_*` call.
#[derive(Debug)]
pub struct RevertOutcome {
    pub success: bool,
    pub warnings: Vec<VendorWarning>,
    pub error: Option<String>,
}

impl RevertOutcome {
    pub fn ok() -> Self {
        Self {
            success: true,
            warnings: Vec::new(),
            error: None,
        }
    }

    pub fn failed(error: impl Into<String>) -> Self {
        Self {
            success: false,
            warnings: Vec::new(),
            error: Some(error.into()),
        }
    }
}

/// True iff this build can vendor this PURL's ecosystem.
pub fn is_vendorable(purl: &str) -> bool {
    ecosystem_dir_for_purl(purl).is_some()
}

/// Cheap probe used by `apply` to respect vendor ownership: is `purl`
/// recorded as vendored in the committed ledger?
pub async fn is_purl_vendored(project_root: &std::path::Path, purl: &str) -> bool {
    match load_state(project_root).await {
        Ok(state) => {
            state.entries.contains_key(purl) || state.entries.values().any(|e| e.base_purl == purl)
        }
        Err(_) => false,
    }
}

/// Every purl spelling under which the ledger's entries are addressable:
/// each entry's map key (the manifest purl, possibly qualified), its
/// resolved base purl, and the qualifier-stripped key. The one-load,
/// many-lookups companion to [`is_purl_vendored`] for callers that match
/// whole purl sets against vendor ownership (apply / rollback / scan
/// prune). An unreadable ledger degrades to the empty set — the same
/// fail-open contract as `is_purl_vendored`; mutating callers that need
/// fail-closed semantics use [`load_state`] directly.
pub async fn vendored_purl_keys(
    project_root: &std::path::Path,
) -> std::collections::HashSet<String> {
    match load_state(project_root).await {
        Ok(state) => state
            .entries
            .iter()
            .flat_map(|(key, entry)| {
                [
                    key.clone(),
                    entry.base_purl.clone(),
                    crate::utils::purl::strip_purl_qualifiers(key).to_string(),
                ]
            })
            .collect(),
        Err(_) => std::collections::HashSet::new(),
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use crate::patch::apply::VerifyResult;

    fn verify(status: VerifyStatus, expected: Option<&str>, current: Option<&str>) -> VerifyResult {
        VerifyResult {
            file: "package/index.js".to_string(),
            status,
            message: None,
            current_hash: current.map(str::to_string),
            expected_hash: expected.map(str::to_string),
            target_hash: None,
        }
    }

    fn result_with(files_verified: Vec<VerifyResult>) -> ApplyResult {
        ApplyResult {
            package_key: "pkg:npm/x@1.0.0".to_string(),
            package_path: String::new(),
            success: true,
            files_verified,
            files_patched: Vec::new(),
            applied_via: HashMap::new(),
            error: None,
            sidecar: None,
        }
    }

    /// Only the force-promoted signature (`Ready` + `expected_hash: Some` +
    /// differing `current_hash`) flags an overwrite; clean verifies and
    /// AlreadyPatched files never do.
    #[test]
    fn mismatch_overwrite_warnings_detects_promoted_ready() {
        // Force-promoted mismatch: flagged.
        let r = result_with(vec![verify(VerifyStatus::Ready, Some("aa"), Some("bb"))]);
        let w = mismatch_overwrite_warnings(&r, "left-pad", "1.3.0");
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].code, "vendor_content_mismatch_overwritten");
        assert!(w[0].detail.contains("left-pad@1.3.0"));
        assert!(w[0].detail.contains("package/index.js"));

        // Clean Ready (verify matched beforeHash): expected_hash is None.
        let r = result_with(vec![verify(VerifyStatus::Ready, None, Some("aa"))]);
        assert!(mismatch_overwrite_warnings(&r, "x", "1").is_empty());

        // AlreadyPatched (afterHash content): not a mismatch.
        let r = result_with(vec![verify(
            VerifyStatus::AlreadyPatched,
            None,
            Some("after"),
        )]);
        assert!(mismatch_overwrite_warnings(&r, "x", "1").is_empty());

        // NotFound (force-skipped): not an overwrite.
        let r = result_with(vec![verify(VerifyStatus::NotFound, None, None)]);
        assert!(mismatch_overwrite_warnings(&r, "x", "1").is_empty());
    }
}
