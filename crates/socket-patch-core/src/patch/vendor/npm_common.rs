//! Flavor-agnostic npm vendoring pipeline: coordinate guards plus the shared
//! stage→patch→pack steps.
//!
//! Every npm lockfile flavor (package-lock today; yarn-classic/pnpm/bun
//! backends to come) vendors the same way up to the wiring: validate the
//! coordinates fail-closed, stage a private copy of the installed package in
//! a tempdir OUTSIDE the project, prune nested `node_modules`, refuse
//! bundled-deps packages, run the hardened apply pipeline against the stage,
//! and pack the result into a deterministic tarball under
//! `.socket/vendor/npm/<uuid>/`. Only the lockfile wiring differs per flavor,
//! and it always runs LAST — so a refusal or failure in this pipeline leaves
//! the project byte-untouched (a dry run stops after verification and
//! creates nothing on disk).

use std::path::Path;

use serde_json::Value;

use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{normalize_file_path, ApplyResult, PatchSources};
use crate::patch::copy_tree::{fresh_copy, remove_tree};
use crate::patch::path_safety;
use crate::utils::purl::{percent_decode_purl_component, strip_purl_qualifiers};

use super::npm_pack::{pack_deterministic, PackedTarball};
use super::path::vendor_uuid_dir_rel;
use super::{VendorOutcome, VendorWarning};

/// Validated npm vendoring coordinates (the output of
/// [`guard_coordinates`]). `name`/`version` are the percent-DECODED purl
/// components (the API serves scoped purls as `%40scope/name`; the
/// lockfile and node_modules carry the literal `@scope/name`).
#[derive(Debug)]
pub(super) struct NpmCoords {
    pub name: String,
    pub version: String,
    /// `.socket/vendor/npm/<uuid>` (validated, forward slashes).
    pub uuid_dir_rel: String,
    /// Qualifier-free base PURL — VERBATIM (still encoded when the API
    /// encoded it): the ledger's `base_purl`/entry keys must keep
    /// matching the manifest keys, which store the purl as-served.
    pub base_purl: String,
}

/// Parse + validate the coordinates every npm flavor keys its artifact path
/// (and lockfile strings) on.
///
/// SECURITY: name/version/uuid come from a committed, tamper-able manifest
/// and key the artifact path under `.socket/vendor/npm/` plus the spec
/// string written into the lockfile. A `..` segment, separator, or
/// non-canonical uuid would escape the vendor dir (arbitrary write on
/// vendor, arbitrary delete on revert) — reject fail-closed before any disk
/// access. `Err` carries a ready [`VendorOutcome::Refused`] to bubble
/// verbatim.
pub(super) fn guard_coordinates(
    purl: &str,
    record: &PatchRecord,
) -> Result<NpmCoords, Box<VendorOutcome>> {
    let Some((name, version)) = parse_npm_purl(purl) else {
        return Err(Box::new(refused(
            "unsafe_coordinates",
            format!("cannot parse an npm name@version out of `{purl}`"),
        )));
    };
    if !is_safe_npm_name(&name) || !path_safety::is_safe_single_segment(&version) {
        return Err(Box::new(refused(
            "unsafe_coordinates",
            format!(
                "refusing to vendor `{name}@{version}`: a `..` segment, absolute path, or \
                 separator would escape .socket/vendor/npm/"
            ),
        )));
    }
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("npm", &record.uuid) else {
        return Err(Box::new(refused(
            "unsafe_coordinates",
            format!(
                "refusing to vendor with non-canonical patch uuid `{}`",
                record.uuid
            ),
        )));
    };
    Ok(NpmCoords {
        name,
        version,
        uuid_dir_rel,
        base_purl: strip_purl_qualifiers(purl).to_string(),
    })
}

/// The shared pipeline's product: a verified, deterministically packed
/// tarball plus the facts the flavor wiring needs.
pub(super) struct NpmStagedPack {
    pub name: String,
    pub version: String,
    /// `.socket/vendor/npm/<uuid>/<leaf>` (forward slashes).
    pub rel_tgz: String,
    pub packed: PackedTarball,
    /// `Some` iff the patch rewrote the package's own `package.json` (the
    /// lockfile's dependency-mirror fields are then stale and the flavor
    /// wiring must recompute them from this parsed manifest).
    pub staged_pkg_json: Option<Value>,
}

/// Stage → patch → pack one installed npm package.
///
/// Runs [`guard_coordinates`] first (pure and cheap — callers that already
/// guarded simply re-validate), stages a fresh copy of `installed_dir` in a
/// tempdir outside the project, prunes nested `node_modules`, refuses
/// bundled-deps packages, applies the patch via the hardened apply pipeline,
/// and packs the deterministic tarball into the uuid dir.
///
/// Result shape (mirrors how `npm_lock::vendor_npm` splits its phases):
///
/// * `Err(outcome)` — a refusal (`Refused`) or a hard pipeline failure
///   (`Done` with a failed synthesized [`ApplyResult`]); bubble verbatim.
///   Nothing inside the project was written.
/// * `Ok((None, result))` — the patch step finished without packing: either
///   `!result.success` (verify/patch failure; the caller wraps it with its
///   accumulated warnings) or a successful dry run (stops after
///   verification — no pack, no dirs created).
/// * `Ok((Some(staged), result))` — full success: the tarball is on disk at
///   `staged.rel_tgz` and the caller proceeds to its lockfile wiring.
#[allow(clippy::too_many_arguments)]
pub(super) async fn stage_patch_pack(
    purl: &str,
    installed_dir: &Path,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    dry_run: bool,
    force: bool,
    warnings: &mut Vec<VendorWarning>,
) -> Result<(Option<NpmStagedPack>, ApplyResult), Box<VendorOutcome>> {
    let coords = guard_coordinates(purl, record)?;

    // ── Stage + patch a private copy ────────────────────────────────────
    // The stage lives in a tempdir OUTSIDE the project: nothing inside the
    // project is written until the patched tarball verifies.
    let stage_tmp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => {
            return Err(Box::new(done_failure(
                purl,
                format!("cannot create staging tempdir: {e}"),
            )))
        }
    };
    let stage = stage_tmp.path().join("stage");
    if let Err(e) = fresh_copy(installed_dir, &stage, None).await {
        return Err(Box::new(done_failure(
            purl,
            format!("cannot stage a copy of the installed package: {e}"),
        )));
    }
    // The tarball must carry ONLY the package's own files: a nested
    // node_modules (hoisting leftovers, file:-dep installs) would balloon
    // the artifact and shadow the lock's own resolution.
    if let Err(e) = remove_tree(&stage.join("node_modules")).await {
        return Err(Box::new(done_failure(
            purl,
            format!("cannot prune staged node_modules: {e}"),
        )));
    }
    // Bundled dependencies ship INSIDE the package tarball; since we just
    // dropped nested node_modules, repacking would produce a tarball npm
    // cannot satisfy those deps from. Refuse before patching.
    if let Ok(bytes) = tokio::fs::read(stage.join("package.json")).await {
        if let Ok(pkg) = serde_json::from_slice::<Value>(&bytes) {
            if declares_bundled_deps(&pkg) {
                return Err(Box::new(refused(
                    "vendor_bundled_deps_unsupported",
                    format!(
                        "{}@{} declares bundleDependencies; vendoring would repack \
                         the tarball without its bundled node_modules and break installs",
                        coords.name, coords.version
                    ),
                )));
            }
        }
    }

    // Delegate to the hardened apply pipeline (with the vendor auto-force
    // policy — see `force_apply_staged`), pointed at the stage (which
    // plays the role of the installed package dir — manifest npm keys carry
    // the `package/` prefix and `apply` strips it via `normalize_file_path`,
    // exactly as it does for an in-place npm apply).
    let result = super::force_apply_staged(
        purl,
        &stage,
        record,
        sources,
        dry_run,
        force,
        &coords.name,
        &coords.version,
        warnings,
    )
    .await;
    // A failed patch never packs (wiring is last — the caller returns with
    // the project byte-untouched); a dry run stops after the verify.
    if !result.success || dry_run {
        return Ok((None, result));
    }

    // ── Pack the deterministic tarball ──────────────────────────────────
    let rel_tgz = format!(
        "{}/{}",
        coords.uuid_dir_rel,
        tgz_rel_leaf(&coords.name, &coords.version)
    );
    let dest = project_root.join(&rel_tgz);
    if let Some(parent) = dest.parent() {
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            return Err(Box::new(done_failure(
                purl,
                format!("cannot create {}: {e}", parent.display()),
            )));
        }
    }
    let packed = match pack_deterministic(&stage, &dest).await {
        Ok(p) => p,
        Err(e) => {
            return Err(Box::new(done_failure(
                purl,
                format!("cannot pack the vendored tarball: {e}"),
            )))
        }
    };

    // ── Patched package.json ⇒ the lock's dependency mirror is stale ────
    let staged_pkg_json = if record
        .files
        .keys()
        .any(|k| normalize_file_path(k) == "package.json")
    {
        match read_staged_package_json(&stage).await {
            Ok(pkg) => Some(pkg),
            Err(e) => return Err(Box::new(done_failure(purl, e))),
        }
    } else {
        None
    };

    Ok((
        Some(NpmStagedPack {
            name: coords.name,
            version: coords.version,
            rel_tgz,
            packed,
            staged_pkg_json,
        }),
        result,
    ))
}

// ───────────────────────────── small helpers ─────────────────────────────

/// `pkg:npm/[@scope/]name@version` → `(name, version)`; scoped names keep
/// the `@scope/` prefix. The LAST `@` separates the version (a leading
/// scope-`@` is at index 0 and never the last `@` of a versioned purl).
///
/// Components are percent-DECODED (the API serves `pkg:npm/%40scope/...`).
/// SECURITY: each segment decodes independently AFTER the `/`/`@` splits,
/// and the post-decode `is_safe_npm_name`/`is_safe_single_segment` gates in
/// [`guard_coordinates`] reject any separator or traversal sequence a
/// decode may have surfaced (`%2e%2e`, `%2f`, ...) — decoding never runs
/// after the guards.
pub(super) fn parse_npm_purl(purl: &str) -> Option<(String, String)> {
    let base = strip_purl_qualifiers(purl);
    let rest = base.strip_prefix("pkg:npm/")?;
    let at = rest.rfind('@').filter(|&i| i > 0)?;
    let (name_raw, version_raw) = (&rest[..at], &rest[at + 1..]);
    if name_raw.is_empty() || version_raw.is_empty() {
        return None;
    }
    let name = name_raw
        .split('/')
        .map(percent_decode_purl_component)
        .collect::<Vec<_>>()
        .join("/");
    let version = percent_decode_purl_component(version_raw).into_owned();
    Some((name, version))
}

/// npm-name shape on top of the generic traversal guard: at most one `/`,
/// and only with an `@scope` first segment (so a smuggled `a/b/c` can't
/// create surprise directory levels under the uuid dir).
pub(super) fn is_safe_npm_name(name: &str) -> bool {
    if !path_safety::is_safe_multi_segment(name) {
        return false;
    }
    match name.split_once('/') {
        None => !name.starts_with('@'),
        Some((scope, bare)) => scope.starts_with('@') && !bare.contains('/'),
    }
}

/// The artifact path under the uuid dir: `[@scope/]<name>-<version>.tgz`,
/// with the scope kept as a real subdirectory.
pub(super) fn tgz_rel_leaf(name: &str, version: &str) -> String {
    match name.split_once('/') {
        Some((scope, bare)) => format!("{scope}/{bare}-{version}.tgz"),
        None => format!("{name}-{version}.tgz"),
    }
}

/// `bundleDependencies` (npm) / `bundledDependencies` (legacy alias):
/// `true` means "all deps", an array names them; either makes the package
/// unvendorable (see the refusal site).
fn declares_bundled_deps(pkg: &Value) -> bool {
    ["bundleDependencies", "bundledDependencies"]
        .iter()
        .any(|k| match pkg.get(*k) {
            Some(Value::Bool(b)) => *b,
            Some(Value::Array(a)) => !a.is_empty(),
            _ => false,
        })
}

async fn read_staged_package_json(stage: &Path) -> Result<Value, String> {
    let bytes = tokio::fs::read(stage.join("package.json"))
        .await
        .map_err(|e| format!("patched package.json unreadable in the stage: {e}"))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("patched package.json is not parseable JSON: {e}"))
}

pub(super) fn refused(code: &'static str, detail: String) -> VendorOutcome {
    VendorOutcome::Refused { code, detail }
}

/// A backend failure after the refusal phase: `Done` with a failed
/// synthesized [`ApplyResult`], mirroring `go_redirect`'s synthesized
/// results.
pub(super) fn done_failure(purl: &str, error: String) -> VendorOutcome {
    VendorOutcome::Done {
        result: super::failed_apply_result(purl, error),
        entry: None,
        warnings: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::schema::PatchFileInfo;
    use std::collections::HashMap;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    fn record_with_uuid(uuid: &str) -> PatchRecord {
        let mut files = HashMap::new();
        files.insert(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash: "a".repeat(64),
                after_hash: "b".repeat(64),
            },
        );
        PatchRecord {
            uuid: uuid.to_string(),
            exported_at: String::new(),
            files,
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    fn expect_refusal(err: Box<VendorOutcome>, want_code: &str) {
        match *err {
            VendorOutcome::Refused { code, detail } => {
                assert_eq!(code, want_code, "{detail}");
            }
            other => panic!("expected Refused {want_code}, got {other:?}"),
        }
    }

    #[test]
    fn guard_coordinates_accepts_plain_and_scoped_names() {
        let record = record_with_uuid(UUID);
        let coords = guard_coordinates("pkg:npm/left-pad@1.3.0", &record).unwrap();
        assert_eq!((coords.name.as_str(), coords.version.as_str()), ("left-pad", "1.3.0"));
        assert_eq!(coords.uuid_dir_rel, format!(".socket/vendor/npm/{UUID}"));
        assert_eq!(coords.base_purl, "pkg:npm/left-pad@1.3.0");

        let coords = guard_coordinates("pkg:npm/@scope/pkg@1.0.0?artifact_id=x", &record).unwrap();
        assert_eq!((coords.name.as_str(), coords.version.as_str()), ("@scope/pkg", "1.0.0"));
        assert_eq!(
            coords.base_purl, "pkg:npm/@scope/pkg@1.0.0",
            "qualifiers stripped"
        );
    }

    /// The API serves scoped purls percent-encoded; the coordinates must
    /// decode to the literal `@scope/name` (which keys the lockfile and
    /// the artifact path), while `base_purl` stays verbatim — the ledger
    /// must keep matching the manifest key as-served.
    #[test]
    fn guard_coordinates_decodes_percent_encoded_scope() {
        let record = record_with_uuid(UUID);
        let coords =
            guard_coordinates("pkg:npm/%40modelcontextprotocol/sdk@1.12.0", &record).unwrap();
        assert_eq!(
            (coords.name.as_str(), coords.version.as_str()),
            ("@modelcontextprotocol/sdk", "1.12.0")
        );
        assert_eq!(
            coords.base_purl, "pkg:npm/%40modelcontextprotocol/sdk@1.12.0",
            "base_purl stays verbatim-encoded (manifest/ledger key parity)"
        );
        assert_eq!(
            tgz_rel_leaf(&coords.name, &coords.version),
            "@modelcontextprotocol/sdk-1.12.0.tgz",
            "artifact leaf is built from the decoded name"
        );
    }

    #[test]
    fn guard_coordinates_refuses_fail_closed() {
        let record = record_with_uuid(UUID);
        // Unparseable purl.
        expect_refusal(
            guard_coordinates("pkg:pypi/six@1.16.0", &record).unwrap_err(),
            "unsafe_coordinates",
        );
        // Traversal name.
        expect_refusal(
            guard_coordinates("pkg:npm/../escape@1.0.0", &record).unwrap_err(),
            "unsafe_coordinates",
        );
        // Traversal version.
        expect_refusal(
            guard_coordinates("pkg:npm/x@../1.0.0", &record).unwrap_err(),
            "unsafe_coordinates",
        );
        // SECURITY: percent-encoded traversal must be rejected POST-decode —
        // guarding the encoded form would be a bypass (`%2e%2e` → `..`).
        expect_refusal(
            guard_coordinates("pkg:npm/%2e%2e/escape@1.0.0", &record).unwrap_err(),
            "unsafe_coordinates",
        );
        expect_refusal(
            guard_coordinates("pkg:npm/@scope/%2e%2e%2f%2e%2e@1.0.0", &record).unwrap_err(),
            "unsafe_coordinates",
        );
        expect_refusal(
            guard_coordinates("pkg:npm/x@%2e%2e%2f1.0.0", &record).unwrap_err(),
            "unsafe_coordinates",
        );
        // Tampered uuid.
        let record = record_with_uuid("../../x");
        expect_refusal(
            guard_coordinates("pkg:npm/left-pad@1.3.0", &record).unwrap_err(),
            "unsafe_coordinates",
        );
    }

    #[tokio::test]
    async fn done_failure_shape_matches_contract() {
        let outcome = done_failure("pkg:npm/x@1.0.0", "boom".to_string());
        let VendorOutcome::Done {
            result,
            entry,
            warnings,
        } = outcome
        else {
            panic!("done_failure must be Done");
        };
        assert!(!result.success);
        assert_eq!(result.package_key, "pkg:npm/x@1.0.0");
        assert_eq!(result.error.as_deref(), Some("boom"));
        assert!(result.files_verified.is_empty() && result.files_patched.is_empty());
        assert!(entry.is_none());
        assert!(warnings.is_empty());
    }
}
