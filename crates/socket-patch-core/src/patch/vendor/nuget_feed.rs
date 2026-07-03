//! NuGet vendor backend: a committed flat-folder package feed plus
//! `nuget.config` source wiring and (when present) `packages.lock.json`
//! content-hash pinning pointing every restore of the patched package id at a
//! rebuilt, patched `.nupkg`.
//!
//! Mechanism (verified against .NET SDK 8.0 in the docker capstone):
//!
//! * artifact — a single rebuilt `.nupkg` at the stable path
//!   `.socket/vendor/nuget/<uuid>/<idLower>.<versionNorm>.nupkg`. The uuid dir
//!   IS a NuGet *local folder feed* (NuGet enumerates its `*.nupkg` files and
//!   reads each embedded `.nuspec` for id/version, so the filename casing is
//!   cosmetic — the marker sibling `socket-patch.vendor.json` is ignored).
//!   The `.nupkg` is rebuilt by extracting the cached pristine package,
//!   force-applying the patch, and re-zipping deterministically (so a re-run
//!   never churns the committed bytes). The embedded package signature
//!   (`.signature.p7s`) is dropped: the bytes changed, so it is no longer the
//!   signed original — an unsigned package is accepted under NuGet's default
//!   `accept` validation mode, whereas a stale signature could be rejected.
//!
//! * `nuget.config` — the source `<add key="socket-patch-<uuid>"
//!   value=".socket/vendor/nuget/<uuid>"/>` (relative paths resolve against
//!   the config file's directory) plus a `packageSourceMapping` routing the
//!   patched id to that source. `packageSourceMapping` is EXCLUSIVE: once ANY
//!   mapping exists, every package must map to a source or restore hard-fails
//!   NU1100. So when the pre-vendor config had NO mapping, we ALSO emit a
//!   catch-all `<package pattern="*"/>` mapped to every pre-existing source
//!   (this catch-all rule is load-bearing). A more specific id pattern beats
//!   `*` by NuGet's longest-prefix match, so the patched id resolves from our
//!   feed while everything else keeps its original source.
//!
//! * `packages.lock.json` (when present) — every framework entry for the id
//!   whose `resolved` equals the vendored version gets its `contentHash`
//!   rewritten to `base64(sha512(vendored nupkg bytes))`; `resolved` and the
//!   rest are untouched. `dotnet restore --locked-mode` recomputes the nupkg's
//!   hash and compares it to this pin (a tampered nupkg then fails NU1403).
//!   An absent lockfile is tolerated with a `vendor_nuget_no_lockfile`
//!   warning — the feed + mapping still force the patched id from our copy,
//!   just without the content-hash pin.
//!
//! Edit order: artifact → nuget.config → packages.lock.json. Any failure after
//! the artifact removes the uuid dir; a lock-write failure additionally unwinds
//! the config to its recorded pre-vendor bytes, so the pair is never half-wired.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest as _, Sha512};

use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{ApplyResult, PatchSources};
use crate::patch::copy_tree::remove_tree;
use crate::patch::path_safety::is_safe_single_segment;
use crate::utils::fs::{atomic_write_bytes, list_dir_entries};
use crate::utils::purl::{build_nuget_purl, parse_nuget_purl};

use super::common::{
    already_patched_result, done, failed_result, insert_before, rebuild_zip, refused,
    synthesized_result, zip_matches_after_hashes,
};
use super::path::vendor_uuid_dir_rel;
use super::registry_fetch::extract_zip;
use super::service_fetch::{service_archive_copy, ServiceCopy};
use super::state::{
    write_marker, VendorArtifact, VendorEntry, VendorMarker, WiringAction, WiringRecord,
};
use super::{RevertOutcome, VendorOutcome, VendorServiceConfig, VendorWarning};

/// Project-relative lockfile this backend pins (optional — NuGet only writes
/// it when `RestorePackagesWithLockFile`/`--use-lock-file` is set).
const PACKAGES_LOCK: &str = "packages.lock.json";

/// Wiring-record discriminators. `nuget_config_source` carries the WHOLE-FILE
/// pre/post `nuget.config` snapshot (the authoritative revert record);
/// `nuget_config_mapping` is an audit record naming the mapping we added (its
/// revert is a no-op — the source record restores the file wholesale);
/// `nuget_lock_entry` carries the verbatim original `contentHash` so revert
/// restores it byte-identically.
const CONFIG_SOURCE_WIRING_KIND: &str = "nuget_config_source";
const CONFIG_MAPPING_WIRING_KIND: &str = "nuget_config_mapping";
const LOCK_WIRING_KIND: &str = "nuget_lock_entry";

/// The embedded package signature part; dropped from the rebuilt nupkg so the
/// patched (content-changed) package reads as unsigned rather than
/// invalid-signed.
const SIGNATURE_PART: &str = ".signature.p7s";

/// The implicit default public NuGet source, seeded as the catch-all target
/// when a from-scratch `<packageSourceMapping>` would otherwise have no
/// pre-existing source to fan `*` out to (a socket-only mapping NU1100s every
/// non-patched package). Mirrors `redirect::add_nuget_source`.
const NUGET_ORG_SOURCE_KEY: &str = "nuget.org";
const NUGET_ORG_SOURCE_URL: &str = "https://api.nuget.org/v3/index.json";

/// Normalize a NuGet version for the flat-container / registration path:
/// lowercase, drop build metadata (`+…`), strip per-segment leading zeros, pad
/// the numeric core to 3 parts, and drop a zero 4th (Revision) segment. Rust
/// twin of the TS `normalizeNuGetVersion`
/// (`workspaces/patches/src/services/patch-registry-serve-decision.ts`); the
/// two MUST stay in sync so the vendored feed filename, the
/// `packageSourceMapping` version match, and the server-side registry paths
/// agree. Mirrors `NuGetVersion.ToNormalizedString().ToLowerInvariant()`.
fn normalize_nuget_version(version: &str) -> String {
    // Build metadata is not part of package identity — drop it first.
    let without_build = match version.find('+') {
        Some(i) => &version[..i],
        None => version,
    };
    // A pre-release tag (`-rc.1`) is preserved verbatim (only the numeric core
    // is normalized). The `-` and everything after it is the pre-release.
    let (core, pre) = match without_build.find('-') {
        Some(i) => (&without_build[..i], &without_build[i..]),
        None => (without_build, ""),
    };
    let mut parts: Vec<String> = core
        .split('.')
        .map(|p| {
            // Strip leading zeros but keep at least one digit (`0`, `00` → `0`).
            let stripped = p.trim_start_matches('0');
            if stripped.is_empty() {
                "0".to_string()
            } else {
                stripped.to_string()
            }
        })
        .collect();
    while parts.len() < 3 {
        parts.push("0".to_string());
    }
    if parts.len() == 4 && parts[3] == "0" {
        parts.pop();
    }
    format!("{}{}", parts.join("."), pre).to_lowercase()
}

/// A NuGet id/version token is safe to embed into an on-disk filename, an XML
/// attribute value (`nuget.config`), and a path segment. A real NuGet id is
/// `[A-Za-z0-9._-]` and a version is semver `[A-Za-z0-9.+-]`; anything else
/// (a quote, angle bracket, ampersand, slash, …) would be an XML/path
/// injection, so it is rejected fail-closed.
fn is_plain_nuget_token(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
}

/// Vendor a NuGet package: rebuild a patched `.nupkg` under
/// `.socket/vendor/nuget/<uuid>/`, wire `nuget.config` to serve it, and pin its
/// `contentHash` in `packages.lock.json` (see the module doc).
///
/// `installed_dir` is the crawler's package dir
/// (`~/.nuget/packages/<idLower>/<verLower>/` or the legacy
/// `packages/<Name>.<Version>/`), which holds the cached pristine `.nupkg` the
/// rebuild extracts from and against which the manifest's package-relative file
/// keys resolve.
#[allow(clippy::too_many_arguments)]
pub async fn vendor_nuget(
    purl: &str,
    installed_dir: &Path,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
    service: Option<&VendorServiceConfig>,
) -> VendorOutcome {
    // ── coordinates ──────────────────────────────────────────────────────
    let Some((name, version)) = parse_nuget_purl(purl) else {
        return refused("unsafe_coordinates", format!("not a nuget purl: {purl}"));
    };
    // SECURITY: `uuid`, `name`, and `version` come from committed, tamper-able
    // manifest data. They key the uuid dir vendor creates and `--revert`
    // deletes, the vendored filename, and — via `nuget.config` — XML attribute
    // values. Reject anything but the plain NuGet token charset fail-closed
    // before any disk access.
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("nuget", &record.uuid) else {
        return refused(
            "unsafe_coordinates",
            format!("non-canonical patch uuid {:?}", record.uuid),
        );
    };
    if !is_safe_single_segment(name)
        || !is_safe_single_segment(version)
        || !is_plain_nuget_token(name)
        || !is_plain_nuget_token(version)
    {
        return refused(
            "unsafe_coordinates",
            format!("unsafe nuget coordinates `{name}` @ `{version}`"),
        );
    }

    let id_lower = name.to_lowercase();
    let version_norm = normalize_nuget_version(version);
    let leaf = format!("{id_lower}.{version_norm}.nupkg");
    let copy_rel = format!("{uuid_dir_rel}/{leaf}");
    let uuid_dir = project_root.join(&uuid_dir_rel);
    let nupkg_path = project_root.join(&copy_rel);
    let source_key = format!("socket-patch-{}", record.uuid);

    // A patch with no files is meaningless to vendor: no-op success, no edits.
    if record.files.is_empty() {
        return done(
            synthesized_result(purl, &nupkg_path, Vec::new(), true, None),
            None,
            Vec::new(),
        );
    }

    let config_path = existing_config_path(project_root).await;
    let config_text: Option<String> = match &config_path {
        Some(p) => match tokio::fs::read_to_string(p).await {
            Ok(t) => Some(t),
            Err(e) => {
                return refused(
                    "vendor_nuget_config_unreadable",
                    format!("unreadable {}: {e}", p.display()),
                );
            }
        },
        None => None,
    };
    let lock_path = project_root.join(PACKAGES_LOCK);
    let lock_text: Option<String> = match tokio::fs::read_to_string(&lock_path).await {
        Ok(t) => Some(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return refused(
                "vendor_nuget_lock_unreadable",
                format!("unreadable {}: {e}", lock_path.display()),
            );
        }
    };

    // ── idempotent hot path ──────────────────────────────────────────────
    // nuget.config already carries our source, the committed nupkg already
    // hashes its patched entries, and the lock (if any) already pins that
    // nupkg → touch nothing, report AlreadyPatched. `entry` stays `None`: the
    // first run's ledger entry holds the only copy of the verbatim pre-vendor
    // originals, and re-recording here would clobber them.
    let config_wired = config_text
        .as_deref()
        .is_some_and(|t| t.contains(&source_key));
    if config_wired {
        let nupkg_ok = zip_matches_after_hashes(&nupkg_path, &record.files).await;
        let lock_ok = match &lock_text {
            None => true,
            Some(text) => match tokio::fs::read(&nupkg_path).await {
                Ok(bytes) => lock_pinned(text, name, &version_norm, &content_hash(&bytes)),
                Err(_) => false,
            },
        };
        if nupkg_ok && lock_ok {
            return done(
                already_patched_result(purl, &nupkg_path, &record.files),
                None,
                Vec::new(),
            );
        }
        // Wired but the committed nupkg is missing/stale: rebuild the ARTIFACT
        // only (and re-pin the lock at the rebuilt bytes). The config is
        // already correct and the full path would re-record the live vendored
        // fragments as `original`, breaking a later `--revert`.
        if !dry_run {
            let mut warnings: Vec<VendorWarning> = Vec::new();
            let (bytes, mut result) = match materialise_patched_nupkg(
                purl,
                installed_dir,
                &uuid_dir,
                &nupkg_path,
                name,
                version,
                record,
                sources,
                force,
                service,
                &mut warnings,
            )
            .await
            {
                Ok(pair) => pair,
                Err(outcome) => return *outcome,
            };
            if !result.success {
                return done(result, None, warnings);
            }
            // Re-pin the lock at the rebuilt bytes (the config is untouched).
            if let Some(text) = &lock_text {
                let new_hash = content_hash(&bytes);
                if let Ok(Some(edit)) = edit_lock(text, name, &version_norm, &new_hash) {
                    if let Err(e) = atomic_write_bytes(&lock_path, edit.text.as_bytes()).await {
                        let _ = remove_tree(&uuid_dir).await;
                        result.success = false;
                        result.error = Some(format!("failed to rewrite {PACKAGES_LOCK}: {e}"));
                        return done(result, None, warnings);
                    }
                }
            }
            warnings.push(VendorWarning::new(
                "vendor_artifact_rebuilt",
                format!(
                    "the committed vendored nupkg for {name}@{version} was missing or stale; \
                     rebuilt at {copy_rel} (nuget.config untouched)"
                ),
            ));
            return done(result, None, warnings);
        }
        // Dry runs fall through to the verify-only preview below.
    }

    // ── dry run: verify-only against the installed dir, no writes ────────
    if dry_run {
        let mut dry_warnings: Vec<VendorWarning> = Vec::new();
        let mut result = super::force_apply_staged(
            purl,
            installed_dir,
            record,
            sources,
            true,
            force,
            name,
            version,
            &mut dry_warnings,
        )
        .await;
        result.package_path = nupkg_path.display().to_string();
        return done(result, None, dry_warnings);
    }

    // ── materialise the patched nupkg (service download / local rebuild) ──
    let mut warnings: Vec<VendorWarning> = Vec::new();
    let (nupkg_bytes, mut result) = match materialise_patched_nupkg(
        purl,
        installed_dir,
        &uuid_dir,
        &nupkg_path,
        name,
        version,
        record,
        sources,
        force,
        service,
        &mut warnings,
    )
    .await
    {
        Ok(pair) => pair,
        Err(outcome) => return *outcome,
    };
    if !result.success {
        // The rebuild left the result un-successful (and cleaned up its own
        // partial artifact); no project file was touched.
        return done(result, None, warnings);
    }
    result.package_path = nupkg_path.display().to_string();
    let new_hash = content_hash(&nupkg_bytes);

    // ── nuget.config wiring (runs after the artifact) ─────────────────────
    let config_edit =
        match build_config_edit(config_text.as_deref(), &source_key, &uuid_dir_rel, name) {
            Ok(edit) => edit,
            Err(detail) => {
                let _ = remove_tree(&uuid_dir).await;
                result.success = false;
                result.error = Some(detail);
                return done(result, None, warnings);
            }
        };
    let config_target = config_path
        .clone()
        .unwrap_or_else(|| project_root.join("nuget.config"));
    if let Err(e) = atomic_write_bytes(&config_target, config_edit.new_text.as_bytes()).await {
        let _ = remove_tree(&uuid_dir).await;
        result.success = false;
        result.error = Some(format!("failed to write {}: {e}", config_target.display()));
        return done(result, None, warnings);
    }

    // ── packages.lock.json pinning (a failure here unwinds the config) ────
    let mut lock_record: Option<WiringRecord> = None;
    if let Some(text) = &lock_text {
        match edit_lock(text, name, &version_norm, &new_hash) {
            Ok(Some(edit)) => {
                if let Err(e) = atomic_write_bytes(&lock_path, edit.text.as_bytes()).await {
                    unwind_config(&config_target, config_text.as_deref(), &uuid_dir).await;
                    result.success = false;
                    result.error = Some(format!("failed to write {PACKAGES_LOCK}: {e}"));
                    return done(result, None, warnings);
                }
                lock_record = Some(WiringRecord {
                    file: PACKAGES_LOCK.to_string(),
                    kind: LOCK_WIRING_KIND.to_string(),
                    action: WiringAction::Rewritten,
                    key: Some(name.to_string()),
                    original: Some(Value::String(edit.original_hash)),
                    new: Some(Value::String(new_hash.clone())),
                });
            }
            Ok(None) => {
                // The lock names the id at our version but its resolution is
                // absent (a lock that never pinned this package) — the feed +
                // mapping still force it from our copy, just unpinned.
                warnings.push(VendorWarning::new(
                    "vendor_nuget_lock_entry_absent",
                    format!(
                        "{PACKAGES_LOCK} has no resolved entry for {name} {version_norm}; the \
                         vendored feed still serves it but its contentHash is not pinned"
                    ),
                ));
            }
            Err(detail) => {
                unwind_config(&config_target, config_text.as_deref(), &uuid_dir).await;
                result.success = false;
                result.error = Some(detail);
                return done(result, None, warnings);
            }
        }
    } else {
        warnings.push(VendorWarning::new(
            "vendor_nuget_no_lockfile",
            format!(
                "no {PACKAGES_LOCK} (RestorePackagesWithLockFile is off); the vendored feed \
                 forces {name} from the patched copy but its contentHash is not pinned"
            ),
        ));
    }

    // ── marker + ledger entry ────────────────────────────────────────────
    let base_purl = build_nuget_purl(name, version);
    let marker = VendorMarker::new("nuget", &base_purl, record, vendored_at);
    if let Err(e) = write_marker(&uuid_dir, &marker).await {
        // Informational only (state.json is the ledger of record) — a marker
        // failure must not fail an otherwise-wired vendor.
        warnings.push(VendorWarning::new(
            "vendor_marker_write_failed",
            format!("could not write {}: {e}", super::state::VENDOR_MARKER_FILE),
        ));
    }

    // The source record is the authoritative revert record: it carries the
    // whole-file pre/post config snapshot. When the config pre-existed it is a
    // `Rewritten` (revert restores `original`); when we created it, an `Added`
    // (revert deletes the file). The mapping record is audit-only.
    let created_config = config_text.is_none();
    // Both records name the config by its basename (nuget.config always sits
    // at the project root).
    let config_rel = config_target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "nuget.config".to_string());
    let source_record = WiringRecord {
        file: config_rel.clone(),
        kind: CONFIG_SOURCE_WIRING_KIND.to_string(),
        action: if created_config {
            WiringAction::Added
        } else {
            WiringAction::Rewritten
        },
        key: Some(source_key.clone()),
        original: config_text.as_ref().map(|t| Value::String(t.clone())),
        new: Some(Value::String(config_edit.new_text.clone())),
    };
    let mapping_record = WiringRecord {
        file: config_rel,
        kind: CONFIG_MAPPING_WIRING_KIND.to_string(),
        action: WiringAction::Added,
        key: Some(name.to_string()),
        original: None,
        new: Some(Value::String(config_edit.mapping_fragment.clone())),
    };
    // Application order: config source, config mapping, then the lock pin.
    // Revert runs them in reverse (lock → mapping → source).
    let mut wiring = vec![source_record, mapping_record];
    if let Some(rec) = lock_record {
        wiring.push(rec);
    }

    let entry = VendorEntry {
        ecosystem: "nuget".to_string(),
        base_purl,
        uuid: record.uuid.clone(),
        artifact: VendorArtifact {
            // A `.nupkg` is a single verifiable file; record its plain sha256
            // for tooling (harvest re-derives per-entry git hashes from the
            // zip, so the vendored copy is self-describing without a network).
            path: copy_rel,
            sha256: hex::encode(sha2::Sha256::digest(&nupkg_bytes)),
            size: Some(nupkg_bytes.len() as u64),
            platform_locked: None,
        },
        wiring,
        lock: None,
        took_over_go_patches: false,
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

/// Revert a NuGet vendor entry: undo the lock pin, restore/delete the
/// `nuget.config`, and remove the validated uuid dir. Each fragment that no
/// longer looks like what vendor wrote — a hand edit, a `dotnet restore`
/// re-resolution, a newer vendor run — is left alone with a
/// `vendor_lock_entry_drifted` warning.
pub async fn revert_nuget(
    entry: &VendorEntry,
    project_root: &Path,
    dry_run: bool,
) -> RevertOutcome {
    // SECURITY: state.json is committed and tamper-able; the uuid keys the
    // directory we are about to delete. Anything but the canonical uuid
    // grammar is rejected fail-closed before any disk access.
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("nuget", &entry.uuid) else {
        return RevertOutcome::failed(format!(
            "refusing revert: non-canonical patch uuid {:?}",
            entry.uuid
        ));
    };
    let uuid_dir = project_root.join(&uuid_dir_rel);
    let mut warnings = Vec::new();

    // Reverse application order: lock pin, then the (no-op) mapping audit
    // record, then the authoritative config restore.
    for w in entry.wiring.iter().rev() {
        let restored = match w.kind.as_str() {
            LOCK_WIRING_KIND => {
                revert_lock_record(&project_root.join(PACKAGES_LOCK), w, dry_run).await
            }
            // Audit-only: the whole-file config restore lives on the source
            // record, so there is nothing to undo here.
            CONFIG_MAPPING_WIRING_KIND => Ok(true),
            CONFIG_SOURCE_WIRING_KIND => {
                revert_config_record(project_root, &uuid_dir_rel, w, dry_run).await
            }
            _ => {
                warnings.push(VendorWarning::new(
                    "vendor_lock_entry_drifted",
                    format!("unrecognized wiring kind {:?}; fragment left alone", w.kind),
                ));
                continue;
            }
        };
        match restored {
            Ok(true) => {}
            Ok(false) => warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "{} no longer carries what vendor wrote for {}; left alone",
                    w.file,
                    w.key.as_deref().unwrap_or("<unknown>")
                ),
            )),
            Err(e) => {
                return RevertOutcome {
                    success: false,
                    warnings,
                    error: Some(e),
                };
            }
        }
    }

    if !dry_run {
        if let Err(e) = remove_tree(&uuid_dir).await {
            return RevertOutcome {
                success: false,
                warnings,
                error: Some(format!("failed to remove {}: {e}", uuid_dir.display())),
            };
        }
    }

    RevertOutcome {
        success: true,
        warnings,
        error: None,
    }
}

// ── materialisation (service download / local rebuild) ─────────────────────────

/// Produce the patched `.nupkg` bytes at `nupkg_path` — service download first
/// (Tier A: the served archive IS the patched nupkg, written verbatim), local
/// rebuild otherwise (extract the cached pristine nupkg → force-apply → re-zip
/// deterministically). Returns `(bytes, ApplyResult)`, or a terminal
/// [`VendorOutcome`] to bubble. On a non-fatal rebuild failure the returned
/// `ApplyResult.success` is false and the partial uuid dir is cleaned up.
#[allow(clippy::too_many_arguments)]
async fn materialise_patched_nupkg(
    purl: &str,
    installed_dir: &Path,
    uuid_dir: &Path,
    nupkg_path: &Path,
    name: &str,
    version: &str,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    force: bool,
    service: Option<&VendorServiceConfig>,
    warnings: &mut Vec<VendorWarning>,
) -> Result<(Vec<u8>, ApplyResult), Box<VendorOutcome>> {
    match service_archive_copy(service, &record.uuid, name, ".nupkg", warnings).await {
        ServiceCopy::Used(bytes) => {
            if let Err(e) = write_nupkg(uuid_dir, nupkg_path, &bytes).await {
                let _ = remove_tree(uuid_dir).await;
                return Err(Box::new(refused("vendor_prebuilt_write_failed", e)));
            }
            Ok((
                bytes,
                already_patched_result(purl, nupkg_path, &record.files),
            ))
        }
        ServiceCopy::HardFail(outcome) => Err(outcome),
        ServiceCopy::FallBack => {
            local_rebuild(
                purl,
                installed_dir,
                uuid_dir,
                nupkg_path,
                name,
                version,
                record,
                sources,
                force,
                warnings,
            )
            .await
        }
    }
}

/// Local rebuild: locate the cached pristine `.nupkg` in `installed_dir`,
/// extract it to a private stage, force-apply the patch, and re-zip
/// deterministically. The `.signature.p7s` part is dropped (see the module
/// doc). Returns `(bytes, ApplyResult)`; a failure surfaces as an un-successful
/// `ApplyResult` (partial uuid dir cleaned up), or a refusal to bubble.
#[allow(clippy::too_many_arguments)]
async fn local_rebuild(
    purl: &str,
    installed_dir: &Path,
    uuid_dir: &Path,
    nupkg_path: &Path,
    name: &str,
    version: &str,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    force: bool,
    warnings: &mut Vec<VendorWarning>,
) -> Result<(Vec<u8>, ApplyResult), Box<VendorOutcome>> {
    let Some(src_nupkg) = locate_cached_nupkg(installed_dir).await else {
        return Err(Box::new(refused(
            "vendor_nupkg_not_found",
            format!(
                "no cached .nupkg under {} to rebuild {name}@{version} from (a patched feed \
                 needs the pristine package; restore it or use --vendor-source=service)",
                installed_dir.display()
            ),
        )));
    };
    let bytes = match tokio::fs::read(&src_nupkg).await {
        Ok(b) => b,
        Err(e) => {
            return Ok((
                Vec::new(),
                failed_result(
                    purl,
                    nupkg_path,
                    format!("cannot read {}: {e}", src_nupkg.display()),
                ),
            ));
        }
    };
    let stage = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(e) => {
            return Ok((
                Vec::new(),
                failed_result(purl, nupkg_path, format!("cannot create stage dir: {e}")),
            ));
        }
    };
    // The nupkg carries content at the archive root (no strip). extract_zip is
    // traversal-guarded and refuses an escaping entry fail-closed.
    if let Err(e) = extract_zip(&bytes, stage.path(), /*strip_first=*/ false) {
        return Ok((
            Vec::new(),
            failed_result(
                purl,
                nupkg_path,
                format!("cannot extract {}: {e}", src_nupkg.display()),
            ),
        ));
    }

    let result = super::force_apply_staged(
        purl,
        stage.path(),
        record,
        sources,
        false,
        force,
        name,
        version,
        warnings,
    )
    .await;
    if !result.success {
        return Ok((Vec::new(), result));
    }

    // Deterministic re-zip of the patched stage (RECORD-free — a nupkg is a
    // plain OPC zip; NuGet reads the central directory, so entry order is free
    // to be lexicographic for stable bytes across re-runs).
    let stage_path = stage.path().to_path_buf();
    let rezip =
        tokio::task::spawn_blocking(move || rebuild_zip(&stage_path, Some(SIGNATURE_PART))).await;
    let nupkg_bytes = match rezip {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            return Ok((
                Vec::new(),
                failed_result(purl, nupkg_path, format!("nupkg re-zip failed: {e}")),
            ));
        }
        Err(e) => {
            return Ok((
                Vec::new(),
                failed_result(purl, nupkg_path, format!("nupkg re-zip task failed: {e}")),
            ));
        }
    };

    if let Err(e) = write_nupkg(uuid_dir, nupkg_path, &nupkg_bytes).await {
        let _ = remove_tree(uuid_dir).await;
        return Ok((Vec::new(), failed_result(purl, nupkg_path, e)));
    }
    Ok((nupkg_bytes, result))
}

/// Write `bytes` to `nupkg_path`, creating the uuid dir. Errors are strings.
async fn write_nupkg(uuid_dir: &Path, nupkg_path: &Path, bytes: &[u8]) -> Result<(), String> {
    tokio::fs::create_dir_all(uuid_dir)
        .await
        .map_err(|e| format!("cannot create {}: {e}", uuid_dir.display()))?;
    atomic_write_bytes(nupkg_path, bytes)
        .await
        .map_err(|e| format!("cannot write {}: {e}", nupkg_path.display()))
}

/// The `content_hash` NuGet pins in `packages.lock.json`: base64 of the
/// sha512 of the whole `.nupkg`.
fn content_hash(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
}

/// Locate the single cached pristine `.nupkg` inside a crawler package dir
/// (NuGet keeps `<idLower>.<verLower>.nupkg` alongside the extracted files in
/// both the global cache and the legacy `packages/` layout).
async fn locate_cached_nupkg(installed_dir: &Path) -> Option<PathBuf> {
    for entry in list_dir_entries(installed_dir).await {
        let name = entry.file_name().to_string_lossy().into_owned();
        // `.nupkg.metadata` / `.nupkg.sha512` are sidecars, not packages.
        if name.to_ascii_lowercase().ends_with(".nupkg") {
            return Some(entry.path());
        }
    }
    None
}

// ── nuget.config editing ───────────────────────────────────────────────────────

/// The planned config edit: the whole new file text plus the mapping fragment
/// (for the audit wiring record).
struct ConfigEdit {
    new_text: String,
    mapping_fragment: String,
}

/// Resolve the existing `nuget.config` (prefer lowercase `nuget.config`, then
/// `NuGet.Config`), or `None` when the project has none.
async fn existing_config_path(project_root: &Path) -> Option<PathBuf> {
    for name in ["nuget.config", "NuGet.Config"] {
        let p = project_root.join(name);
        if tokio::fs::metadata(&p).await.is_ok() {
            return Some(p);
        }
    }
    None
}

/// Build the wired `nuget.config` text. Creating from scratch seeds the default
/// nuget.org source so the load-bearing catch-all has a target; editing an
/// existing file inserts our source (and, only when no `packageSourceMapping`
/// existed, the catch-all over its pre-existing sources).
fn build_config_edit(
    original: Option<&str>,
    source_key: &str,
    source_rel: &str,
    patched_id: &str,
) -> Result<ConfigEdit, String> {
    let mapping_fragment = format!(
        "    <packageSource key=\"{source_key}\">\n      <package pattern=\"{patched_id}\" />\n    </packageSource>\n"
    );
    match original {
        None => {
            // Fresh config: nuget.org (the implicit default) is seeded as the
            // catch-all target, our source added, and the mapping routes the
            // patched id to us while `*` keeps everything else on nuget.org.
            let text = format!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
                 <configuration>\n\
                 \x20 <packageSources>\n\
                 \x20   <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n\
                 \x20   <add key=\"{source_key}\" value=\"{source_rel}\" />\n\
                 \x20 </packageSources>\n\
                 \x20 <packageSourceMapping>\n\
                 \x20   <packageSource key=\"nuget.org\">\n\
                 \x20     <package pattern=\"*\" />\n\
                 \x20   </packageSource>\n\
                 \x20   <packageSource key=\"{source_key}\">\n\
                 \x20     <package pattern=\"{patched_id}\" />\n\
                 \x20   </packageSource>\n\
                 \x20 </packageSourceMapping>\n\
                 </configuration>\n"
            );
            Ok(ConfigEdit {
                new_text: text,
                mapping_fragment,
            })
        }
        Some(text) => {
            // Whether we are about to CREATE the mapping section (vs. extend an
            // existing one) — decided against the pre-edit text.
            let creating_mapping = !text.contains("</packageSourceMapping>");
            // The pre-existing sources the catch-all fans `*` out to. When the
            // config has NONE and we are creating a mapping from scratch, a
            // socket-only mapping would NU1100 every other package, so seed the
            // implicit default nuget.org source (unless already present) and map
            // `*` to it. Mirrors redirect::add_nuget_source.
            let mut catch_all_keys = parse_config_source_keys(text);
            let seed_nuget_org = creating_mapping
                && catch_all_keys.is_empty()
                && !text.contains(NUGET_ORG_SOURCE_KEY);

            let source_add = format!("    <add key=\"{source_key}\" value=\"{source_rel}\" />\n");
            let org_add = format!(
                "    <add key=\"{NUGET_ORG_SOURCE_KEY}\" value=\"{NUGET_ORG_SOURCE_URL}\" />\n"
            );
            // The sources we inject: the seeded nuget.org (when needed) then our
            // vendored source.
            let injected_sources = if seed_nuget_org {
                catch_all_keys.push(NUGET_ORG_SOURCE_KEY.to_string());
                format!("{org_add}{source_add}")
            } else {
                source_add
            };
            // 1. Insert into <packageSources> (or create the section). A
            //    self-closing `<packageSources />` carries no children, so
            //    expand it in place into an open/close pair rather than leaving
            //    it dangling beside a duplicate element.
            let with_source = if let Some((start, end)) = self_closing_package_sources(text) {
                let mut expanded = String::with_capacity(text.len() + injected_sources.len() + 40);
                expanded.push_str(&text[..start]);
                expanded.push_str(&format!(
                    "<packageSources>\n{injected_sources}  </packageSources>"
                ));
                expanded.push_str(&text[end..]);
                expanded
            } else if text.contains("</packageSources>") {
                insert_before(text, "</packageSources>", &injected_sources).ok_or_else(|| {
                    "could not locate </packageSources> to insert the vendored source".to_string()
                })?
            } else if text.contains("</configuration>") {
                let block = format!("  <packageSources>\n{injected_sources}  </packageSources>\n");
                insert_before(text, "</configuration>", &block).ok_or_else(|| {
                    "could not locate </configuration> to insert a packageSources section"
                        .to_string()
                })?
            } else {
                return Err("nuget.config has no </configuration> to edit".to_string());
            };
            // 2. Mapping: extend an existing section, or create one over the
            //    pre-existing sources (the load-bearing catch-all).
            let new_text = if !creating_mapping {
                insert_before(&with_source, "</packageSourceMapping>", &mapping_fragment)
                    .ok_or_else(|| {
                        "could not locate </packageSourceMapping> to insert the mapping".to_string()
                    })?
            } else {
                let mut block = String::from("  <packageSourceMapping>\n");
                for key in &catch_all_keys {
                    block.push_str(&format!(
                        "    <packageSource key=\"{key}\">\n      <package pattern=\"*\" />\n    </packageSource>\n"
                    ));
                }
                block.push_str(&mapping_fragment);
                block.push_str("  </packageSourceMapping>\n");
                insert_before(&with_source, "</configuration>", &block).ok_or_else(|| {
                    "could not locate </configuration> to insert a packageSourceMapping section"
                        .to_string()
                })?
            };
            Ok(ConfigEdit {
                new_text,
                mapping_fragment,
            })
        }
    }
}

/// Extract the `key` attribute of every `<add ... />` element inside
/// `<packageSources>`. Deliberately minimal (no XML parser dependency): scans
/// the packageSources span for `<add ... key="..." ...>` elements. These are
/// the "pre-existing sources" the catch-all maps `*` to.
fn parse_config_source_keys(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(start) = text.find("<packageSources") else {
        return out;
    };
    let end = text[start..]
        .find("</packageSources>")
        .map(|e| start + e)
        .unwrap_or(text.len());
    let span = &text[start..end];
    let mut rest = span;
    while let Some(add_at) = rest.find("<add") {
        let after = &rest[add_at + 4..];
        // The element ends at the next '>'.
        let elem_end = after.find('>').unwrap_or(after.len());
        let elem = &after[..elem_end];
        if let Some(key) = attr_value(elem, "key") {
            if !out.contains(&key) {
                out.push(key);
            }
        }
        rest = &after[elem_end..];
    }
    out
}

/// The value of `<attr>="..."` inside an element's attribute text, if present.
fn attr_value(elem: &str, attr: &str) -> Option<String> {
    let needle = format!("{attr}=\"");
    let at = elem.find(&needle)?;
    let after = &elem[at + needle.len()..];
    let close = after.find('"')?;
    Some(after[..close].to_string())
}

/// The `[start, end)` byte span of a self-closing `<packageSources />` element
/// (any whitespace before `/>`), or `None` if the config has no such element.
/// Deliberately minimal (no XML parser dependency), matching the rest of this
/// module's scanning style.
fn self_closing_package_sources(text: &str) -> Option<(usize, usize)> {
    let start = text.find("<packageSources")?;
    // What immediately follows the tag name must be whitespace then `/>` for a
    // self-closing element — anything else (`>` or an attribute) is a normal
    // open tag, which the caller handles separately.
    let after_name = &text[start + "<packageSources".len()..];
    // trim_start guarantees only whitespace between the name and `/>`, so a
    // `<packageSources>` open tag or `<packageSourcesFoo` prefix won't match.
    let rest = after_name.trim_start().strip_prefix("/>")?;
    let end = text.len() - rest.len();
    Some((start, end))
}

/// Revert our `nuget.config` wiring. `Ok(true)` = reverted (or would be on dry
/// run) / already gone; `Ok(false)` = drifted (the live config no longer carries
/// our source key), left alone; `Err` = a real I/O failure.
///
/// FRAGMENT-LEVEL: the whole-file `w.original` restore (or, for a config we
/// created, deleting the file) is only taken on the provably-safe fast path
/// where the live config is still byte-identical to what we wrote (`w.new`), so
/// nothing else has changed. Otherwise — a sibling patch added its own
/// `<add>`/`<packageSource>`, or the user hand-edited AFTER vendoring — we
/// surgically excise ONLY the two elements we authored (our source `<add>` line
/// and our `<packageSource key="…">` mapping block, both anchored on our
/// `source_key` so they are matched verbatim) and leave every other byte
/// intact. The catch-all mappings a fresh section may carry are left in place:
/// on the fast path they vanish with the whole-file restore, and when a sibling
/// is present they are load-bearing for it. A config that no longer carries our
/// source key at all is third-party state, left alone with a drift warning.
async fn revert_config_record(
    project_root: &Path,
    uuid_dir_rel: &str,
    w: &WiringRecord,
    dry_run: bool,
) -> Result<bool, String> {
    let config_path = project_root.join(&w.file);
    let Some(source_key) = w.key.as_deref() else {
        return Ok(false);
    };
    let live = match tokio::fs::read_to_string(&config_path).await {
        Ok(live) => live,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Already gone — nothing to restore (we created it and it is gone,
            // or a prior revert removed it). Treat as done.
            return Ok(true);
        }
        Err(e) => return Err(format!("unreadable {}: {e}", config_path.display())),
    };

    // (a) Byte-identical to what we wrote → the whole-file restore/delete is
    //     provably safe (nothing changed since vendoring).
    let new_matches = matches!(&w.new, Some(Value::String(n)) if *n == live);
    if new_matches {
        if dry_run {
            return Ok(true);
        }
        match &w.original {
            // Pre-existed → restore the verbatim original bytes.
            Some(Value::String(orig)) => {
                atomic_write_bytes(&config_path, orig.as_bytes())
                    .await
                    .map_err(|e| format!("failed to restore {}: {e}", config_path.display()))?;
            }
            // Created by us → delete the file.
            _ => match tokio::fs::remove_file(&config_path).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("failed to remove {}: {e}", config_path.display())),
            },
        }
        return Ok(true);
    }

    // (b) The file diverged but our source is still present → excise ONLY our
    //     two authored elements. Both are reproduced verbatim from the source
    //     key + uuid dir (the source `<add>`) and matched structurally by our
    //     source key (the mapping `<packageSource>`).
    let source_add = format!("    <add key=\"{source_key}\" value=\"{uuid_dir_rel}\" />\n");
    let mapping_block = excise_source_mapping(&live, source_key);
    if !live.contains(&source_add) && mapping_block.is_none() {
        // (c) Neither authored element is present verbatim → drift, leave alone.
        return Ok(false);
    }
    if dry_run {
        return Ok(true);
    }
    let mut out = live.replacen(&source_add, "", 1);
    if let Some(block) = mapping_block {
        out = out.replacen(&block, "", 1);
    }
    atomic_write_bytes(&config_path, out.as_bytes())
        .await
        .map_err(|e| {
            format!(
                "failed to excise the vendored source from {}: {e}",
                config_path.display()
            )
        })?;
    Ok(true)
}

/// The exact `<packageSource key="{source_key}"> … </packageSource>\n` block we
/// authored in the mapping section, if present verbatim in `config`. Anchored on
/// our source key and closed at the first `</packageSource>` after it, then
/// extended through the trailing newline so the excision leaves no blank line.
/// `None` when our mapping block is absent (already reverted, or edited).
fn excise_source_mapping(config: &str, source_key: &str) -> Option<String> {
    let open = format!("    <packageSource key=\"{source_key}\">\n");
    let open_at = config.find(&open)?;
    let close = "    </packageSource>\n";
    let rel_close = config[open_at..].find(close)?;
    let end = open_at + rel_close + close.len();
    Some(config[open_at..end].to_string())
}

// ── packages.lock.json editing ──────────────────────────────────────────────────

/// The applied lock edit plus the verbatim original `contentHash` for revert.
struct LockEdit {
    text: String,
    original_hash: String,
}

/// Rewrite `contentHash` to `new_hash` for every framework entry of `id`
/// (case-insensitive) whose `resolved` equals `version_norm`. Returns
/// `Ok(Some(edit))` when a rewrite happened, `Ok(None)` when the lock has no
/// matching resolved entry (nothing to pin), `Err` on parse failure.
///
/// The rewrite is targeted string surgery on the (unique, 88-char base64
/// sha512) old hash value so all other bytes — key order, indentation — are
/// preserved and a later revert restores the file byte-identically.
fn edit_lock(
    text: &str,
    id: &str,
    version_norm: &str,
    new_hash: &str,
) -> Result<Option<LockEdit>, String> {
    let value: Value =
        serde_json::from_str(text).map_err(|e| format!("unparseable {PACKAGES_LOCK}: {e}"))?;
    let Some(deps) = value.get("dependencies").and_then(Value::as_object) else {
        return Ok(None);
    };
    // Collect the original hash of every matching (framework, id) entry.
    let mut old_hash: Option<String> = None;
    for framework in deps.values() {
        let Some(pkgs) = framework.as_object() else {
            continue;
        };
        for (pkg_name, entry) in pkgs {
            if !pkg_name.eq_ignore_ascii_case(id) {
                continue;
            }
            let resolved = entry.get("resolved").and_then(Value::as_str);
            if resolved.map(normalize_nuget_version).as_deref() != Some(version_norm) {
                continue;
            }
            if let Some(h) = entry.get("contentHash").and_then(Value::as_str) {
                match &old_hash {
                    // All matching entries share the same package version, so
                    // the same nupkg and the same contentHash — a divergence
                    // means the lock disagrees with itself; fail closed.
                    Some(prev) if prev != h => {
                        return Err(format!(
                            "{PACKAGES_LOCK} has conflicting contentHash values for {id} {version_norm}"
                        ));
                    }
                    _ => old_hash = Some(h.to_string()),
                }
            }
        }
    }
    let Some(old_hash) = old_hash else {
        return Ok(None);
    };
    if old_hash == *new_hash {
        // Already pinned at our bytes (idempotent) — no rewrite needed, but
        // report it so the caller records the (identity) wiring for revert.
        return Ok(Some(LockEdit {
            text: text.to_string(),
            original_hash: old_hash,
        }));
    }
    // The base64 sha512 is unique, so replacing the quoted value is safe and
    // hits every framework entry that shares it.
    let new_text = text.replace(&format!("\"{old_hash}\""), &format!("\"{new_hash}\""));
    Ok(Some(LockEdit {
        text: new_text,
        original_hash: old_hash,
    }))
}

/// True when the lock already pins `id` at `expected_hash` for the matching
/// resolved version (the hot-path in-sync check).
fn lock_pinned(text: &str, id: &str, version_norm: &str, expected_hash: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    let Some(deps) = value.get("dependencies").and_then(Value::as_object) else {
        return false;
    };
    let mut matched = false;
    for framework in deps.values() {
        let Some(pkgs) = framework.as_object() else {
            continue;
        };
        for (pkg_name, entry) in pkgs {
            if !pkg_name.eq_ignore_ascii_case(id) {
                continue;
            }
            let resolved = entry.get("resolved").and_then(Value::as_str);
            if resolved.map(normalize_nuget_version).as_deref() != Some(version_norm) {
                continue;
            }
            matched = true;
            if entry.get("contentHash").and_then(Value::as_str) != Some(expected_hash) {
                return false;
            }
        }
    }
    matched
}

/// Restore a `nuget_lock_entry` record's original `contentHash`. `Ok(true)` =
/// restored (or would be on dry run) / already restored; `Ok(false)` = drifted
/// (neither our value nor the original is present); `Err` = I/O failure.
async fn revert_lock_record(
    lock_path: &Path,
    w: &WiringRecord,
    dry_run: bool,
) -> Result<bool, String> {
    let (Some(Value::String(orig)), Some(Value::String(ours))) = (&w.original, &w.new) else {
        return Ok(false);
    };
    if orig == ours {
        return Ok(true); // identity pin — nothing to undo
    }
    let text = match tokio::fs::read_to_string(lock_path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("unreadable {}: {e}", lock_path.display())),
    };
    let ours_q = format!("\"{ours}\"");
    if !text.contains(&ours_q) {
        // Our value is gone. If the original is already present, a prior revert
        // (shared across framework entries) restored it — done; else drift.
        return Ok(text.contains(&format!("\"{orig}\"")));
    }
    if dry_run {
        return Ok(true);
    }
    let restored = text.replace(&ours_q, &format!("\"{orig}\""));
    atomic_write_bytes(lock_path, restored.as_bytes())
        .await
        .map_err(|e| format!("failed to restore {}: {e}", lock_path.display()))?;
    Ok(true)
}

/// Restore the config to its pre-vendor state (or delete a created file) after
/// a later wiring step failed, then remove the partial uuid dir.
async fn unwind_config(config_target: &Path, original: Option<&str>, uuid_dir: &Path) {
    match original {
        Some(orig) => {
            let _ = atomic_write_bytes(config_target, orig.as_bytes()).await;
        }
        None => {
            let _ = tokio::fs::remove_file(config_target).await;
        }
    }
    let _ = remove_tree(uuid_dir).await;
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::{Read as _, Write as _};

    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::PatchFileInfo;
    use crate::patch::vendor::state::VENDOR_MARKER_FILE;
    use serde_json::json;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const PURL: &str = "pkg:nuget/Newtonsoft.Json@13.0.3";
    const PRISTINE: &[u8] = b"The MIT License (MIT)\nCopyright (c) 2007 James Newton-King\n";
    const PATCHED: &[u8] =
        b"The MIT License (MIT)\n// SOCKET-PATCH-MARKER\nCopyright (c) 2007 James Newton-King\n";

    fn copy_rel() -> String {
        format!(".socket/vendor/nuget/{UUID}/newtonsoft.json.13.0.3.nupkg")
    }

    // ── normalize_nuget_version: pinned against the documented TS vectors ──

    #[test]
    fn normalize_matches_documented_vectors() {
        assert_eq!(normalize_nuget_version("1.0.0.0"), "1.0.0");
        assert_eq!(normalize_nuget_version("1.0"), "1.0.0");
        assert_eq!(normalize_nuget_version("1.02.3"), "1.2.3");
        assert_eq!(normalize_nuget_version("1.0.0-Beta+build"), "1.0.0-beta");
        // A plain three-part release is unchanged; a prerelease with dots keeps
        // its inner dots; a non-zero 4th segment is retained.
        assert_eq!(normalize_nuget_version("13.0.3"), "13.0.3");
        assert_eq!(normalize_nuget_version("2.0.0-RC.1"), "2.0.0-rc.1");
        assert_eq!(normalize_nuget_version("1.2.3.4"), "1.2.3.4");
    }

    // ── nuget.config surgery ───────────────────────────────────────────────

    fn source_key() -> String {
        format!("socket-patch-{UUID}")
    }

    #[test]
    fn fresh_config_seeds_org_and_maps_id() {
        let edit = build_config_edit(
            None,
            &source_key(),
            &format!(".socket/vendor/nuget/{UUID}"),
            "Newtonsoft.Json",
        )
        .unwrap();
        let t = &edit.new_text;
        assert!(t.contains(&format!("<add key=\"{}\"", source_key())));
        assert!(t.contains("key=\"nuget.org\""));
        assert!(t.contains("<packageSourceMapping>"));
        // The load-bearing catch-all AND the specific id mapping are present.
        assert!(t.contains("<package pattern=\"*\" />"));
        assert!(t.contains("<package pattern=\"Newtonsoft.Json\" />"));
        assert!(t.trim_end().ends_with("</configuration>"));
    }

    #[test]
    fn existing_config_without_mapping_gets_catch_all() {
        // A user config with a private feed and NO packageSourceMapping: our
        // edit must add a catch-all mapping `*` to the pre-existing sources
        // (else every non-patched package NU1100s) plus the id → our source.
        let orig = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
                    <configuration>\n\
                    \x20 <packageSources>\n\
                    \x20   <add key=\"corp\" value=\"https://corp/nuget/v3/index.json\" />\n\
                    \x20 </packageSources>\n\
                    </configuration>\n";
        let edit = build_config_edit(
            Some(orig),
            &source_key(),
            &format!(".socket/vendor/nuget/{UUID}"),
            "Newtonsoft.Json",
        )
        .unwrap();
        let t = &edit.new_text;
        assert!(t.contains(&format!("<add key=\"{}\"", source_key())));
        assert!(
            t.contains("<packageSource key=\"corp\">"),
            "catch-all target: {t}"
        );
        assert!(t.contains("<package pattern=\"*\" />"));
        assert!(t.contains("<package pattern=\"Newtonsoft.Json\" />"));
        // The original corp source survives.
        assert!(t.contains("key=\"corp\" value=\"https://corp/nuget/v3/index.json\""));
    }

    #[test]
    fn existing_config_empty_sources_seeds_org_catch_all() {
        // A config with an EMPTY <packageSources> and no mapping: a from-scratch
        // mapping would be socket-only → NU1100 for every other package. Our
        // edit must seed nuget.org as a source AND map `*` to it.
        let orig = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
                    <configuration>\n\
                    \x20 <packageSources>\n\
                    \x20 </packageSources>\n\
                    </configuration>\n";
        let edit = build_config_edit(
            Some(orig),
            &source_key(),
            &format!(".socket/vendor/nuget/{UUID}"),
            "Newtonsoft.Json",
        )
        .unwrap();
        let t = &edit.new_text;
        // nuget.org seeded as a real source...
        assert!(
            t.contains("<add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />"),
            "nuget.org source seeded: {t}"
        );
        // ...and mapped `*`.
        assert!(
            t.contains(
                "    <packageSource key=\"nuget.org\">\n      <package pattern=\"*\" />\n    </packageSource>"
            ),
            "nuget.org catch-all present: {t}"
        );
        assert!(t.contains(&format!("<add key=\"{}\"", source_key())));
        assert!(t.contains("<package pattern=\"Newtonsoft.Json\" />"));
        // Exactly one catch-all (no phantom-source fan-out).
        assert_eq!(t.matches("<package pattern=\"*\" />").count(), 1);
    }

    #[test]
    fn existing_config_self_closing_sources_expanded_in_place() {
        // A SELF-CLOSING <packageSources /> must be expanded in place, not left
        // dangling beside a duplicate element. Output is byte-identical to the
        // open-but-empty form (the tag shape is cosmetic once expanded).
        let build = |sources_xml: &str| {
            let orig = format!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  {sources_xml}\n</configuration>\n"
            );
            build_config_edit(
                Some(&orig),
                &source_key(),
                &format!(".socket/vendor/nuget/{UUID}"),
                "Newtonsoft.Json",
            )
            .unwrap()
            .new_text
        };
        let sc = build("<packageSources />");
        let sc_tight = build("<packageSources/>");
        let open = build("<packageSources>\n  </packageSources>");

        assert_eq!(sc, open, "self-closing (space) matches open-empty bytes");
        assert_eq!(
            sc_tight, open,
            "self-closing (no space) matches open-empty bytes"
        );
        // Single opening <packageSources> element — no dangling duplicate.
        assert_eq!(
            sc.matches("<packageSources>").count(),
            1,
            "single packageSources element: {sc}"
        );
        assert!(!sc.contains("<packageSources />"));
        assert!(!sc.contains("<packageSources/>"));
        // nuget.org seeded + mapped, socket mapping present.
        assert!(sc.contains("<add key=\"nuget.org\""));
        assert!(sc.contains(
            "    <packageSource key=\"nuget.org\">\n      <package pattern=\"*\" />\n    </packageSource>"
        ));
        assert!(sc.contains(&format!("<add key=\"{}\"", source_key())));
    }

    #[test]
    fn existing_config_with_mapping_only_appends_id() {
        // A config that ALREADY has a mapping (an exclusive world): we only
        // append the id → our source; no new catch-all (the user owns `*`).
        let orig = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
                    <configuration>\n\
                    \x20 <packageSources>\n\
                    \x20   <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n\
                    \x20 </packageSources>\n\
                    \x20 <packageSourceMapping>\n\
                    \x20   <packageSource key=\"nuget.org\">\n\
                    \x20     <package pattern=\"*\" />\n\
                    \x20   </packageSource>\n\
                    \x20 </packageSourceMapping>\n\
                    </configuration>\n";
        let edit = build_config_edit(
            Some(orig),
            &source_key(),
            &format!(".socket/vendor/nuget/{UUID}"),
            "Newtonsoft.Json",
        )
        .unwrap();
        let t = &edit.new_text;
        assert!(t.contains(&format!("<packageSource key=\"{}\">", source_key())));
        assert!(t.contains("<package pattern=\"Newtonsoft.Json\" />"));
        // Exactly one catch-all (the user's) — we didn't add another.
        assert_eq!(t.matches("<package pattern=\"*\" />").count(), 1);
    }

    #[test]
    fn parse_config_source_keys_reads_adds() {
        let text = "<configuration><packageSources>\
                    <add key=\"a\" value=\"x\" /><add key=\"b\" value=\"y\" />\
                    </packageSources></configuration>";
        assert_eq!(parse_config_source_keys(text), vec!["a", "b"]);
    }

    // ── packages.lock.json surgery ─────────────────────────────────────────

    fn lock_json(content_hash: &str) -> String {
        // Two frameworks referencing the same resolved version share one hash.
        serde_json::to_string_pretty(&json!({
            "version": 1,
            "dependencies": {
                "net8.0": {
                    "Newtonsoft.Json": {
                        "type": "Direct",
                        "requested": "[13.0.3, )",
                        "resolved": "13.0.3",
                        "contentHash": content_hash
                    }
                },
                "net6.0": {
                    "Newtonsoft.Json": {
                        "type": "Direct",
                        "requested": "[13.0.3, )",
                        "resolved": "13.0.3",
                        "contentHash": content_hash
                    }
                }
            }
        }))
        .unwrap()
    }

    #[test]
    fn edit_lock_repins_all_matching_frameworks() {
        let orig_hash = "AAAAoriginalhashvalue==";
        let lock = lock_json(orig_hash);
        let edit = edit_lock(&lock, "Newtonsoft.Json", "13.0.3", "ZZZZnewhashvalue==")
            .unwrap()
            .expect("a matching entry");
        assert_eq!(edit.original_hash, orig_hash);
        assert_eq!(
            edit.text.matches("ZZZZnewhashvalue==").count(),
            2,
            "both frameworks repinned"
        );
        assert!(!edit.text.contains(orig_hash));
        // resolved untouched.
        assert_eq!(edit.text.matches("\"resolved\": \"13.0.3\"").count(), 2);
    }

    #[test]
    fn edit_lock_case_insensitive_id_and_version_mismatch_skipped() {
        let lock = lock_json("HHHHhash==");
        // Case-insensitive id match.
        assert!(edit_lock(&lock, "newtonsoft.json", "13.0.3", "NEW==")
            .unwrap()
            .is_some());
        // A different resolved version is not our package → nothing to pin.
        assert!(edit_lock(&lock, "Newtonsoft.Json", "12.0.0", "NEW==")
            .unwrap()
            .is_none());
    }

    #[test]
    fn lock_pinned_reports_sync_state() {
        let lock = lock_json("PINNEDhash==");
        assert!(lock_pinned(
            &lock,
            "Newtonsoft.Json",
            "13.0.3",
            "PINNEDhash=="
        ));
        assert!(!lock_pinned(&lock, "Newtonsoft.Json", "13.0.3", "OTHER=="));
        assert!(!lock_pinned(&lock, "Missing.Pkg", "1.0.0", "x"));
    }

    // ── full vendor / revert against a real .nupkg fixture ─────────────────

    /// A minimal but valid `.nupkg` (OPC zip): `[Content_Types].xml`,
    /// `_rels/.rels`, the `.nuspec`, a `.signature.p7s` to prove it is dropped,
    /// and `LICENSE.md` (the patch target).
    fn make_nupkg(license: &[u8]) -> Vec<u8> {
        let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        let files: &[(&str, &[u8])] = &[
            ("[Content_Types].xml", b"<?xml version=\"1.0\"?><Types/>"),
            ("_rels/.rels", b"<?xml version=\"1.0\"?><Relationships/>"),
            (
                "Newtonsoft.Json.nuspec",
                b"<?xml version=\"1.0\"?><package><metadata><id>Newtonsoft.Json</id><version>13.0.3</version></metadata></package>",
            ),
            (".signature.p7s", b"FAKE-SIGNATURE-BYTES"),
            ("lib/net6.0/Newtonsoft.Json.dll", b"MZ-fake-assembly"),
            ("LICENSE.md", license),
        ];
        for (name, bytes) in files {
            zw.start_file(*name, opts).unwrap();
            zw.write_all(bytes).unwrap();
        }
        zw.finish().unwrap().into_inner()
    }

    async fn fixture(
        with_lock: bool,
        with_config: Option<&str>,
    ) -> (tempfile::TempDir, PathBuf, PathBuf, PatchRecord) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Installed package dir: the global-cache layout keeps the pristine
        // cached .nupkg alongside the EXTRACTED package files (the dry-run
        // verify + the apply path read these), plus NuGet's sidecars.
        let installed = root.join("packages/newtonsoft.json/13.0.3");
        tokio::fs::create_dir_all(installed.join("lib/net6.0"))
            .await
            .unwrap();
        tokio::fs::write(
            installed.join("newtonsoft.json.13.0.3.nupkg"),
            make_nupkg(PRISTINE),
        )
        .await
        .unwrap();
        // Extracted files (what NuGet lays down beside the cached nupkg).
        tokio::fs::write(installed.join("LICENSE.md"), PRISTINE)
            .await
            .unwrap();
        tokio::fs::write(
            installed.join("lib/net6.0/Newtonsoft.Json.dll"),
            b"MZ-fake-assembly",
        )
        .await
        .unwrap();
        // NuGet cache sidecars that must NOT be mistaken for the package.
        tokio::fs::write(installed.join("newtonsoft.json.13.0.3.nupkg.sha512"), b"x")
            .await
            .unwrap();

        // Blob store carrying the patched LICENSE.md.
        let after = compute_git_sha256_from_bytes(PATCHED);
        let blobs = root.join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        tokio::fs::write(blobs.join(&after), PATCHED).await.unwrap();

        if with_lock {
            tokio::fs::write(root.join(PACKAGES_LOCK), lock_json("ORIGINALcachedhash=="))
                .await
                .unwrap();
        }
        if let Some(cfg) = with_config {
            tokio::fs::write(root.join("nuget.config"), cfg)
                .await
                .unwrap();
        }

        let mut files = HashMap::new();
        files.insert(
            "LICENSE.md".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(PRISTINE),
                after_hash: after,
            },
        );
        let mut vulnerabilities = HashMap::new();
        vulnerabilities.insert(
            "GHSA-vend-nuget-real".to_string(),
            crate::manifest::schema::VulnerabilityInfo {
                cves: Vec::new(),
                summary: String::new(),
                severity: String::new(),
                description: String::new(),
            },
        );
        let record = PatchRecord {
            uuid: UUID.to_string(),
            exported_at: "2026-06-09T00:00:00Z".to_string(),
            files,
            vulnerabilities,
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        };
        (dir, blobs, installed, record)
    }

    fn unwrap_done(o: VendorOutcome) -> (ApplyResult, Option<VendorEntry>, Vec<VendorWarning>) {
        match o {
            VendorOutcome::Done {
                result,
                entry,
                warnings,
            } => (result, entry, warnings),
            VendorOutcome::Refused { code, detail } => panic!("refused: {code}: {detail}"),
        }
    }

    fn unwrap_refused(o: VendorOutcome) -> (&'static str, String) {
        match o {
            VendorOutcome::Refused { code, detail } => (code, detail),
            VendorOutcome::Done { result, .. } => panic!("not refused: {result:?}"),
        }
    }

    async fn run_vendor(
        root: &Path,
        blobs: &Path,
        installed: &Path,
        record: &PatchRecord,
        dry_run: bool,
    ) -> VendorOutcome {
        let sources = PatchSources::blobs_only(blobs);
        vendor_nuget(
            PURL,
            installed,
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

    fn read_nupkg_entry(bytes: &[u8], name: &str) -> Option<Vec<u8>> {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).ok()?;
        let mut f = archive.by_name(name).ok()?;
        let mut out = Vec::new();
        f.read_to_end(&mut out).ok()?;
        Some(out)
    }

    #[tokio::test]
    async fn happy_path_wires_config_lock_and_artifact() {
        let (dir, blobs, installed, record) = fixture(true, None).await;
        let root = dir.path();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);

        // Artifact: rebuilt nupkg with the patched LICENSE.md, signature dropped.
        let nupkg = tokio::fs::read(root.join(copy_rel())).await.unwrap();
        assert_eq!(
            read_nupkg_entry(&nupkg, "LICENSE.md").as_deref(),
            Some(PATCHED)
        );
        assert!(
            read_nupkg_entry(&nupkg, ".signature.p7s").is_none(),
            "signature dropped"
        );
        assert!(read_nupkg_entry(&nupkg, "Newtonsoft.Json.nuspec").is_some());

        // Marker + ledger.
        let marker = root.join(format!(".socket/vendor/nuget/{UUID}/{VENDOR_MARKER_FILE}"));
        assert!(marker.exists());

        // nuget.config created with our source + the id mapping.
        let cfg = tokio::fs::read_to_string(root.join("nuget.config"))
            .await
            .unwrap();
        assert!(cfg.contains(&format!("socket-patch-{UUID}")));
        assert!(cfg.contains("<package pattern=\"Newtonsoft.Json\" />"));

        // packages.lock.json repinned to base64(sha512(nupkg)).
        let want_hash = content_hash(&nupkg);
        let lock = tokio::fs::read_to_string(root.join(PACKAGES_LOCK))
            .await
            .unwrap();
        assert!(lock.contains(&want_hash), "lock repinned: {lock}");
        assert!(!lock.contains("ORIGINALcachedhash=="));

        // Ledger entry shape.
        let entry = entry.expect("success carries a ledger entry");
        assert_eq!(entry.ecosystem, "nuget");
        assert_eq!(entry.base_purl, PURL);
        assert_eq!(entry.artifact.path, copy_rel());
        // source (Added — created), mapping (audit), lock (Rewritten).
        assert_eq!(entry.wiring.len(), 3);
        assert_eq!(entry.wiring[0].kind, CONFIG_SOURCE_WIRING_KIND);
        assert_eq!(entry.wiring[0].action, WiringAction::Added);
        assert_eq!(entry.wiring[1].kind, CONFIG_MAPPING_WIRING_KIND);
        assert_eq!(entry.wiring[2].kind, LOCK_WIRING_KIND);
    }

    #[tokio::test]
    async fn rerun_is_idempotent_no_rerecord() {
        let (dir, blobs, installed, record) = fixture(true, None).await;
        let root = dir.path();

        let (r1, e1, _) = unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
        assert!(r1.success);
        assert!(e1.is_some());
        let cfg1 = tokio::fs::read(root.join("nuget.config")).await.unwrap();
        let lock1 = tokio::fs::read(root.join(PACKAGES_LOCK)).await.unwrap();
        let nupkg1 = tokio::fs::read(root.join(copy_rel())).await.unwrap();

        let (r2, e2, _) = unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
        assert!(r2.success);
        assert!(e2.is_none(), "in-sync rerun must not re-record the ledger");
        assert_eq!(
            tokio::fs::read(root.join("nuget.config")).await.unwrap(),
            cfg1
        );
        assert_eq!(
            tokio::fs::read(root.join(PACKAGES_LOCK)).await.unwrap(),
            lock1
        );
        assert_eq!(
            tokio::fs::read(root.join(copy_rel())).await.unwrap(),
            nupkg1,
            "re-zip is deterministic"
        );
    }

    #[tokio::test]
    async fn revert_created_config_deletes_it_and_restores_lock() {
        let (dir, blobs, installed, record) = fixture(true, None).await;
        let root = dir.path();
        let lock_before = tokio::fs::read(root.join(PACKAGES_LOCK)).await.unwrap();

        let (_r, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
        let entry = entry.unwrap();
        assert!(root.join("nuget.config").exists());

        let outcome = revert_nuget(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !root.join("nuget.config").exists(),
            "a created nuget.config is deleted on revert"
        );
        assert_eq!(
            tokio::fs::read(root.join(PACKAGES_LOCK)).await.unwrap(),
            lock_before,
            "packages.lock.json restored byte-identically"
        );
        assert!(
            !root.join(format!(".socket/vendor/nuget/{UUID}")).exists(),
            "uuid dir removed"
        );
    }

    #[tokio::test]
    async fn revert_restores_preexisting_config_byte_identical() {
        let orig_cfg = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
                        <configuration>\n\
                        \x20 <packageSources>\n\
                        \x20   <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n\
                        \x20 </packageSources>\n\
                        </configuration>\n";
        let (dir, blobs, installed, record) = fixture(true, Some(orig_cfg)).await;
        let root = dir.path();

        let (_r, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
        let entry = entry.unwrap();
        // Our source landed; action is Rewritten (file pre-existed).
        assert_eq!(entry.wiring[0].action, WiringAction::Rewritten);
        assert_ne!(
            tokio::fs::read_to_string(root.join("nuget.config"))
                .await
                .unwrap(),
            orig_cfg,
            "vendor rewired the config"
        );

        let outcome = revert_nuget(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join("nuget.config"))
                .await
                .unwrap(),
            orig_cfg,
            "pre-existing nuget.config restored byte-identically"
        );
    }

    #[tokio::test]
    async fn revert_excises_only_our_source_preserving_sibling() {
        // A pre-existing config. Vendor wires OUR source + mapping. Then a
        // sibling vendor run adds ITS OWN source + mapping (simulated by the
        // same insertion shape). Reverting us must excise ONLY our source
        // `<add>` and our `<packageSource>` mapping, keeping the sibling's —
        // the old whole-file restore would have wiped the sibling entirely.
        let orig_cfg = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
                        <configuration>\n\
                        \x20 <packageSources>\n\
                        \x20   <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n\
                        \x20 </packageSources>\n\
                        </configuration>\n";
        let (dir, blobs, installed, record) = fixture(true, Some(orig_cfg)).await;
        let root = dir.path();

        let (_r, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
        let entry = entry.unwrap();

        // A sibling patch's source + mapping land in the config we edited.
        let wired = tokio::fs::read_to_string(root.join("nuget.config"))
            .await
            .unwrap();
        let sib_add =
            "    <add key=\"socket-patch-SIBLING\" value=\".socket/vendor/nuget/SIBLING\" />\n";
        let sib_map = "    <packageSource key=\"socket-patch-SIBLING\">\n      <package pattern=\"Some.Other.Pkg\" />\n    </packageSource>\n";
        let with_sibling = wired
            .replacen(
                "</packageSources>",
                &format!("{sib_add}  </packageSources>"),
                1,
            )
            .replacen(
                "</packageSourceMapping>",
                &format!("{sib_map}  </packageSourceMapping>"),
                1,
            );
        assert_ne!(with_sibling, wired, "sibling wiring inserted");
        tokio::fs::write(root.join("nuget.config"), &with_sibling)
            .await
            .unwrap();

        let outcome = revert_nuget(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "excising our source is not drift: {:?}",
            outcome.warnings
        );
        let after = tokio::fs::read_to_string(root.join("nuget.config"))
            .await
            .unwrap();
        assert!(
            !after.contains(&format!("socket-patch-{UUID}")),
            "our source + mapping excised: {after}"
        );
        assert!(
            after.contains("socket-patch-SIBLING") && after.contains("Some.Other.Pkg"),
            "sibling source + mapping preserved: {after}"
        );
        // The original nuget.org source survives untouched.
        assert!(after.contains("key=\"nuget.org\""));
    }

    #[tokio::test]
    async fn revert_warns_when_our_source_key_already_gone() {
        // The user regenerated nuget.config, dropping our source entirely.
        // Our source key is absent → drift, and we must not touch their file.
        let (dir, blobs, installed, record) = fixture(true, None).await;
        let root = dir.path();

        let (_r, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
        let entry = entry.unwrap();
        assert!(root.join("nuget.config").exists());

        let regenerated = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
                           <configuration>\n\
                           \x20 <packageSources>\n\
                           \x20   <add key=\"corp\" value=\"https://corp/nuget/v3/index.json\" />\n\
                           \x20 </packageSources>\n\
                           </configuration>\n";
        tokio::fs::write(root.join("nuget.config"), regenerated)
            .await
            .unwrap();

        let outcome = revert_nuget(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "our source gone → drift must be reported: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("nuget.config"))
                .await
                .unwrap(),
            regenerated,
            "the user's regenerated config is left alone"
        );
    }

    #[test]
    fn excise_source_mapping_matches_authored_block_only() {
        let cfg = "  <packageSourceMapping>\n\
                   \x20   <packageSource key=\"nuget.org\">\n\
                   \x20     <package pattern=\"*\" />\n\
                   \x20   </packageSource>\n\
                   \x20   <packageSource key=\"socket-patch-abc\">\n\
                   \x20     <package pattern=\"Newtonsoft.Json\" />\n\
                   \x20   </packageSource>\n\
                   \x20 </packageSourceMapping>\n";
        let block = excise_source_mapping(cfg, "socket-patch-abc").unwrap();
        assert!(block.contains("key=\"socket-patch-abc\""));
        assert!(block.contains("Newtonsoft.Json"));
        // Does not swallow the sibling nuget.org block.
        assert!(!block.contains("nuget.org"));
        // Absent key → None.
        assert!(excise_source_mapping(cfg, "socket-patch-missing").is_none());
    }

    #[tokio::test]
    async fn no_lockfile_still_wires_with_warning() {
        let (dir, blobs, installed, record) = fixture(false, None).await;
        let root = dir.path();

        let (result, entry, warnings) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());
        assert!(root.join("nuget.config").exists());
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_nuget_no_lockfile"),
            "missing lock is surfaced: {warnings:?}"
        );
        // No lock wiring record (only the two config records).
        assert_eq!(entry.unwrap().wiring.len(), 2);
    }

    #[tokio::test]
    async fn dry_run_writes_nothing() {
        let (dir, blobs, installed, record) = fixture(true, None).await;
        let root = dir.path();
        let lock_before = tokio::fs::read(root.join(PACKAGES_LOCK)).await.unwrap();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, true).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_none());
        assert!(!root.join(".socket").exists(), "no artifact created");
        assert!(!root.join("nuget.config").exists(), "no config created");
        assert_eq!(
            tokio::fs::read(root.join(PACKAGES_LOCK)).await.unwrap(),
            lock_before
        );
    }

    #[tokio::test]
    async fn refuses_unsafe_coordinates() {
        let (dir, blobs, installed, record) = fixture(true, None).await;
        let root = dir.path();
        let mut bad = record.clone();
        bad.uuid = "../../escape".to_string();
        let (code, _d) = unwrap_refused(run_vendor(root, &blobs, &installed, &bad, false).await);
        assert_eq!(code, "unsafe_coordinates");
        assert!(!root.join(".socket").exists(), "refusal writes nothing");

        // A traversal/injection in the coordinate name is refused too.
        let sources = PatchSources::blobs_only(&blobs);
        let (code, _d) = unwrap_refused(
            vendor_nuget(
                "pkg:nuget/../evil@1.0.0",
                &installed,
                root,
                &record,
                &sources,
                "t",
                false,
                false,
                None,
            )
            .await,
        );
        assert_eq!(code, "unsafe_coordinates");
    }

    #[tokio::test]
    async fn missing_cached_nupkg_refuses() {
        let (dir, blobs, installed, record) = fixture(true, None).await;
        let root = dir.path();
        // Remove the cached .nupkg so the rebuild has no pristine source.
        tokio::fs::remove_file(installed.join("newtonsoft.json.13.0.3.nupkg"))
            .await
            .unwrap();
        let (code, _d) = unwrap_refused(run_vendor(root, &blobs, &installed, &record, false).await);
        assert_eq!(code, "vendor_nupkg_not_found");
        assert!(!root.join(".socket").exists());
        assert!(!root.join("nuget.config").exists());
    }
}
