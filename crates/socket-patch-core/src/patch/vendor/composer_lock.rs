//! Composer vendor backend: lock-only `dist` surgery pointing at a committed
//! patched copy.
//!
//! Spike-verified mechanism (composer 2.10 — `spikes/PHASE0-FINDINGS.txt`):
//! edit ONLY `composer.lock`. `composer.json` is never touched, and the lock's
//! `content-hash` covers composer.json alone, so the surgery triggers no
//! "lock file out of date" warning. The package's lock entry is rewritten to:
//!
//! * `dist` → `{"type": "path", "url": "<rel copy dir>", "reference": null}`
//!   (replaced IN ITS ORIGINAL SLOT so the entry's key order is stable);
//! * `source` REMOVED entirely — left in place, `--prefer-source` could
//!   git-clone the unpatched upstream; with it removed the spike confirmed
//!   `--prefer-source` falls back to the path dist cleanly;
//! * `"transport-options": {"symlink": false}` inserted right after `dist` —
//!   LOAD-BEARING: composer's default path-repo strategy symlinks, and a
//!   symlink into `.socket/vendor/` would defeat the real-copy guarantee.
//!   `symlink: false` forces the 'Mirroring' (copy) strategy.
//!
//! Lock names are matched CASE-INSENSITIVELY (locks are normally lowercase,
//! but hand-written mixed-case locks exist and install fine) while the dist
//! URL we write always uses the lowercase canonical `<vendor>/<name>` — the
//! casing of the directory this backend creates. Versions are matched through
//! the leading-`v` normalization (locks carry the pretty `v6.4.1`, PURLs the
//! bare `6.4.1`) but the lock's own `version` string is never rewritten.
//!
//! Serialization mirrors composer's own writer: 4-space indent
//! (`JSON_PRETTY_PRINT`) + trailing newline; serde_json does not escape `/`
//! (matching `JSON_UNESCAPED_SLASHES`).

use std::collections::HashMap;
use std::path::Path;

use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::manifest::schema::{PatchFileInfo, PatchRecord};
use crate::patch::apply::{
    apply_package_patch, is_safe_relative_subpath, normalize_file_path, ApplyResult, PatchSources,
    VerifyResult, VerifyStatus,
};
use crate::patch::copy_tree::{fresh_copy, remove_tree};
use crate::patch::file_hash::compute_file_git_sha256;
use crate::patch::path_safety::{is_safe_multi_segment, is_safe_single_segment};
use crate::utils::fs::atomic_write_bytes;
use crate::utils::purl::{build_composer_purl, parse_composer_purl};

use super::path::{parse_vendor_path, vendor_uuid_dir_rel};
use super::state::{
    write_marker, VendorArtifact, VendorEntry, VendorMarker, WiringAction, WiringRecord,
};
use super::{RevertOutcome, VendorOutcome, VendorWarning};

/// Project-relative lockfile this backend wires.
const COMPOSER_LOCK: &str = "composer.lock";

/// Wiring-record discriminator. The record's `key` is
/// `"<section>:<vendor>/<name>"` where `<section>` is `packages` or
/// `packages-dev` (the lock array holding the entry) and `<vendor>/<name>` is
/// the lowercase canonical package name — `:` cannot appear in a composer
/// package name, so the encoding is unambiguous.
const WIRING_KIND: &str = "composer_lock_package";

/// Marker schema version written into `socket-patch.vendor.json`.
const MARKER_SCHEMA_VERSION: u32 = 1;

/// Normalize a composer version for identity comparison: strip a single
/// leading `v`/`V` when it directly precedes a digit (`v6.4.1` → `6.4.1`).
/// Local twin of the private `crawlers::composer_crawler::normalize_version`
/// (not visible from here); keep the two in sync.
fn normalize_version(version: &str) -> &str {
    let mut chars = version.chars();
    if matches!(chars.next(), Some('v') | Some('V'))
        && chars.next().map(|c| c.is_ascii_digit()).unwrap_or(false)
    {
        return &version[1..];
    }
    version
}

/// Vendor a composer package: materialize a patched copy under
/// `.socket/vendor/composer/<uuid>/<vendor>/<name>@<version>` and rewire the
/// matching `composer.lock` entry at it (see the module doc for the surgery).
///
/// `installed_dir` is the crawler's package dir (`vendor/<v>/<n>` — the same
/// root `apply` patches, so the manifest file keys resolve relative to it).
/// The lock edit runs LAST: any copy/patch failure removes the copy and
/// leaves the lock untouched.
#[allow(clippy::too_many_arguments)]
pub async fn vendor_composer(
    purl: &str,
    installed_dir: &Path,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
) -> VendorOutcome {
    // ── coordinates ──────────────────────────────────────────────────────
    let Some(((vendor, name), version)) = parse_composer_purl(purl) else {
        return refused("unsafe_coordinates", format!("not a composer purl: {purl}"));
    };
    // Canonical (packagist) lowercase form keys the on-disk copy dir and the
    // dist URL; the lock's own pretty casing is preserved untouched.
    let vendor = vendor.to_lowercase();
    let name = name.to_lowercase();
    let pkg = format!("{vendor}/{name}");

    // SECURITY: `uuid`, `vendor/name` and `version` come from committed,
    // tamper-able manifest data and key the copy dir that vendor creates and
    // `--revert` deletes. A `..` segment, separator, or non-canonical uuid
    // would escape `.socket/vendor/composer/` — reject fail-closed before any
    // disk access.
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("composer", &record.uuid) else {
        return refused(
            "unsafe_coordinates",
            format!("non-canonical patch uuid {:?}", record.uuid),
        );
    };
    if !is_safe_multi_segment(&pkg) || !is_safe_single_segment(version) {
        return refused(
            "unsafe_coordinates",
            format!("unsafe composer coordinates `{pkg}` @ `{version}`"),
        );
    }

    let copy_rel = format!("{uuid_dir_rel}/{pkg}@{version}");
    let uuid_dir = project_root.join(&uuid_dir_rel);
    let copy_dir = project_root.join(&copy_rel);

    // A patch with no files is meaningless to vendor: no-op success, no edits.
    if record.files.is_empty() {
        return VendorOutcome::Done {
            result: synthesized_result(purl, &copy_dir, Vec::new(), true, None),
            entry: None,
            warnings: Vec::new(),
        };
    }

    // ── lock presence + entry ────────────────────────────────────────────
    let lock_path = project_root.join(COMPOSER_LOCK);
    let lock_text = match tokio::fs::read_to_string(&lock_path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return refused(
                "vendor_lockfile_missing",
                format!("no composer.lock at {}", lock_path.display()),
            );
        }
        Err(e) => {
            return refused(
                "vendor_lockfile_missing",
                format!("unreadable composer.lock: {e}"),
            );
        }
    };
    // An unparseable lock is as unusable as a missing one — same refusal code.
    let mut lock: Value = match serde_json::from_str(&lock_text) {
        Ok(v) => v,
        Err(e) => {
            return refused(
                "vendor_lockfile_missing",
                format!("unparseable composer.lock: {e}"),
            );
        }
    };
    let Some((section, idx)) = find_lock_entry(&lock, &pkg, version) else {
        return refused(
            "vendor_lock_entry_not_found",
            format!("{pkg}@{version} is in neither packages[] nor packages-dev[] of composer.lock"),
        );
    };

    // ── idempotent hot path ──────────────────────────────────────────────
    // Copy already carries every afterHash and the lock entry already points
    // at the uuid path → touch nothing, report AlreadyPatched. `entry` stays
    // `None`: the first run's ledger entry holds the only copy of the
    // verbatim pre-vendor original, and re-recording here would clobber it.
    if entry_is_wired(&lock[section][idx], &copy_rel)
        && copy_matches_after_hashes(&copy_dir, &record.files).await
    {
        let verified = record
            .files
            .keys()
            .map(|f| already_patched_verify(f))
            .collect();
        return VendorOutcome::Done {
            result: synthesized_result(purl, &copy_dir, verified, true, None),
            entry: None,
            warnings: Vec::new(),
        };
    }

    // ── dry run: verify-only against the installed dir, no writes ────────
    if dry_run {
        let mut result = apply_package_patch(
            purl,
            installed_dir,
            &record.files,
            sources,
            Some(&record.uuid),
            true,
            force,
        )
        .await;
        result.package_path = copy_dir.display().to_string();
        return VendorOutcome::Done {
            result,
            entry: None,
            warnings: Vec::new(),
        };
    }

    // ── copy + patch (wiring last) ───────────────────────────────────────
    if let Err(e) = fresh_copy(installed_dir, &copy_dir, None).await {
        return VendorOutcome::Done {
            result: synthesized_result(
                purl,
                &copy_dir,
                Vec::new(),
                false,
                Some(format!("failed to copy installed package: {e}")),
            ),
            entry: None,
            warnings: Vec::new(),
        };
    }
    let mut result = apply_package_patch(
        purl,
        &copy_dir,
        &record.files,
        sources,
        Some(&record.uuid),
        false,
        force,
    )
    .await;
    result.package_path = copy_dir.display().to_string();
    if !result.success {
        // Don't leave a half-built copy; the lock was never touched.
        let _ = remove_tree(&uuid_dir).await;
        return VendorOutcome::Done {
            result,
            entry: None,
            warnings: Vec::new(),
        };
    }

    // ── lock rewrite ─────────────────────────────────────────────────────
    let original_entry = lock[section][idx].clone();
    let Some(original_obj) = original_entry.as_object() else {
        // find_lock_entry only matches objects; defensive.
        let _ = remove_tree(&uuid_dir).await;
        result.success = false;
        result.error = Some("composer.lock entry is not a JSON object".to_string());
        return VendorOutcome::Done {
            result,
            entry: None,
            warnings: Vec::new(),
        };
    };
    let rewritten = rewrite_lock_entry(original_obj, &copy_rel, &record.uuid);
    lock[section][idx] = Value::Object(rewritten.clone());
    let write_result = match composer_json_bytes(&lock) {
        Ok(bytes) => atomic_write_bytes(&lock_path, &bytes).await,
        Err(e) => Err(e),
    };
    if let Err(e) = write_result {
        let _ = remove_tree(&uuid_dir).await;
        result.success = false;
        result.error = Some(format!("failed to write composer.lock: {e}"));
        return VendorOutcome::Done {
            result,
            entry: None,
            warnings: Vec::new(),
        };
    }

    // ── marker + ledger entry ────────────────────────────────────────────
    let mut warnings = Vec::new();
    let base_purl = build_composer_purl(&vendor, &name, version);
    let mut vulnerabilities: Vec<String> = record.vulnerabilities.keys().cloned().collect();
    vulnerabilities.sort();
    let marker = VendorMarker {
        schema_version: MARKER_SCHEMA_VERSION,
        purl: base_purl.clone(),
        patch_uuid: record.uuid.clone(),
        ecosystem: "composer".to_string(),
        vulnerabilities,
        vendored_at: vendored_at.to_string(),
    };
    if let Err(e) = write_marker(&uuid_dir, &marker).await {
        // The marker is informational only (state.json is the ledger of
        // record), so its failure must not fail an otherwise-wired vendor.
        warnings.push(VendorWarning::new(
            "vendor_marker_write_failed",
            format!("could not write {}: {e}", super::state::VENDOR_MARKER_FILE),
        ));
    }

    let entry = VendorEntry {
        ecosystem: "composer".to_string(),
        base_purl,
        uuid: record.uuid.clone(),
        artifact: VendorArtifact {
            path: copy_rel,
            sha256: String::new(), // dir-shaped: integrity is per-file afterHashes
            size: None,
            platform_locked: None,
        },
        wiring: vec![WiringRecord {
            file: COMPOSER_LOCK.to_string(),
            kind: WIRING_KIND.to_string(),
            action: WiringAction::Rewritten,
            key: Some(format!("{section}:{pkg}")),
            original: Some(original_entry),
            new: Some(Value::Object(rewritten)),
        }],
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

    VendorOutcome::Done {
        result,
        entry: Some(entry),
        warnings,
    }
}

/// Revert a composer vendor entry: restore the verbatim original lock entry
/// (when the live entry still points into our uuid dir) and remove the
/// validated uuid dir. A drifted live entry — rewritten by a `composer
/// update`, a hand edit, or a newer vendor run — is left alone with a
/// `vendor_lock_entry_drifted` warning.
///
/// Note: the *installed* `vendor/<v>/<n>` keeps the patched bytes until the
/// next `composer install` re-mirrors from the registry; revert surfaces that
/// as the `vendor_installed_copy_stale` advisory.
pub async fn revert_composer(
    entry: &VendorEntry,
    project_root: &Path,
    dry_run: bool,
) -> RevertOutcome {
    // SECURITY: state.json is committed and tamper-able; the uuid keys the
    // directory we are about to delete. Anything but the canonical uuid
    // grammar is rejected fail-closed before any disk access.
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("composer", &entry.uuid) else {
        return RevertOutcome::failed(format!(
            "refusing revert: non-canonical patch uuid {:?}",
            entry.uuid
        ));
    };
    let uuid_dir = project_root.join(&uuid_dir_rel);
    let lock_path = project_root.join(COMPOSER_LOCK);
    let mut warnings = Vec::new();

    // Wiring is restored in reverse application order (one record today).
    for w in entry.wiring.iter().rev() {
        if w.kind != WIRING_KIND {
            warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!("unrecognized wiring kind {:?}; fragment left alone", w.kind),
            ));
            continue;
        }
        match restore_lock_entry(&lock_path, w, &entry.uuid, dry_run).await {
            Ok(true) => {}
            Ok(false) => warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "composer.lock entry for {} no longer points into .socket/vendor/composer/; left alone",
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

    warnings.push(VendorWarning::new(
        "vendor_installed_copy_stale",
        format!(
            "the installed vendor/{} copy keeps the patched bytes until the next `composer install`",
            entry
                .wiring
                .first()
                .and_then(|w| w.key.as_deref())
                .and_then(|k| k.split_once(':').map(|(_, p)| p))
                .unwrap_or("<package>")
        ),
    ));

    RevertOutcome {
        success: true,
        warnings,
        error: None,
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn refused(code: &'static str, detail: impl Into<String>) -> VendorOutcome {
    VendorOutcome::Refused {
        code,
        detail: detail.into(),
    }
}

/// Locate the package's entry: `packages[]` first, then `packages-dev[]`.
/// Names are compared case-insensitively, versions through the `v`-prefix
/// normalization (see module doc).
fn find_lock_entry(lock: &Value, pkg_lc: &str, version: &str) -> Option<(&'static str, usize)> {
    for section in ["packages", "packages-dev"] {
        let Some(arr) = lock.get(section).and_then(Value::as_array) else {
            continue;
        };
        for (i, e) in arr.iter().enumerate() {
            let Some(name) = e.get("name").and_then(Value::as_str) else {
                continue;
            };
            if !name.eq_ignore_ascii_case(pkg_lc) {
                continue;
            }
            let Some(v) = e.get("version").and_then(Value::as_str) else {
                continue;
            };
            if normalize_version(v) == normalize_version(version) {
                return Some((section, i));
            }
        }
    }
    None
}

/// True when the live entry already carries our path dist.
fn entry_is_wired(entry: &Value, dist_url: &str) -> bool {
    let dist = entry.get("dist");
    dist.and_then(|d| d.get("type")).and_then(Value::as_str) == Some("path")
        && dist.and_then(|d| d.get("url")).and_then(Value::as_str) == Some(dist_url)
}

/// Rebuild the lock entry for the path dist (see module doc): every original
/// key is preserved in order, `source` is dropped, `dist` is replaced in its
/// original slot with `transport-options` inserted right after it. A
/// pre-existing `transport-options` is superseded by ours (never duplicated).
/// A source-only entry without `dist` gets both appended at the end.
fn rewrite_lock_entry(
    original: &Map<String, Value>,
    dist_url: &str,
    patch_uuid: &str,
) -> Map<String, Value> {
    // `reference` carries the patch uuid: composer preserves it verbatim into
    // vendor/composer/installed.json (spike-proven for arbitrary strings), so
    // SBOM/audit tooling can recover the patch from deployed artifacts even
    // when `.socket/` is stripped from the image. The uuid was already
    // canonical-validated by vendor_uuid_dir_rel before reaching here.
    let dist = json!({ "type": "path", "url": dist_url, "reference": patch_uuid });
    let transport = json!({ "symlink": false });
    let mut out = Map::new();
    let mut replaced_dist = false;
    for (k, v) in original {
        match k.as_str() {
            "source" => {}
            "transport-options" => {}
            "dist" => {
                out.insert("dist".to_string(), dist.clone());
                out.insert("transport-options".to_string(), transport.clone());
                replaced_dist = true;
            }
            _ => {
                out.insert(k.clone(), v.clone());
            }
        }
    }
    if !replaced_dist {
        out.insert("dist".to_string(), dist);
        out.insert("transport-options".to_string(), transport);
    }
    out
}

/// Serialize the lock the way composer writes it: 4-space indent
/// (`JSON_PRETTY_PRINT`) + trailing newline. serde_json never escapes `/`,
/// matching `JSON_UNESCAPED_SLASHES`.
fn composer_json_bytes(value: &Value) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let fmt = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, fmt);
    value.serialize(&mut ser).map_err(std::io::Error::other)?;
    buf.push(b'\n');
    Ok(buf)
}

/// True when the copy exists and every patched file in it already hashes to
/// its `afterHash` (the vendor twin of `go_redirect::redirect_in_sync`).
async fn copy_matches_after_hashes(
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

/// Restore one `composer_lock_package` wiring record. `Ok(true)` = restored
/// (or would be, on dry run); `Ok(false)` = drifted, left alone; `Err` = a
/// real I/O / serialization failure.
async fn restore_lock_entry(
    lock_path: &Path,
    w: &WiringRecord,
    uuid: &str,
    dry_run: bool,
) -> Result<bool, String> {
    let Some(key) = w.key.as_deref() else {
        return Ok(false);
    };
    let Some((section, pkg)) = key.split_once(':') else {
        return Ok(false);
    };
    if section != "packages" && section != "packages-dev" {
        return Ok(false);
    }
    let Some(original) = w.original.clone() else {
        return Ok(false);
    };

    let lock_text = match tokio::fs::read_to_string(lock_path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("unreadable composer.lock: {e}")),
    };
    let mut lock: Value =
        serde_json::from_str(&lock_text).map_err(|e| format!("unparseable composer.lock: {e}"))?;

    let Some(arr) = lock.get(section).and_then(Value::as_array) else {
        return Ok(false);
    };
    let Some(idx) = arr.iter().position(|e| {
        e.get("name")
            .and_then(Value::as_str)
            .is_some_and(|n| n.eq_ignore_ascii_case(pkg))
    }) else {
        return Ok(false);
    };

    // Ownership gate: only restore when the live dist still points into OUR
    // uuid dir. A registry dist (composer update reverted it) or a different
    // uuid (a newer vendor run owns the entry) is third-party state — never
    // clobber it.
    let live = &lock[section][idx];
    let wired_to_us = live
        .get("dist")
        .and_then(|d| d.get("url"))
        .and_then(Value::as_str)
        .and_then(parse_vendor_path)
        .is_some_and(|p| p.eco == "composer" && p.uuid == uuid);
    if !wired_to_us {
        return Ok(false);
    }

    if !dry_run {
        lock[section][idx] = original;
        let bytes = composer_json_bytes(&lock).map_err(|e| e.to_string())?;
        atomic_write_bytes(lock_path, &bytes)
            .await
            .map_err(|e| format!("failed to write composer.lock: {e}"))?;
    }
    Ok(true)
}

fn synthesized_result(
    package_key: &str,
    copy_dir: &Path,
    files_verified: Vec<VerifyResult>,
    success: bool,
    error: Option<String>,
) -> ApplyResult {
    ApplyResult {
        package_key: package_key.to_string(),
        package_path: copy_dir.display().to_string(),
        success,
        files_verified,
        files_patched: Vec::new(),
        applied_via: HashMap::new(),
        error,
        sidecar: None,
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::patch::vendor::state::VENDOR_MARKER_FILE;
    use std::path::PathBuf;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const PURL: &str = "pkg:composer/psr/log@3.0.2";
    const PRISTINE: &[u8] = b"<?php\ninterface LoggerInterface {}\n";
    const PATCHED: &[u8] = b"<?php\n// SOCKET-PATCH-MARKER\ninterface LoggerInterface {}\n";

    fn copy_rel() -> String {
        format!(".socket/vendor/composer/{UUID}/psr/log@3.0.2")
    }

    fn psr_log_entry(name: &str, version: &str) -> Value {
        json!({
            "name": name,
            "version": version,
            "source": {
                "type": "git",
                "url": "https://github.com/php-fig/log.git",
                "reference": "f16e1d5863e37f8d8c2a01719f5b34baa2b714d3"
            },
            "dist": {
                "type": "zip",
                "url": "https://api.github.com/repos/php-fig/log/zipball/f16e1d5",
                "reference": "f16e1d5863e37f8d8c2a01719f5b34baa2b714d3",
                "shasum": ""
            },
            "require": { "php": ">=8.0.0" },
            "type": "library"
        })
    }

    fn lock_value(name: &str, version: &str, in_dev: bool) -> Value {
        let dev_entry = json!({
            "name": "phpunit/phpunit",
            "version": "10.0.0",
            "source": {"type": "git", "url": "https://github.com/s/phpunit.git", "reference": "aaa"},
            "dist": {"type": "zip", "url": "https://api.github.com/repos/s/phpunit/zipball/aaa", "reference": "aaa", "shasum": ""},
            "type": "library"
        });
        let (packages, packages_dev) = if in_dev {
            (json!([dev_entry]), json!([psr_log_entry(name, version)]))
        } else {
            (json!([psr_log_entry(name, version)]), json!([dev_entry]))
        };
        json!({
            "_readme": ["This file locks the dependencies of your project to a known state"],
            "content-hash": "7a59d114f58e9b02546b21d7e57430d3",
            "packages": packages,
            "packages-dev": packages_dev,
            "minimum-stability": "stable",
            "plugin-api-version": "2.6.0"
        })
    }

    /// Fixture project: composer.lock (composer-shaped, written with the same
    /// 4-space emitter composer uses), an installed `vendor/psr/log`, and a
    /// blobs dir carrying the patched bytes.
    async fn fixture(lock: &Value) -> (tempfile::TempDir, PathBuf, PathBuf, PatchRecord) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        tokio::fs::write(root.join(COMPOSER_LOCK), composer_json_bytes(lock).unwrap())
            .await
            .unwrap();

        let installed = root.join("vendor/psr/log");
        tokio::fs::create_dir_all(installed.join("src"))
            .await
            .unwrap();
        tokio::fs::write(
            installed.join("composer.json"),
            b"{\"name\": \"psr/log\"}\n",
        )
        .await
        .unwrap();
        tokio::fs::write(installed.join("src/LoggerInterface.php"), PRISTINE)
            .await
            .unwrap();

        let before = compute_git_sha256_from_bytes(PRISTINE);
        let after = compute_git_sha256_from_bytes(PATCHED);
        let blobs = root.join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        tokio::fs::write(blobs.join(&after), PATCHED).await.unwrap();

        let mut files = HashMap::new();
        files.insert(
            "src/LoggerInterface.php".to_string(),
            PatchFileInfo {
                before_hash: before,
                after_hash: after,
            },
        );
        let mut vulnerabilities = HashMap::new();
        vulnerabilities.insert(
            "GHSA-xxxx-yyyy-zzzz".to_string(),
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
        purl: &str,
        dry_run: bool,
    ) -> VendorOutcome {
        let sources = PatchSources::blobs_only(blobs);
        vendor_composer(
            purl,
            installed,
            root,
            record,
            &sources,
            "2026-06-09T00:00:00Z",
            dry_run,
            false,
        )
        .await
    }

    #[tokio::test]
    async fn test_happy_path_rewrites_lock() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);

        // Copy patched at the uuid path; installed dir untouched.
        let copy = root.join(copy_rel());
        assert_eq!(
            tokio::fs::read(copy.join("src/LoggerInterface.php"))
                .await
                .unwrap(),
            PATCHED
        );
        assert_eq!(
            tokio::fs::read(installed.join("src/LoggerInterface.php"))
                .await
                .unwrap(),
            PRISTINE
        );

        // Marker present in the uuid dir.
        let marker = tokio::fs::read_to_string(root.join(format!(
            ".socket/vendor/composer/{UUID}/{VENDOR_MARKER_FILE}"
        )))
        .await
        .unwrap();
        assert!(marker.contains(UUID));
        assert!(marker.contains("GHSA-xxxx-yyyy-zzzz"));

        // Lock surgery: source gone, dist replaced in slot, transport-options
        // right after, all other keys in their original order.
        let text = tokio::fs::read_to_string(root.join(COMPOSER_LOCK))
            .await
            .unwrap();
        let new_lock: Value = serde_json::from_str(&text).unwrap();
        let e = &new_lock["packages"][0];
        let keys: Vec<&str> = e.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            vec![
                "name",
                "version",
                "dist",
                "transport-options",
                "require",
                "type"
            ],
            "dist replaced in its original slot, source dropped, transport-options after dist"
        );
        assert_eq!(e["dist"]["type"], "path");
        assert_eq!(e["dist"]["url"], copy_rel());
        assert_eq!(
            e["dist"]["reference"], UUID,
            "reference carries the patch uuid for in-tree traceability"
        );
        assert_eq!(e["transport-options"]["symlink"], json!(false));
        // content-hash untouched (it covers composer.json only).
        assert_eq!(new_lock["content-hash"], "7a59d114f58e9b02546b21d7e57430d3");
        // 4-space indent + trailing newline + unescaped slashes.
        assert!(text.starts_with("{\n    \""), "4-space indent: {text}");
        assert!(text.ends_with('\n'));
        assert!(
            text.contains(&format!("\"url\": \"{}\"", copy_rel())),
            "slashes must not be escaped"
        );

        // Ledger entry: verbatim original, our rewrite, the artifact path.
        let entry = entry.expect("success must carry a ledger entry");
        assert_eq!(entry.ecosystem, "composer");
        assert_eq!(entry.base_purl, PURL);
        assert_eq!(entry.uuid, UUID);
        assert_eq!(entry.artifact.path, copy_rel());
        assert_eq!(entry.artifact.sha256, "");
        assert_eq!(entry.wiring.len(), 1);
        let w = &entry.wiring[0];
        assert_eq!(w.file, COMPOSER_LOCK);
        assert_eq!(w.kind, WIRING_KIND);
        assert_eq!(w.action, WiringAction::Rewritten);
        assert_eq!(w.key.as_deref(), Some("packages:psr/log"));
        assert_eq!(w.original.as_ref().unwrap(), &lock["packages"][0]);
        assert_eq!(w.new.as_ref().unwrap(), e);
    }

    #[tokio::test]
    async fn test_matches_packages_dev_entry() {
        let lock = lock_value("psr/log", "3.0.2", true);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();
        assert_eq!(entry.wiring[0].key.as_deref(), Some("packages-dev:psr/log"));

        let new_lock: Value = serde_json::from_str(
            &tokio::fs::read_to_string(root.join(COMPOSER_LOCK))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(new_lock["packages-dev"][0]["dist"]["type"], "path");
        // The packages[] sibling (phpunit) is untouched.
        assert_eq!(new_lock["packages"][0]["dist"]["type"], "zip");
    }

    #[tokio::test]
    async fn test_matches_v_prefixed_lock_version() {
        // Lock carries the pretty `v3.0.2`; the PURL is bare `3.0.2`. The
        // entry must match, and its own version string must NOT be rewritten.
        let lock = lock_value("psr/log", "v3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (result, _e, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(result.success, "{:?}", result.error);
        let new_lock: Value = serde_json::from_str(
            &tokio::fs::read_to_string(root.join(COMPOSER_LOCK))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(new_lock["packages"][0]["version"], "v3.0.2");
        assert_eq!(new_lock["packages"][0]["dist"]["type"], "path");
    }

    #[tokio::test]
    async fn test_case_insensitive_name_lowercase_dist_url() {
        // Hand-written mixed-case lock name: matched case-insensitively, the
        // lock's pretty casing preserved, the dist URL lowercase canonical.
        let lock = lock_value("Psr/Log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (result, _e, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(result.success, "{:?}", result.error);
        let new_lock: Value = serde_json::from_str(
            &tokio::fs::read_to_string(root.join(COMPOSER_LOCK))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            new_lock["packages"][0]["name"], "Psr/Log",
            "pretty casing kept"
        );
        assert_eq!(
            new_lock["packages"][0]["dist"]["url"],
            copy_rel(),
            "dist url lowercase"
        );
        assert!(
            dir.path().join(copy_rel()).exists(),
            "copy at the lowercase path"
        );
    }

    #[tokio::test]
    async fn test_refuses_missing_lock() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        tokio::fs::remove_file(root.join(COMPOSER_LOCK))
            .await
            .unwrap();

        let (code, _d) =
            unwrap_refused(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert_eq!(code, "vendor_lockfile_missing");
        assert!(!root.join(".socket").exists(), "refusal must write nothing");
    }

    #[tokio::test]
    async fn test_refuses_entry_not_found() {
        let lock = lock_value("monolog/monolog", "2.9.1", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let before = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        let (code, _d) =
            unwrap_refused(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert_eq!(code, "vendor_lock_entry_not_found");
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            before,
            "lock untouched"
        );
        assert!(!root.join(".socket").exists());
    }

    /// SECURITY: traversal coordinates (a tampered manifest) must be refused
    /// before any disk access — no copy outside `.socket/vendor/composer/`,
    /// no lock edit.
    #[tokio::test]
    async fn test_refuses_unsafe_coordinates() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let before = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        // (a) non-canonical uuid
        let mut bad_uuid = record.clone();
        bad_uuid.uuid = "../../escape".to_string();
        let (code, _d) =
            unwrap_refused(run_vendor(root, &blobs, &installed, &bad_uuid, PURL, false).await);
        assert_eq!(code, "unsafe_coordinates");

        // (b) traversal in the package name
        let (code, _d) = unwrap_refused(
            run_vendor(
                root,
                &blobs,
                &installed,
                &record,
                "pkg:composer/../evil@1.0.0",
                false,
            )
            .await,
        );
        assert_eq!(code, "unsafe_coordinates");

        assert!(!root.join(".socket").exists(), "nothing written");
        assert!(!root.parent().unwrap().join("escape").exists());
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            before
        );
    }

    #[tokio::test]
    async fn test_idempotent_rerun_in_sync() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (r1, e1, _) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(r1.success);
        assert!(e1.is_some());
        let lock_bytes = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();
        let copy_bytes = tokio::fs::read(root.join(copy_rel()).join("src/LoggerInterface.php"))
            .await
            .unwrap();

        let (r2, e2, _) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(r2.success);
        assert!(r2.files_patched.is_empty(), "in-sync rerun patches nothing");
        assert!(
            r2.files_verified
                .iter()
                .all(|v| v.status == VerifyStatus::AlreadyPatched),
            "synthesized AlreadyPatched: {:?}",
            r2.files_verified
        );
        assert!(
            e2.is_none(),
            "hot path must not re-record (would clobber the original in the ledger)"
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            lock_bytes
        );
        assert_eq!(
            tokio::fs::read(root.join(copy_rel()).join("src/LoggerInterface.php"))
                .await
                .unwrap(),
            copy_bytes
        );
    }

    #[tokio::test]
    async fn test_dry_run_writes_nothing() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let before = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, true).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_none(), "dry run records nothing");
        assert!(!root.join(".socket").exists(), "no copy created");
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            before
        );
    }

    #[tokio::test]
    async fn test_partial_failure_removes_copy_lock_untouched() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, _blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let before = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();
        // Empty blobs dir → the patch bytes cannot be sourced → apply fails.
        let empty = root.join("empty-blobs");
        tokio::fs::create_dir_all(&empty).await.unwrap();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &empty, &installed, &record, PURL, false).await);
        assert!(!result.success);
        assert!(entry.is_none());
        assert!(
            !root
                .join(format!(".socket/vendor/composer/{UUID}"))
                .exists(),
            "half-built copy must be removed"
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            before,
            "lock untouched on failure (wiring runs last)"
        );
    }

    #[tokio::test]
    async fn test_revert_round_trip_byte_identical() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let fixture_bytes = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(result.success);
        let entry = entry.unwrap();
        assert_ne!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            fixture_bytes,
            "vendor must have rewired the lock"
        );

        let outcome = revert_composer(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "clean revert must not report drift: {:?}",
            outcome.warnings
        );
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_installed_copy_stale"),
            "revert advises about the stale installed copy"
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            fixture_bytes,
            "lock restored byte-identically"
        );
        assert!(
            !root
                .join(format!(".socket/vendor/composer/{UUID}"))
                .exists(),
            "uuid dir removed"
        );
    }

    #[tokio::test]
    async fn test_revert_drift_warning() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(result.success);
        let entry = entry.unwrap();

        // Third-party drift: `composer update` rewired the entry back to a
        // registry zip dist. Revert must leave it alone and warn.
        let drifted = lock_value("psr/log", "3.0.2", false);
        tokio::fs::write(
            root.join(COMPOSER_LOCK),
            composer_json_bytes(&drifted).unwrap(),
        )
        .await
        .unwrap();
        let drifted_bytes = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        let outcome = revert_composer(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "drift must be reported: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            drifted_bytes,
            "drifted lock left alone"
        );
        assert!(
            !root
                .join(format!(".socket/vendor/composer/{UUID}"))
                .exists(),
            "uuid dir still removed"
        );
    }
}
