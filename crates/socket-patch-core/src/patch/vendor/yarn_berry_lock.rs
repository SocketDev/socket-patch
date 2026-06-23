//! yarn berry (4.x) vendor backend: paired `package.json` resolutions +
//! `yarn.lock` entry surgery.
//!
//! Berry verifies every install against the sha512 of the *converted cache
//! zip* (`checksum: 10c0/<hex>`), so a lock-only rewrite à la classic is not
//! enough — but spike B2/B3 (`spikes/PHASE0-V2-FINDINGS.txt` +
//! `spikes/yarn-berry-nm/`) proved the full recipe is reproducible offline:
//!
//! 1. `package.json` gains `"resolutions": {"<name>": "file:./<rel-tgz>"}`
//!    (the dependency ranges stay untouched);
//! 2. `yarn.lock` replaces the `"<name>@npm:<range>"` entry with the exact
//!    entry yarn emits for that resolution — key and resolution locator
//!    embed the ROOT WORKSPACE NAME (from the lock's `@workspace:.` entry)
//!    and the relative tgz path, `hash=` is the first 6 hex chars of
//!    sha512(tgz bytes), and `checksum:` is `10c0/` + sha512 of the
//!    deterministic cache zip rebuilt by [`super::berry_zip`].
//!
//! A fresh checkout of exactly {package.json, yarn.lock, .yarnrc.yml,
//! .socket/} then passes `yarn install --immutable --check-cache` fully
//! offline (spike B5).
//!
//! Fail-closed gates, all BEFORE any write: the checksum recipe only holds
//! for cacheKey `10c0` (compressionLevel 0, the yarn 4 default — B4 showed
//! `compressionLevel: mixed` changes both the cacheKey and the checksum), and
//! a user-authored resolutions entry for the same package is never
//! overwritten. The pair is committed package.json-first, lock-second, and
//! the package.json edit is unwound when the lock write fails — a resolutions
//! entry without its lock counterpart would make a plain `yarn install`
//! re-resolve and rewrite the lock underneath the user.

use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha512};

use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{normalize_file_path, PatchSources};
use crate::patch::copy_tree::remove_tree;
use crate::utils::fs::atomic_write_bytes;

use super::berry_zip::berry_cache_checksum_10c0;
use super::npm_common::{done_failure, guard_coordinates, refused, stage_patch_pack, tgz_rel_leaf};
use super::path::{parse_vendor_path, vendor_uuid_dir_rel};
use super::state::{
    write_marker, VendorArtifact, VendorEntry, VendorMarker, WiringAction, WiringRecord,
};
use super::yarn_classic_lock::{
    already_patched_verify, body_field_line, detect_eol, json_to_lines, lines_to_json,
    replace_block, scan_blocks, split_key_patterns, split_pattern, synthesized_result, LockBlock,
};
use super::{RevertOutcome, VendorOutcome, VendorWarning};

const YARN_LOCK: &str = "yarn.lock";
const PACKAGE_JSON: &str = "package.json";
const YARNRC: &str = ".yarnrc.yml";

/// Wiring kinds this backend owns.
const KIND_RESOLUTION: &str = "yarn_berry_resolution";
const KIND_LOCK_ENTRY: &str = "yarn_berry_lock_entry";

/// The only cache key the offline checksum recipe reproduces (yarn 4's
/// internal CACHE_VERSION `10` + compressionLevel 0 → `c0`).
const SUPPORTED_CACHE_KEY: &str = "10c0";

/// Vendor one installed npm package into a yarn-berry (4.x, cacheKey 10c0)
/// project. Same contract as [`super::npm_lock::vendor_npm`]: refuse-early,
/// wire-last; `entry` is `None` for dry runs and the in-sync re-run.
#[allow(clippy::too_many_arguments)]
pub async fn vendor_yarn_berry(
    purl: &str,
    installed_dir: &Path,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
    service: Option<&super::VendorServiceConfig>,
) -> VendorOutcome {
    let mut warnings: Vec<VendorWarning> = Vec::new();

    // ── 1. Coordinates (shared fail-closed guard, before any disk access) ─
    let coords = match guard_coordinates(purl, record) {
        Ok(coords) => coords,
        Err(outcome) => return *outcome,
    };
    let (name, version) = (coords.name.as_str(), coords.version.as_str());
    let uuid_dir_rel = coords.uuid_dir_rel.clone();
    let base_purl = coords.base_purl.clone();
    let rel_tgz = format!("{}/{}", coords.uuid_dir_rel, tgz_rel_leaf(name, version));
    // The resolutions spec — `file:./` spelling per the B3 fixture.
    let spec = format!("file:./{rel_tgz}");

    // ── 2. Lockfile + cacheKey gate ───────────────────────────────────────
    let lock_path = project_root.join(YARN_LOCK);
    let lock_text = match tokio::fs::read_to_string(&lock_path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return refused(
                "vendor_lockfile_missing",
                format!(
                    "no {YARN_LOCK} at {} — vendoring rewires the lockfile, so one must \
                     exist (run `yarn install` first)",
                    project_root.display()
                ),
            );
        }
        Err(e) => {
            return refused(
                "vendor_lockfile_missing",
                format!("cannot read {YARN_LOCK}: {e}"),
            );
        }
    };
    let blocks = scan_blocks(&lock_text);
    let Some(meta) = blocks.iter().find(|b| b.key == "__metadata") else {
        return refused(
            "vendor_lockfile_version_unsupported",
            "yarn.lock has no `__metadata:` entry — not a yarn berry lockfile".to_string(),
        );
    };
    let cache_key = berry_field(&meta.lines, "cacheKey").unwrap_or("");
    if cache_key != SUPPORTED_CACHE_KEY {
        // The checksum is sha512 of the cache archive, whose bytes depend on
        // the cache format version + compression; only 10c0 (stored entries)
        // is reproducible offline. Emitting a guess would brick installs
        // with YN0018, so refuse.
        return refused(
            "vendor_yarn_berry_cache_unsupported",
            format!(
                "yarn.lock cacheKey is `{cache_key}`; only `{SUPPORTED_CACHE_KEY}` (yarn 4 \
                 with compressionLevel 0, the default) has an offline-reproducible cache \
                 checksum — remove custom compression settings and re-run `yarn install`"
            ),
        );
    }

    // ── 3. .yarnrc.yml knobs that change the checksum (spike B4) ─────────
    match tokio::fs::read_to_string(project_root.join(YARNRC)).await {
        Ok(rc) => {
            if let Some(level) = yarnrc_compression_level(&rc) {
                if level != "0" {
                    return refused(
                        "vendor_yarn_berry_cache_unsupported",
                        format!(
                            "{YARNRC} sets `compressionLevel: {level}`, which changes berry's \
                             cache checksums; only compressionLevel 0 (the yarn 4 default) is \
                             supported"
                        ),
                    );
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return refused(
                "vendor_yarn_berry_cache_unsupported",
                format!("cannot read {YARNRC} to verify the cache configuration: {e}"),
            );
        }
    }

    // ── 4. Root workspace name (the lock key/resolution embed it) ────────
    let Some(workspace) = root_workspace_name(&blocks) else {
        return refused(
            "vendor_lockfile_version_unsupported",
            "yarn.lock has no root `<name>@workspace:.` entry; cannot build the \
             workspace-bound file: locator"
                .to_string(),
        );
    };

    // ── 5. package.json + user-override conflict gate ─────────────────────
    let pkg_path = project_root.join(PACKAGE_JSON);
    let pkg_bytes = match tokio::fs::read(&pkg_path).await {
        Ok(b) => b,
        Err(e) => {
            return refused(
                "vendor_yarn_berry_manifest_unreadable",
                format!("cannot read the project {PACKAGE_JSON}: {e}"),
            );
        }
    };
    let pkg: Value = match serde_json::from_slice(&pkg_bytes) {
        Ok(v) => v,
        Err(e) => {
            return refused(
                "vendor_yarn_berry_manifest_unreadable",
                format!("{PACKAGE_JSON} is not parseable JSON: {e}"),
            );
        }
    };
    let Some(pkg_obj) = pkg.as_object() else {
        return refused(
            "vendor_yarn_berry_manifest_unreadable",
            format!("{PACKAGE_JSON} root is not an object"),
        );
    };
    // A user-authored BARE-name pin to the exact version being vendored is
    // TAKEN OVER (its value is rewritten to our spec — the pin already
    // forced this exact version, so semantics are preserved — and recorded
    // as the wiring `original` so revert restores it). Anything else
    // same-name still refuses.
    let mut takeover_original: Option<String> = None;
    if let Some(res) = pkg_obj.get("resolutions") {
        let Some(res_obj) = res.as_object() else {
            return refused(
                "vendor_override_conflict",
                format!("{PACKAGE_JSON} `resolutions` is not an object"),
            );
        };
        for (selector, value) in res_obj {
            let sel_name = split_pattern(selector)
                .map(|(n, _)| n)
                .unwrap_or(selector.as_str());
            if sel_name != name {
                continue;
            }
            // Our own (possibly stale-uuid) entry is fine to overwrite; a
            // user-authored override is never clobbered silently.
            let ours = value
                .as_str()
                .is_some_and(|v| parse_vendor_path(v).is_some_and(|p| p.eco == "npm"));
            if ours {
                continue;
            }
            if selector == name && value.as_str() == Some(version) {
                takeover_original = Some(version.to_string());
                continue;
            }
            return refused(
                "vendor_override_conflict",
                format!(
                    "{PACKAGE_JSON} already has a resolutions entry for `{selector}` \
                     ({value}); vendor will not overwrite a user-authored override (an \
                     exact-version pin `\"{name}\": \"{version}\"` is taken over \
                     automatically)"
                ),
            );
        }
    }

    // ── 6. The single replaceable lock entry ──────────────────────────────
    let target = match scan_berry_target(&blocks, name, version) {
        Ok(Some(t)) => t,
        Ok(None) => {
            return refused(
                "vendor_lock_entry_not_found",
                format!(
                    "{YARN_LOCK} has no `{name}@npm:` entry resolving {version} — make sure \
                     the package is installed and locked (`yarn install`) before vendoring"
                ),
            );
        }
        Err((code, detail)) => return refused(code, detail),
    };
    let patches_manifest = record
        .files
        .keys()
        .any(|k| normalize_file_path(k) == "package.json");

    // ── 7. Stage → patch → pack (shared flavor-agnostic pipeline) ─────────
    let (staged, result) = match stage_patch_pack(
        purl,
        installed_dir,
        project_root,
        record,
        sources,
        dry_run,
        force,
        &mut warnings,
        service,
    )
    .await
    {
        Ok(pair) => pair,
        Err(outcome) => return *outcome,
    };
    let Some(staged) = staged else {
        // Failed patch (wiring is last — project byte-untouched) or dry run.
        return VendorOutcome::Done {
            result,
            entry: None,
            warnings,
        };
    };
    debug_assert_eq!(staged.rel_tgz, rel_tgz);
    let packed = staged.packed;
    let dest = project_root.join(&rel_tgz);

    // ── 8. Berry identity facts of the packed tarball ─────────────────────
    let tgz_bytes = match tokio::fs::read(&dest).await {
        Ok(b) => b,
        Err(e) => return done_failure(purl, format!("cannot re-read the packed tarball: {e}")),
    };
    let tgz_sha512 = hex::encode(Sha512::digest(&tgz_bytes));
    // `hash=` — the first 6 hex chars of sha512(tgz): the lock-committed
    // tamper guard on the tarball itself (spike B3, flips on any byte edit).
    let hash6 = &tgz_sha512[..6];
    let checksum = match berry_cache_checksum_10c0(&tgz_bytes, name) {
        Ok(c) => c,
        Err(e) => {
            return done_failure(
                purl,
                format!("cannot compute the berry cache checksum for {name}: {e}"),
            )
        }
    };

    // ── 9. The replacement lock entry (verbatim B3 shape) ─────────────────
    let locator = encode_uri_component(&format!("{workspace}@workspace:."));
    let lock_key = format!("\"{name}@file:./{rel_tgz}::locator={locator}\"");
    let resolution = format!("{name}@file:./{rel_tgz}#./{rel_tgz}::hash={hash6}&locator={locator}");
    // Sections beyond the five we own (dependencies:, peerDependencies:,
    // bin:, …) describe the same package version and carry over verbatim.
    let carried = carried_sections(&target.lines);
    if patches_manifest {
        warnings.push(VendorWarning::new(
            "vendor_dep_manifest_stale",
            format!(
                "the patch rewrites {name}@{version}'s package.json; the yarn.lock entry \
                 keeps the registry entry's dependency fields — if the patch changed \
                 dependencies, run `yarn install` once to refresh them"
            ),
        ));
    }
    let new_lines = build_entry_lines(&lock_key, version, &resolution, &checksum, &carried);

    // ── 10. In-sync hot path: nothing to write, nothing to record ─────────
    let pkg_in_sync = pkg_obj
        .get("resolutions")
        .and_then(|r| r.get(name))
        .and_then(Value::as_str)
        == Some(spec.as_str());
    if pkg_in_sync && target.is_ours && target.lines == new_lines {
        let verified = record
            .files
            .keys()
            .map(|f| already_patched_verify(f))
            .collect();
        return VendorOutcome::Done {
            result: synthesized_result(purl, &dest, verified, true, None),
            entry: None,
            warnings,
        };
    }

    // ── 11. Build both new byte images, then commit pkg-first/lock-second ─
    let existing_entry = pkg_obj
        .get("resolutions")
        .and_then(|r| r.get(name))
        .is_some();
    let mut new_pkg = pkg.clone();
    {
        let obj = new_pkg.as_object_mut().expect("validated above");
        let res = obj
            .entry("resolutions".to_string())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        let Some(res_obj) = res.as_object_mut() else {
            return done_failure(purl, "resolutions table vanished mid-edit".to_string());
        };
        res_obj.insert(name.to_string(), Value::String(spec.clone()));
    }
    let pkg_indent = detect_indent(&String::from_utf8_lossy(&pkg_bytes));
    let new_pkg_bytes = match serialize_json(&new_pkg, &pkg_indent) {
        Ok(b) => b,
        Err(e) => return done_failure(purl, format!("cannot serialize {PACKAGE_JSON}: {e}")),
    };
    let new_lock_text = {
        let blocks_now = scan_blocks(&lock_text);
        let Some(block) = blocks_now.iter().find(|b| b.key == target.key) else {
            return done_failure(
                purl,
                format!("lock entry `{}` vanished mid-rewrite", target.key),
            );
        };
        replace_block(&lock_text, block, &new_lines, detect_eol(&lock_text))
    };
    if let Err(e) = commit_pair(
        project_root,
        &new_pkg_bytes,
        &pkg_bytes,
        new_lock_text.as_bytes(),
    )
    .await
    {
        return done_failure(purl, e);
    }

    // ── 12. Marker + ledger entry ─────────────────────────────────────────
    let mut vulnerabilities: Vec<String> = record.vulnerabilities.keys().cloned().collect();
    vulnerabilities.sort();
    let marker = VendorMarker {
        schema_version: 1,
        purl: base_purl.clone(),
        patch_uuid: record.uuid.clone(),
        ecosystem: "npm".to_string(),
        vulnerabilities,
        vendored_at: vendored_at.to_string(),
    };
    if let Err(e) = write_marker(&project_root.join(&uuid_dir_rel), &marker).await {
        warnings.push(VendorWarning::new(
            "vendor_marker_write_failed",
            format!("could not write the informational vendor marker: {e}"),
        ));
    }

    let wiring = vec![
        WiringRecord {
            file: PACKAGE_JSON.to_string(),
            kind: KIND_RESOLUTION.to_string(),
            // Rewritten when replacing our own stale entry (no `original` —
            // never record our own edit as a pre-vendor fragment) or a
            // taken-over user pin (whose value IS the `original`, restored
            // verbatim on revert).
            action: if existing_entry {
                WiringAction::Rewritten
            } else {
                WiringAction::Added
            },
            key: Some(name.to_string()),
            original: takeover_original.map(Value::String),
            new: Some(Value::String(spec)),
        },
        WiringRecord {
            file: YARN_LOCK.to_string(),
            kind: KIND_LOCK_ENTRY.to_string(),
            action: WiringAction::Rewritten,
            key: Some(lock_key),
            original: if target.is_ours {
                None
            } else {
                Some(lines_to_json(&target.lines))
            },
            new: Some(lines_to_json(&new_lines)),
        },
    ];
    let entry = VendorEntry {
        ecosystem: "npm".to_string(),
        base_purl,
        uuid: record.uuid.clone(),
        artifact: VendorArtifact {
            path: rel_tgz,
            sha256: packed.sha256_hex,
            size: Some(packed.size),
            platform_locked: None,
        },
        wiring,
        lock: None,
        took_over_go_patches: false,
        detached: false,
        record: None,
        flavor: Some("yarn-berry".to_string()),
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

/// Undo one yarn-berry vendored package: restore the recorded lock entry,
/// remove the resolutions entry, and remove the artifact dir.
pub async fn revert_yarn_berry(
    entry: &VendorEntry,
    project_root: &Path,
    dry_run: bool,
) -> RevertOutcome {
    // SECURITY: validate the tamper-able uuid before any disk access — it
    // names the directory tree this revert DELETES.
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("npm", &entry.uuid) else {
        return RevertOutcome::failed(format!(
            "refusing revert: `{}` is not a canonical patch uuid (tampered state.json?)",
            entry.uuid
        ));
    };
    if dry_run {
        return RevertOutcome::ok();
    }

    let mut outcome = RevertOutcome::ok();

    // SECURITY: per-flavor FILE ALLOWLIST — this backend only ever writes
    // yarn.lock and package.json; a poisoned state.json naming any other
    // path is skipped fail-closed (warned, never read or written).
    let mut lock_recs: Vec<&WiringRecord> = Vec::new();
    let mut pkg_recs: Vec<&WiringRecord> = Vec::new();
    for rec in entry.wiring.iter().rev() {
        match rec.file.as_str() {
            YARN_LOCK => lock_recs.push(rec),
            PACKAGE_JSON => pkg_recs.push(rec),
            other => outcome.warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "ignoring wiring record for file `{other}` outside the yarn-berry \
                     allowlist [\"{YARN_LOCK}\", \"{PACKAGE_JSON}\"]"
                ),
            )),
        }
    }

    // yarn.lock fragments (reverse application order).
    if !lock_recs.is_empty() {
        let lock_path = project_root.join(YARN_LOCK);
        match tokio::fs::read_to_string(&lock_path).await {
            Ok(mut text) => {
                let mut changed = false;
                for rec in lock_recs {
                    revert_lock_record(
                        &mut text,
                        rec,
                        &entry.uuid,
                        &mut changed,
                        &mut outcome.warnings,
                    );
                }
                if changed {
                    if let Err(e) = atomic_write_bytes(&lock_path, text.as_bytes()).await {
                        return RevertOutcome::failed(format!("cannot write {YARN_LOCK}: {e}"));
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                outcome.warnings.push(VendorWarning::new(
                    "vendor_lockfile_missing",
                    format!("{YARN_LOCK} is missing; lock fragments cannot be restored"),
                ));
            }
            Err(e) => return RevertOutcome::failed(format!("cannot read {YARN_LOCK}: {e}")),
        }
    }

    // package.json resolutions entries.
    if !pkg_recs.is_empty() {
        let pkg_path = project_root.join(PACKAGE_JSON);
        match tokio::fs::read(&pkg_path).await {
            Ok(bytes) => {
                let mut pkg: Value = match serde_json::from_slice(&bytes) {
                    Ok(v) => v,
                    // Fail-closed: rewriting a manifest we cannot parse
                    // risks destroying it.
                    Err(e) => {
                        return RevertOutcome::failed(format!(
                            "{PACKAGE_JSON} is not parseable JSON ({e}); fix it and re-run revert"
                        ))
                    }
                };
                let mut changed = false;
                for rec in pkg_recs {
                    revert_resolution_record(
                        &mut pkg,
                        rec,
                        &entry.uuid,
                        &mut changed,
                        &mut outcome.warnings,
                    );
                }
                if changed {
                    let indent = detect_indent(&String::from_utf8_lossy(&bytes));
                    match serialize_json(&pkg, &indent) {
                        Ok(out) => {
                            if let Err(e) = atomic_write_bytes(&pkg_path, &out).await {
                                return RevertOutcome::failed(format!(
                                    "cannot write {PACKAGE_JSON}: {e}"
                                ));
                            }
                        }
                        Err(e) => {
                            return RevertOutcome::failed(format!(
                                "cannot serialize {PACKAGE_JSON}: {e}"
                            ))
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                outcome.warnings.push(VendorWarning::new(
                    "vendor_lockfile_missing",
                    format!("{PACKAGE_JSON} is missing; the resolutions entry cannot be removed"),
                ));
            }
            Err(e) => return RevertOutcome::failed(format!("cannot read {PACKAGE_JSON}: {e}")),
        }
    }

    if let Err(e) = remove_tree(&project_root.join(&uuid_dir_rel)).await {
        return RevertOutcome::failed(format!("cannot remove {uuid_dir_rel}: {e}"));
    }

    outcome
}

// ───────────────────────────── revert internals ─────────────────────────────

/// Restore one recorded lock entry iff the live entry is still ours
/// (resolution parses into `.socket/vendor/npm/<entry.uuid>/…`).
fn revert_lock_record(
    text: &mut String,
    rec: &WiringRecord,
    entry_uuid: &str,
    changed: &mut bool,
    warnings: &mut Vec<VendorWarning>,
) {
    let Some(key) = rec.key.as_deref() else {
        warnings.push(VendorWarning::new(
            "vendor_lock_entry_drifted",
            format!("wiring record in {} has no key; left alone", rec.file),
        ));
        return;
    };
    if rec.kind != KIND_LOCK_ENTRY {
        warnings.push(VendorWarning::new(
            "vendor_lock_entry_drifted",
            format!("unknown wiring kind `{}` for `{key}`; left alone", rec.kind),
        ));
        return;
    }
    let edit = {
        let blocks = scan_blocks(text);
        let Some(block) = blocks.iter().find(|b| b.key == key) else {
            warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!("lock entry `{key}` no longer exists; nothing to restore"),
            ));
            return;
        };
        let ours = berry_field(&block.lines, "resolution")
            .and_then(parse_vendor_path)
            .is_some_and(|p| p.eco == "npm" && p.uuid == entry_uuid);
        if !ours {
            warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!("lock entry `{key}` was re-resolved since vendoring; left alone"),
            ));
            return;
        }
        let Some(original) = rec.original.as_ref().and_then(json_to_lines) else {
            warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "lock entry `{key}` has no recorded pre-vendor original; left as-is \
                     (re-run `yarn install` to re-resolve it from the registry)"
                ),
            ));
            return;
        };
        replace_block(text, block, &original, detect_eol(text))
    };
    *text = edit;
    *changed = true;
}

/// Remove our resolutions entry iff the live value still points into our
/// uuid dir; drop the `resolutions` table when that leaves it empty (we only
/// ever ADD entries — an empty table would be vendor residue).
fn revert_resolution_record(
    pkg: &mut Value,
    rec: &WiringRecord,
    entry_uuid: &str,
    changed: &mut bool,
    warnings: &mut Vec<VendorWarning>,
) {
    let Some(key) = rec.key.as_deref() else {
        warnings.push(VendorWarning::new(
            "vendor_lock_entry_drifted",
            format!("wiring record in {} has no key; left alone", rec.file),
        ));
        return;
    };
    if rec.kind != KIND_RESOLUTION {
        warnings.push(VendorWarning::new(
            "vendor_lock_entry_drifted",
            format!("unknown wiring kind `{}` for `{key}`; left alone", rec.kind),
        ));
        return;
    }
    let Some(obj) = pkg.as_object_mut() else {
        warnings.push(VendorWarning::new(
            "vendor_lock_entry_drifted",
            format!("{PACKAGE_JSON} root is not an object; resolutions entry left alone"),
        ));
        return;
    };
    let Some(res_obj) = obj.get_mut("resolutions").and_then(Value::as_object_mut) else {
        warnings.push(VendorWarning::new(
            "vendor_lock_entry_drifted",
            format!("resolutions entry `{key}` no longer exists; nothing to remove"),
        ));
        return;
    };
    let ours = res_obj
        .get(key)
        .and_then(Value::as_str)
        .and_then(parse_vendor_path)
        .is_some_and(|p| p.eco == "npm" && p.uuid == entry_uuid);
    if !ours {
        warnings.push(VendorWarning::new(
            "vendor_lock_entry_drifted",
            format!("resolutions entry `{key}` was changed since vendoring; left alone"),
        ));
        return;
    }
    // A takeover recorded the user's pinned value: restore it in place
    // (the key and table stay). Otherwise remove our entry as before.
    if let Some(orig) = rec.original.as_ref().and_then(Value::as_str) {
        res_obj.insert(key.to_string(), Value::String(orig.to_string()));
        *changed = true;
        return;
    }
    res_obj.shift_remove(key);
    if res_obj.is_empty() {
        obj.shift_remove("resolutions");
    }
    *changed = true;
}

// ───────────────────────────── vendor internals ─────────────────────────────

/// Commit the pair in contract order — package.json first, yarn.lock second
/// — unwinding package.json to its original bytes when the lock write fails
/// (a resolutions entry without its lock counterpart would let a plain
/// `yarn install` silently re-resolve around the patch).
async fn commit_pair(
    project_root: &Path,
    new_pkg: &[u8],
    orig_pkg: &[u8],
    new_lock: &[u8],
) -> Result<(), String> {
    let pkg_path = project_root.join(PACKAGE_JSON);
    atomic_write_bytes(&pkg_path, new_pkg)
        .await
        .map_err(|e| format!("cannot write {PACKAGE_JSON}: {e}"))?;
    if let Err(e) = atomic_write_bytes(&project_root.join(YARN_LOCK), new_lock).await {
        return match atomic_write_bytes(&pkg_path, orig_pkg).await {
            Ok(()) => Err(format!(
                "cannot write {YARN_LOCK}: {e} ({PACKAGE_JSON} restored)"
            )),
            Err(e2) => Err(format!(
                "cannot write {YARN_LOCK}: {e} — and restoring {PACKAGE_JSON} failed too: \
                 {e2}; restore {PACKAGE_JSON} from version control"
            )),
        };
    }
    Ok(())
}

/// The single lock entry the rewrite replaces.
struct BerryTarget {
    /// Verbatim key (no trailing colon, quotes kept).
    key: String,
    lines: Vec<String>,
    /// Already one of our `file:` entries (stale uuid or current).
    is_ours: bool,
}

/// Find the one replaceable entry for `name@version`, refusing fail-closed on
/// anything a bare-name resolutions entry would also move (other versions of
/// the name, non-npm protocols, ambiguous duplicates).
fn scan_berry_target(
    blocks: &[LockBlock],
    name: &str,
    version: &str,
) -> Result<Option<BerryTarget>, (&'static str, String)> {
    let mut found: Vec<BerryTarget> = Vec::new();
    for block in blocks {
        if block.key == "__metadata" {
            continue;
        }
        let patterns = split_key_patterns(&block.key);
        let parsed: Vec<(&str, &str)> = patterns.iter().filter_map(|p| split_pattern(p)).collect();
        if parsed.len() != patterns.len() || parsed.is_empty() {
            continue; // not a descriptor key we understand; not ours to touch
        }
        if !parsed.iter().any(|(n, _)| *n == name) {
            continue;
        }
        if !parsed.iter().all(|(n, _)| *n == name) {
            return Err((
                "vendor_override_conflict",
                format!(
                    "lock entry `{}` mixes `{name}` with other descriptors; refusing the \
                     ambiguous rewrite",
                    block.key
                ),
            ));
        }
        if parsed.iter().all(|(_, r)| r.starts_with("npm:")) {
            let v = berry_field(&block.lines, "version").unwrap_or("");
            if v == version {
                found.push(BerryTarget {
                    key: block.key.clone(),
                    lines: block.lines.clone(),
                    is_ours: false,
                });
            } else {
                // SECURITY/CORRECTNESS: resolutions selectors are name-keyed;
                // ours would force-move this OTHER version too on the next
                // install — refuse rather than silently change versions.
                return Err((
                    "vendor_override_conflict",
                    format!(
                        "yarn.lock also resolves {name}@{v} (`{}`); the name-keyed \
                         resolutions entry vendoring writes would move that version too — \
                         refusing",
                        block.key
                    ),
                ));
            }
        } else if parsed
            .iter()
            .all(|(_, r)| parse_vendor_path(r).is_some_and(|p| p.eco == "npm"))
        {
            found.push(BerryTarget {
                key: block.key.clone(),
                lines: block.lines.clone(),
                is_ours: true,
            });
        } else {
            return Err((
                "vendor_override_conflict",
                format!(
                    "lock entry `{}` resolves {name} through a protocol vendor cannot own \
                     (workspace:/patch:/portal:/link:, or a file: outside .socket/vendor) — \
                     refusing",
                    block.key
                ),
            ));
        }
    }
    match found.len() {
        0 => Ok(None),
        1 => Ok(found.into_iter().next()),
        _ => Err((
            "vendor_override_conflict",
            format!(
                "multiple yarn.lock entries resolve {name}@{version}; refusing the \
                     ambiguous rewrite"
            ),
        )),
    }
}

/// The exact entry yarn 4 emits for a resolutions-driven `file:` tarball
/// (spike B3, verbatim), with any carried-over sections (dependencies:, …)
/// in yarn's position between `resolution` and `checksum`.
fn build_entry_lines(
    lock_key: &str,
    version: &str,
    resolution: &str,
    checksum: &str,
    carried: &[String],
) -> Vec<String> {
    let mut out = vec![format!("{lock_key}:")];
    out.push(format!("  version: {version}"));
    out.push(format!("  resolution: \"{resolution}\""));
    out.extend(carried.iter().cloned());
    out.push(format!("  checksum: {checksum}"));
    out.push("  languageName: node".to_string());
    out.push("  linkType: hard".to_string());
    out
}

/// Body sections of a lock entry that are NOT the five scalar fields we own
/// — dependency sub-maps, bin:, conditions:, … — verbatim, in order.
fn carried_sections(lines: &[String]) -> Vec<String> {
    const OWNED: [&str; 5] = [
        "version",
        "resolution",
        "checksum",
        "languageName",
        "linkType",
    ];
    let mut out = Vec::new();
    let mut i = 1;
    while i < lines.len() {
        if let Some(rest) = body_field_line(&lines[i]) {
            let field = rest.split(':').next().unwrap_or("");
            if OWNED.contains(&field) {
                i += 1;
                continue;
            }
            out.push(lines[i].clone());
            i += 1;
            // Sub-map entries (deeper indent) belong to this section.
            while i < lines.len() && body_field_line(&lines[i]).is_none() {
                out.push(lines[i].clone());
                i += 1;
            }
        } else {
            out.push(lines[i].clone());
            i += 1;
        }
    }
    out
}

/// Read a berry scalar field (`<name>: <value>`, value possibly quoted).
pub(super) fn berry_field<'a>(lines: &'a [String], field: &str) -> Option<&'a str> {
    for line in lines.iter().skip(1) {
        let Some(rest) = body_field_line(line) else {
            continue;
        };
        let Some(value) = rest.strip_prefix(field) else {
            continue;
        };
        let Some(value) = value.strip_prefix(':') else {
            continue;
        };
        return Some(value.trim().trim_matches('"'));
    }
    None
}

/// The root workspace's name: the lock's single-pattern `<name>@workspace:.`
/// entry (the key + resolution of our file: entry embed it).
fn root_workspace_name(blocks: &[LockBlock]) -> Option<String> {
    for block in blocks {
        if let [single] = split_key_patterns(&block.key).as_slice() {
            if let Some(name) = single.strip_suffix("@workspace:.") {
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

/// The `.yarnrc.yml` `compressionLevel` value, when set. A flat line scan is
/// enough: yarn writes the knob as a top-level scalar (spike B4), and any
/// value we cannot positively read as `0` makes the caller refuse.
fn yarnrc_compression_level(rc: &str) -> Option<&str> {
    rc.lines().find_map(|line| {
        let rest = line.strip_prefix("compressionLevel:")?;
        Some(rest.trim().trim_matches(['\'', '"']))
    })
}

/// JS `encodeURIComponent` (uppercase hex, RFC 2396 unreserved set) — the
/// encoding yarn uses for the `locator=` binding in keys/resolutions.
fn encode_uri_component(s: &str) -> String {
    const UNRESERVED: &[u8] = b"-_.!~*'()";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || UNRESERVED.contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The manifest's indent unit (mirrors `npm_lock::detect_indent`); defaults
/// to npm's 2 spaces.
fn detect_indent(text: &str) -> String {
    for line in text.lines() {
        let trimmed = line.trim_start_matches([' ', '\t']);
        if !trimmed.is_empty() && trimmed.len() < line.len() {
            return line[..line.len() - trimmed.len()].to_string();
        }
    }
    "  ".to_string()
}

/// Pretty-print with the detected indent + trailing newline (mirrors
/// `npm_lock::serialize_lock`), so untouched keys stay byte-identical.
fn serialize_json(value: &Value, indent: &str) -> std::io::Result<Vec<u8>> {
    use serde::Serialize;
    let mut out = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(indent.as_bytes());
    let mut ser = serde_json::Serializer::with_formatter(&mut out, formatter);
    value.serialize(&mut ser).map_err(std::io::Error::other)?;
    out.push(b'\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::PatchFileInfo;
    use crate::patch::apply::{ApplyResult, VerifyStatus};
    use serde_json::json;
    use std::collections::HashMap;
    use std::path::PathBuf;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const ORIG_INDEX: &[u8] = b"module.exports = () => 'orig';\n";
    const PATCHED_INDEX: &[u8] = b"module.exports = () => 'patched';\n";

    /// Verbatim `spikes/yarn-berry-nm/fixtures/b3-vendored-resolutions/before/package.json`.
    const B3_BEFORE_PKG: &str = r#"{
  "name": "vendor-spike",
  "version": "1.0.0",
  "packageManager": "yarn@4.12.0",
  "dependencies": {
    "left-pad": "1.3.0"
  }
}
"#;

    /// Verbatim `…/b3-vendored-resolutions/after/package.json`.
    const B3_AFTER_PKG: &str = r#"{
  "name": "vendor-spike",
  "version": "1.0.0",
  "packageManager": "yarn@4.12.0",
  "dependencies": {
    "left-pad": "1.3.0"
  },
  "resolutions": {
    "left-pad": "file:./.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz"
  }
}
"#;

    /// Verbatim `…/b3-vendored-resolutions/before/yarn.lock` (yarn 4.12.0).
    const B3_BEFORE_LOCK: &str = r#"# This file is generated by running "yarn install" inside your project.
# Manual changes might be lost - proceed with caution!

__metadata:
  version: 8
  cacheKey: 10c0

"left-pad@npm:1.3.0":
  version: 1.3.0
  resolution: "left-pad@npm:1.3.0"
  checksum: 10c0/3fb59c76e281a2f5c810ad71dbbb8eba8b10c6cf94733dc7f27b8c516a5376cacea53543e76f6ae477d866c8954b27f1e15ca349424c2542474eb5bb1d2b6955
  languageName: node
  linkType: hard

"vendor-spike@workspace:.":
  version: 0.0.0-use.local
  resolution: "vendor-spike@workspace:."
  dependencies:
    left-pad: "npm:1.3.0"
  languageName: unknown
  linkType: soft
"#;

    /// Verbatim `…/b3-vendored-resolutions/after/yarn.lock` (yarn-emitted).
    const B3_AFTER_LOCK: &str = r#"# This file is generated by running "yarn install" inside your project.
# Manual changes might be lost - proceed with caution!

__metadata:
  version: 8
  cacheKey: 10c0

"left-pad@file:./.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz::locator=vendor-spike%40workspace%3A.":
  version: 1.3.0
  resolution: "left-pad@file:./.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz#./.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz::hash=39ea9b&locator=vendor-spike%40workspace%3A."
  checksum: 10c0/7785879d9a7dc9bee6730ec55926a0ab9ed6bfe0eaee0cbcbcf00841d42488fddda51265c73eeddd54c5deca87d131e846ff66d27d890ef73f12720b458d7ca3
  languageName: node
  linkType: hard

"vendor-spike@workspace:.":
  version: 0.0.0-use.local
  resolution: "vendor-spike@workspace:."
  dependencies:
    left-pad: "npm:1.3.0"
  languageName: unknown
  linkType: soft
"#;

    /// The spike tarball's hash constants inside the after-lock fixture; the
    /// tests substitute the recomputed hashes of the tarball this build
    /// packs (everything else must match byte-for-byte).
    const SPIKE_HASH6: &str = "39ea9b";
    const SPIKE_CHECKSUM: &str = "10c0/7785879d9a7dc9bee6730ec55926a0ab9ed6bfe0eaee0cbcbcf00841d42488fddda51265c73eeddd54c5deca87d131e846ff66d27d890ef73f12720b458d7ca3";

    const YARNRC_DEFAULT: &str =
        "nodeLinker: node-modules\nenableGlobalCache: true\nenableTelemetry: false\n";

    fn spike_after_lock(hash6: &str, checksum: &str) -> String {
        B3_AFTER_LOCK
            .replace(
                &format!("::hash={SPIKE_HASH6}&"),
                &format!("::hash={hash6}&"),
            )
            .replace(SPIKE_CHECKSUM, checksum)
    }

    struct Fixture {
        tmp: tempfile::TempDir,
        record: PatchRecord,
        pkg_bytes: Vec<u8>,
        lock_bytes: Vec<u8>,
    }

    impl Fixture {
        fn root(&self) -> &Path {
            self.tmp.path()
        }

        fn installed(&self) -> PathBuf {
            self.root().join("node_modules/left-pad")
        }

        fn lock_path(&self) -> PathBuf {
            self.root().join(YARN_LOCK)
        }

        fn pkg_path(&self) -> PathBuf {
            self.root().join(PACKAGE_JSON)
        }

        fn tgz_path(&self) -> PathBuf {
            self.root()
                .join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"))
        }

        /// (hash6, full `10c0/<hex>` checksum) of the packed tarball.
        async fn packed_berry_facts(&self) -> (String, String) {
            let tgz = tokio::fs::read(self.tgz_path()).await.unwrap();
            let hash6 = hex::encode(Sha512::digest(&tgz))[..6].to_string();
            let checksum = berry_cache_checksum_10c0(&tgz, "left-pad").unwrap();
            (hash6, checksum)
        }

        async fn vendor(&self, dry_run: bool) -> VendorOutcome {
            let blobs = self.root().join(".socket/blobs");
            let sources = PatchSources::blobs_only(&blobs);
            vendor_yarn_berry(
                "pkg:npm/left-pad@1.3.0",
                &self.installed(),
                self.root(),
                &self.record,
                &sources,
                "2026-06-09T00:00:00Z",
                dry_run,
                false,
                None,
            )
            .await
        }

        async fn assert_untouched(&self) {
            assert_eq!(
                tokio::fs::read(self.pkg_path()).await.unwrap(),
                self.pkg_bytes
            );
            assert_eq!(
                tokio::fs::read(self.lock_path()).await.unwrap(),
                self.lock_bytes
            );
            assert!(!self.root().join(".socket/vendor").exists());
        }
    }

    async fn fixture_with(pkg: &str, lock: &str) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        let installed = root.join("node_modules/left-pad");
        tokio::fs::create_dir_all(&installed).await.unwrap();
        tokio::fs::write(
            installed.join("package.json"),
            br#"{"name":"left-pad","version":"1.3.0"}"#,
        )
        .await
        .unwrap();
        tokio::fs::write(installed.join("index.js"), ORIG_INDEX)
            .await
            .unwrap();

        let blobs = root.join(".socket/blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        let after_hash = compute_git_sha256_from_bytes(PATCHED_INDEX);
        tokio::fs::write(blobs.join(&after_hash), PATCHED_INDEX)
            .await
            .unwrap();

        tokio::fs::write(root.join(PACKAGE_JSON), pkg.as_bytes())
            .await
            .unwrap();
        tokio::fs::write(root.join(YARN_LOCK), lock.as_bytes())
            .await
            .unwrap();
        tokio::fs::write(root.join(YARNRC), YARNRC_DEFAULT)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(ORIG_INDEX),
                after_hash,
            },
        );
        let record = PatchRecord {
            uuid: UUID.to_string(),
            exported_at: "2026-06-01T00:00:00Z".to_string(),
            files,
            vulnerabilities: HashMap::new(),
            description: "test patch".to_string(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
        };

        Fixture {
            tmp,
            record,
            pkg_bytes: pkg.as_bytes().to_vec(),
            lock_bytes: lock.as_bytes().to_vec(),
        }
    }

    async fn fixture() -> Fixture {
        fixture_with(B3_BEFORE_PKG, B3_BEFORE_LOCK).await
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
                panic!("expected Done, got Refused {code}: {detail}")
            }
        }
    }

    fn expect_refused(outcome: VendorOutcome, want_code: &str) -> String {
        match outcome {
            VendorOutcome::Refused { code, detail } => {
                assert_eq!(code, want_code, "wrong refusal code ({detail})");
                detail
            }
            VendorOutcome::Done { result, .. } => {
                panic!(
                    "expected Refused {want_code}, got Done (success={})",
                    result.success
                )
            }
        }
    }

    #[tokio::test]
    async fn b3_fixture_oracle_pair_edit_is_byte_exact() {
        let fx = fixture().await;
        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(warnings.is_empty(), "{warnings:?}");
        let entry = entry.expect("success carries a ledger entry");

        // package.json: byte-for-byte the spike's after fixture.
        assert_eq!(
            tokio::fs::read_to_string(fx.pkg_path()).await.unwrap(),
            B3_AFTER_PKG
        );
        // yarn.lock: byte-for-byte modulo the recomputed hash= + checksum of
        // the tarball THIS build packed (checksum equality with the
        // spike-captured value is berry_zip's own oracle test).
        let (hash6, checksum) = fx.packed_berry_facts().await;
        assert_eq!(
            tokio::fs::read_to_string(fx.lock_path()).await.unwrap(),
            spike_after_lock(&hash6, &checksum)
        );

        // Ledger shape: pkg record first (application order), lock second.
        assert_eq!(entry.flavor.as_deref(), Some("yarn-berry"));
        assert_eq!(entry.wiring.len(), 2);
        let pkg_rec = &entry.wiring[0];
        assert_eq!(
            (pkg_rec.file.as_str(), pkg_rec.kind.as_str()),
            (PACKAGE_JSON, KIND_RESOLUTION)
        );
        assert_eq!(pkg_rec.action, WiringAction::Added);
        assert_eq!(pkg_rec.key.as_deref(), Some("left-pad"));
        assert_eq!(
            pkg_rec.new,
            Some(json!(format!(
                "file:./.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"
            )))
        );
        let lock_rec = &entry.wiring[1];
        assert_eq!(
            (lock_rec.file.as_str(), lock_rec.kind.as_str()),
            (YARN_LOCK, KIND_LOCK_ENTRY)
        );
        assert_eq!(lock_rec.action, WiringAction::Rewritten);
        assert_eq!(
            lock_rec.key.as_deref(),
            Some(format!(
                "\"left-pad@file:./.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz::locator=vendor-spike%40workspace%3A.\""
            ).as_str())
        );
        assert_eq!(
            lock_rec.original.as_ref().unwrap(),
            &json!([
                "\"left-pad@npm:1.3.0\":",
                "  version: 1.3.0",
                "  resolution: \"left-pad@npm:1.3.0\"",
                "  checksum: 10c0/3fb59c76e281a2f5c810ad71dbbb8eba8b10c6cf94733dc7f27b8c516a5376cacea53543e76f6ae477d866c8954b27f1e15ca349424c2542474eb5bb1d2b6955",
                "  languageName: node",
                "  linkType: hard"
            ]),
            "original must be the verbatim pre-vendor entry"
        );

        // Artifact facts + marker.
        let tgz = tokio::fs::read(fx.tgz_path()).await.unwrap();
        assert_eq!(
            entry.artifact.sha256,
            hex::encode(sha2::Sha256::digest(&tgz))
        );
        assert_eq!(entry.artifact.size, Some(tgz.len() as u64));
        assert!(fx
            .root()
            .join(format!(
                ".socket/vendor/npm/{UUID}/socket-patch.vendor.json"
            ))
            .exists());
    }

    #[tokio::test]
    async fn non_10c0_cache_key_is_refused_before_any_write() {
        let lock = B3_BEFORE_LOCK.replace("cacheKey: 10c0", "cacheKey: 10");
        let fx = fixture_with(B3_BEFORE_PKG, &lock).await;
        let detail = expect_refused(
            fx.vendor(false).await,
            "vendor_yarn_berry_cache_unsupported",
        );
        assert!(
            detail.contains("`10`"),
            "names the found cacheKey: {detail}"
        );
        fx.assert_untouched().await;
    }

    #[tokio::test]
    async fn checksum_changing_yarnrc_knob_is_refused_by_name() {
        let fx = fixture().await;
        tokio::fs::write(
            fx.root().join(YARNRC),
            "nodeLinker: node-modules\ncompressionLevel: mixed\n",
        )
        .await
        .unwrap();
        let detail = expect_refused(
            fx.vendor(false).await,
            "vendor_yarn_berry_cache_unsupported",
        );
        assert!(
            detail.contains("compressionLevel"),
            "names the knob: {detail}"
        );
        fx.assert_untouched().await;

        // An explicit `compressionLevel: 0` (the default) is fine.
        tokio::fs::write(
            fx.root().join(YARNRC),
            "nodeLinker: node-modules\ncompressionLevel: 0\n",
        )
        .await
        .unwrap();
        let (result, _, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
    }

    #[tokio::test]
    async fn user_resolutions_entry_is_refused_never_overwritten() {
        let pkg = B3_BEFORE_PKG.replace(
            "  }\n}",
            "  },\n  \"resolutions\": {\n    \"left-pad\": \"1.2.0\"\n  }\n}",
        );
        let fx = fixture_with(&pkg, B3_BEFORE_LOCK).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_override_conflict");
        assert!(detail.contains("left-pad"), "{detail}");
        assert!(!fx.root().join(".socket/vendor").exists());
        assert_eq!(tokio::fs::read(fx.pkg_path()).await.unwrap(), fx.pkg_bytes);
    }

    /// A user-authored BARE-name pin to the exact version being vendored is
    /// taken over: the value moves to our spec, the wiring records the pin
    /// as `original`, and revert restores it (table kept). Range-keyed
    /// selectors keep refusing.
    #[tokio::test]
    async fn user_exact_pin_resolution_is_taken_over_and_revert_restores_it() {
        let pkg_before = B3_BEFORE_PKG.replace(
            "  }\n}",
            "  },\n  \"resolutions\": {\n    \"left-pad\": \"1.3.0\"\n  }\n}",
        );
        let fx = fixture_with(&pkg_before, B3_BEFORE_LOCK).await;

        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();

        let pkg: Value =
            serde_json::from_slice(&tokio::fs::read(fx.pkg_path()).await.unwrap()).unwrap();
        let val = pkg["resolutions"]["left-pad"].as_str().unwrap();
        assert!(
            parse_vendor_path(val).is_some_and(|p| p.eco == "npm"),
            "pin value rewritten to our spec: {val}"
        );

        let rec = entry
            .wiring
            .iter()
            .find(|r| r.kind == KIND_RESOLUTION)
            .unwrap();
        assert_eq!(rec.action, WiringAction::Rewritten);
        assert_eq!(
            rec.original,
            Some(Value::String("1.3.0".to_string())),
            "the user's pin is the original"
        );

        // Revert restores the pin in place (the resolutions table stays).
        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        let pkg: Value =
            serde_json::from_slice(&tokio::fs::read(fx.pkg_path()).await.unwrap()).unwrap();
        assert_eq!(
            pkg["resolutions"]["left-pad"],
            Value::String("1.3.0".to_string()),
            "pin restored"
        );

        // A range-keyed selector with the same value still refuses.
        let pkg = B3_BEFORE_PKG.replace(
            "  }\n}",
            "  },\n  \"resolutions\": {\n    \"left-pad@npm:1.x\": \"1.3.0\"\n  }\n}",
        );
        let fx = fixture_with(&pkg, B3_BEFORE_LOCK).await;
        expect_refused(fx.vendor(false).await, "vendor_override_conflict");
    }

    #[tokio::test]
    async fn missing_entry_and_other_version_guards() {
        // No left-pad entry at all.
        let lock = B3_BEFORE_LOCK.replace("left-pad@npm:1.3.0", "is-odd@npm:1.3.0");
        let fx = fixture_with(B3_BEFORE_PKG, &lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_not_found");
        assert!(detail.contains("yarn install"), "{detail}");

        // A SECOND version of the name in the lock: the name-keyed
        // resolutions entry would move it too — refuse.
        let lock = format!(
            "{B3_BEFORE_LOCK}\n\"left-pad@npm:^1.2.0\":\n  version: 1.2.0\n  resolution: \"left-pad@npm:1.2.0\"\n  checksum: 10c0/aa\n  languageName: node\n  linkType: hard\n"
        );
        let fx = fixture_with(B3_BEFORE_PKG, &lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_override_conflict");
        assert!(
            detail.contains("1.2.0"),
            "names the other version: {detail}"
        );
        fx.assert_untouched().await;
    }

    #[tokio::test]
    async fn rerun_is_in_sync_and_byte_stable() {
        let fx = fixture().await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        assert!(entry.is_some());
        let pkg_first = tokio::fs::read(fx.pkg_path()).await.unwrap();
        let lock_first = tokio::fs::read(fx.lock_path()).await.unwrap();
        let tgz_first = tokio::fs::read(fx.tgz_path()).await.unwrap();

        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(
            entry.is_none(),
            "in-sync re-run must not produce a new ledger entry"
        );
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(
            result
                .files_verified
                .iter()
                .all(|v| v.status == VerifyStatus::AlreadyPatched),
            "{:?}",
            result.files_verified
        );
        assert_eq!(tokio::fs::read(fx.pkg_path()).await.unwrap(), pkg_first);
        assert_eq!(tokio::fs::read(fx.lock_path()).await.unwrap(), lock_first);
        assert_eq!(tokio::fs::read(fx.tgz_path()).await.unwrap(), tgz_first);
    }

    #[tokio::test]
    async fn dry_run_writes_nothing() {
        let fx = fixture().await;
        let (result, entry, _) = expect_done(fx.vendor(true).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_none());
        assert!(result.files_patched.is_empty());
        fx.assert_untouched().await;
        assert_eq!(
            tokio::fs::read(fx.installed().join("index.js"))
                .await
                .unwrap(),
            ORIG_INDEX,
            "vendor never patches the installed copy in place"
        );
    }

    #[tokio::test]
    async fn dependency_submaps_are_carried_into_the_new_entry() {
        // A target entry WITH a dependencies sub-map; the patch also rewrites
        // package.json, which must surface the loud staleness advisory.
        let lock = B3_BEFORE_LOCK.replace(
            "  resolution: \"left-pad@npm:1.3.0\"\n  checksum:",
            "  resolution: \"left-pad@npm:1.3.0\"\n  dependencies:\n    wow: \"npm:^1.0.0\"\n  checksum:",
        );
        let mut fx = fixture_with(B3_BEFORE_PKG, &lock).await;
        let before: &[u8] = br#"{"name":"left-pad","version":"1.3.0"}"#;
        let after: &[u8] = br#"{"name":"left-pad","version":"1.3.0","description":"patched"}"#;
        let after_hash = compute_git_sha256_from_bytes(after);
        tokio::fs::write(fx.root().join(".socket/blobs").join(&after_hash), after)
            .await
            .unwrap();
        fx.record.files.insert(
            "package/package.json".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(before),
                after_hash,
            },
        );

        let (result, _, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_dep_manifest_stale"),
            "{warnings:?}"
        );

        let text = tokio::fs::read_to_string(fx.lock_path()).await.unwrap();
        let (_, checksum) = fx.packed_berry_facts().await;
        assert!(
            text.contains(&format!(
                "&locator=vendor-spike%40workspace%3A.\"\n  dependencies:\n    wow: \"npm:^1.0.0\"\n  checksum: {checksum}"
            )),
            "sub-map carried between resolution and checksum: {text}"
        );
    }

    #[tokio::test]
    async fn commit_pair_unwinds_package_json_when_the_lock_write_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::write(root.join(PACKAGE_JSON), b"orig-pkg")
            .await
            .unwrap();
        // A directory at the lock path makes the atomic rename fail.
        tokio::fs::create_dir(root.join(YARN_LOCK)).await.unwrap();

        let err = commit_pair(root, b"new-pkg", b"orig-pkg", b"new-lock")
            .await
            .unwrap_err();
        assert!(err.contains("restored"), "{err}");
        assert_eq!(
            tokio::fs::read(root.join(PACKAGE_JSON)).await.unwrap(),
            b"orig-pkg",
            "package.json unwound to its original bytes"
        );
    }

    #[tokio::test]
    async fn revert_round_trips_both_files_and_removes_the_artifact() {
        let fx = fixture().await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();

        // Dry-run revert: nothing restored or removed.
        let outcome = revert_yarn_berry(&entry, fx.root(), true).await;
        assert!(outcome.success);
        assert!(fx.tgz_path().exists());

        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert_eq!(
            tokio::fs::read(fx.pkg_path()).await.unwrap(),
            fx.pkg_bytes,
            "package.json restored byte-for-byte (empty resolutions table dropped)"
        );
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes,
            "yarn.lock restored byte-for-byte"
        );
        assert!(!fx
            .root()
            .join(format!(".socket/vendor/npm/{UUID}"))
            .exists());
    }

    #[tokio::test]
    async fn revert_leaves_drifted_fragments_alone_with_warnings() {
        // Lock drift: the user re-resolved our entry back to the registry.
        let fx = fixture().await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let text = tokio::fs::read_to_string(fx.lock_path()).await.unwrap();
        // Replace the ENTIRE resolution line (any leftover vendor-path tail
        // would still parse as ours and defeat the drift simulation).
        let drifted: String = text
            .lines()
            .map(|l| {
                if l.starts_with("  resolution: \"left-pad@file:") {
                    "  resolution: \"left-pad@npm:1.3.0\"".to_string()
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        assert_ne!(drifted, text, "the drift edit must hit");
        tokio::fs::write(fx.lock_path(), &drifted).await.unwrap();

        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "{:?}",
            outcome.warnings
        );
        // The drifted lock entry stays; the (still-ours) resolutions entry
        // was removed; the artifact is gone.
        let after = tokio::fs::read_to_string(fx.lock_path()).await.unwrap();
        assert!(
            after.contains("left-pad@file:")
                && after.contains("  resolution: \"left-pad@npm:1.3.0\""),
            "drifted entry left alone: {after}"
        );
        let pkg: Value =
            serde_json::from_slice(&tokio::fs::read(fx.pkg_path()).await.unwrap()).unwrap();
        assert!(pkg.get("resolutions").is_none());
        assert!(!fx.tgz_path().exists());

        // Manifest drift: the user repointed the resolutions entry.
        let fx = fixture().await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let pkg_text = tokio::fs::read_to_string(fx.pkg_path()).await.unwrap();
        tokio::fs::write(
            fx.pkg_path(),
            pkg_text.replace(
                &format!("file:./.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"),
                "npm:1.3.1",
            ),
        )
        .await
        .unwrap();
        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted" && w.detail.contains("resolutions")),
            "{:?}",
            outcome.warnings
        );
        let pkg: Value =
            serde_json::from_slice(&tokio::fs::read(fx.pkg_path()).await.unwrap()).unwrap();
        assert_eq!(
            pkg["resolutions"]["left-pad"],
            json!("npm:1.3.1"),
            "user-repointed entry left alone"
        );
        // The lock was still restored (independent fragment).
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes
        );
    }

    #[tokio::test]
    async fn revert_allowlist_fails_closed_on_foreign_files() {
        let fx = fixture().await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let mut entry = entry.unwrap();
        for evil in ["../x", "Cargo.toml"] {
            entry.wiring.push(WiringRecord {
                file: evil.to_string(),
                kind: KIND_LOCK_ENTRY.to_string(),
                action: WiringAction::Rewritten,
                key: Some("whatever".to_string()),
                original: Some(json!(["pwned:"])),
                new: Some(json!(["pwned:"])),
            });
        }

        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        let allow = outcome
            .warnings
            .iter()
            .filter(|w| w.detail.contains("allowlist"))
            .count();
        assert_eq!(
            allow, 2,
            "every foreign file warned: {:?}",
            outcome.warnings
        );
        // The legitimate records still reverted both files; the foreign
        // paths were never created or touched.
        assert_eq!(tokio::fs::read(fx.pkg_path()).await.unwrap(), fx.pkg_bytes);
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes
        );
        assert!(!fx.root().join("Cargo.toml").exists());
        assert!(!fx.root().parent().unwrap().join("x").exists());
    }

    #[tokio::test]
    async fn revert_refuses_tampered_uuid_fail_closed() {
        let fx = fixture().await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let mut entry = entry.unwrap();
        entry.uuid = "../../escape".to_string();
        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(!outcome.success, "tampered uuid must fail closed");
    }

    #[test]
    fn helper_grammar() {
        // encodeURIComponent semantics, incl. a scoped workspace name.
        assert_eq!(
            encode_uri_component("vendor-spike@workspace:."),
            "vendor-spike%40workspace%3A."
        );
        assert_eq!(
            encode_uri_component("@acme/root@workspace:."),
            "%40acme%2Froot%40workspace%3A."
        );

        // Root workspace name extraction + berry field reads.
        let blocks = scan_blocks(B3_BEFORE_LOCK);
        assert_eq!(
            root_workspace_name(&blocks).as_deref(),
            Some("vendor-spike")
        );
        let meta = blocks.iter().find(|b| b.key == "__metadata").unwrap();
        assert_eq!(berry_field(&meta.lines, "cacheKey"), Some("10c0"));
        let lp = blocks
            .iter()
            .find(|b| b.key == "\"left-pad@npm:1.3.0\"")
            .unwrap();
        assert_eq!(berry_field(&lp.lines, "version"), Some("1.3.0"));
        assert_eq!(
            berry_field(&lp.lines, "resolution"),
            Some("left-pad@npm:1.3.0")
        );

        // Carried sections: dep sub-maps survive, owned scalars do not.
        let lines: Vec<String> = [
            "\"left-pad@npm:1.3.0\":",
            "  version: 1.3.0",
            "  resolution: \"left-pad@npm:1.3.0\"",
            "  dependencies:",
            "    wow: \"npm:^1.0.0\"",
            "  checksum: 10c0/aa",
            "  languageName: node",
            "  linkType: hard",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            carried_sections(&lines),
            vec![
                "  dependencies:".to_string(),
                "    wow: \"npm:^1.0.0\"".to_string()
            ]
        );
    }
}
