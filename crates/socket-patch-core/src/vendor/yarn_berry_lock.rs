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
use crate::utils::fs::atomic_write_bytes_preserving_mode;
use crate::utils::uri::encode_uri_component;

use super::berry_zip::berry_cache_checksum_10c0;
use super::common::{already_patched_result, detect_eol, detect_indent, refused, serialize_json};
use super::npm_common::{
    done_failure_unstage, guard_coordinates, guard_revert_uuid_dir, stage_patch_pack, tgz_rel_leaf,
};
use super::path::parse_vendor_path;
use super::state::{
    write_marker, VendorArtifact, VendorEntry, VendorMarker, WiringAction, WiringRecord,
};
use super::yarn_classic_lock::{
    body_field_line, lines_to_json, pattern_real_name, read_regular, read_regular_to_string,
    read_yarn_lock, replace_block, revert_recorded_block, scan_blocks, split_key_patterns,
    split_pattern, LockBlock,
};
use super::{RevertOpts, RevertOutcome, VendorOutcome, VendorWarning};

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
    let lock_text = match read_yarn_lock(project_root).await {
        Ok(t) => t,
        Err(outcome) => return *outcome,
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
    match read_regular_to_string(&project_root.join(YARNRC)).await {
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
    let pkg_bytes = match read_regular(&pkg_path).await {
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
    let scan = match scan_berry_target(&blocks, name, version) {
        Ok(scan) => scan,
        Err((code, detail)) => return refused(code, detail),
    };
    // An `alias@npm:<name>@…` descriptor consumes the patched package under
    // a different ident; the bare-name resolutions entry vendoring writes
    // can never move it, so that copy keeps installing the UNPATCHED bytes.
    // Surface every such entry loudly instead of silently part-patching.
    for key in &scan.alias_keys {
        warnings.push(VendorWarning::new(
            "vendor_alias_entry_skipped",
            format!(
                "{YARN_LOCK} entry `{key}` consumes {name}@{version} through an npm: alias; \
                 the bare-name resolutions entry vendoring writes cannot move aliased \
                 descriptors, so that copy keeps installing the UNPATCHED registry bytes"
            ),
        ));
    }
    let (target, target_is_ours) = match scan.target {
        Some((idx, is_ours)) => (&blocks[idx], is_ours),
        None => {
            if !scan.alias_keys.is_empty() {
                return refused(
                    "vendor_lock_entry_not_found",
                    format!(
                        "{YARN_LOCK} resolves {name}@{version} only through npm: alias \
                         descriptors ({}); berry resolutions are name-keyed and cannot \
                         reach aliased descriptors, so vendoring cannot rewire this \
                         project's copy",
                        scan.alias_keys.join(", ")
                    ),
                );
            }
            return refused(
                "vendor_lock_entry_not_found",
                format!(
                    "{YARN_LOCK} has no `{name}@npm:` entry resolving {version} — make sure \
                     the package is installed and locked (`yarn install`) before vendoring"
                ),
            );
        }
    };
    let patches_manifest = record
        .files
        .keys()
        .any(|k| normalize_file_path(k) == "package.json");

    // ── 7. Stage → patch → pack (shared flavor-agnostic pipeline) ─────────
    // A wiring failure past this point must unwind the uuid dir staging is
    // about to create — but never one that already existed (a same-uuid
    // re-vendor's dir may still be referenced by live wiring).
    let uuid_dir_preexisted = tokio::fs::metadata(project_root.join(&uuid_dir_rel))
        .await
        .is_ok();
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
        Err(e) => {
            return done_failure_unstage(
                purl,
                format!("cannot re-read the packed tarball: {e}"),
                project_root,
                &uuid_dir_rel,
                uuid_dir_preexisted,
            )
            .await
        }
    };
    let tgz_sha512 = hex::encode(Sha512::digest(&tgz_bytes));
    // `hash=` — the first 6 hex chars of sha512(tgz): the lock-committed
    // tamper guard on the tarball itself (spike B3, flips on any byte edit).
    let hash6 = &tgz_sha512[..6];
    let checksum = match berry_cache_checksum_10c0(&tgz_bytes, name) {
        Ok(c) => c,
        Err(e) => {
            return done_failure_unstage(
                purl,
                format!("cannot compute the berry cache checksum for {name}: {e}"),
                project_root,
                &uuid_dir_rel,
                uuid_dir_preexisted,
            )
            .await
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
    // The exact entry yarn 4 emits for a resolutions-driven `file:` tarball
    // (spike B3, verbatim), carried sections in yarn's position between
    // `resolution` and `checksum`.
    let mut new_lines = vec![
        format!("{lock_key}:"),
        format!("  version: {version}"),
        format!("  resolution: \"{resolution}\""),
    ];
    new_lines.extend(carried);
    new_lines.push(format!("  checksum: {checksum}"));
    new_lines.push("  languageName: node".to_string());
    new_lines.push("  linkType: hard".to_string());

    // ── 10. In-sync hot path: nothing to write, nothing to record ─────────
    let existing_res = pkg_obj.get("resolutions").and_then(|r| r.get(name));
    let pkg_in_sync = existing_res.and_then(Value::as_str) == Some(spec.as_str());
    if pkg_in_sync && target_is_ours && target.lines == new_lines {
        return VendorOutcome::Done {
            result: already_patched_result(purl, &dest, &record.files),
            entry: None,
            warnings,
        };
    }

    // ── 11. Build both new byte images, then commit pkg-first/lock-second ─
    let existing_entry = existing_res.is_some();
    let mut new_pkg = pkg.clone();
    {
        let obj = new_pkg.as_object_mut().expect("validated above");
        let res = obj
            .entry("resolutions".to_string())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        let Some(res_obj) = res.as_object_mut() else {
            return done_failure_unstage(
                purl,
                "resolutions table vanished mid-edit".to_string(),
                project_root,
                &uuid_dir_rel,
                uuid_dir_preexisted,
            )
            .await;
        };
        res_obj.insert(name.to_string(), Value::String(spec.clone()));
    }
    let pkg_indent = detect_indent(&String::from_utf8_lossy(&pkg_bytes));
    let new_pkg_bytes = match serialize_json(&new_pkg, &pkg_indent) {
        Ok(b) => b,
        Err(e) => {
            return done_failure_unstage(
                purl,
                format!("cannot serialize {PACKAGE_JSON}: {e}"),
                project_root,
                &uuid_dir_rel,
                uuid_dir_preexisted,
            )
            .await
        }
    };
    let new_lock_text = replace_block(&lock_text, target, &new_lines, detect_eol(&lock_text));
    if let Err(e) = commit_pair(
        project_root,
        &new_pkg_bytes,
        &pkg_bytes,
        new_lock_text.as_bytes(),
    )
    .await
    {
        return done_failure_unstage(purl, e, project_root, &uuid_dir_rel, uuid_dir_preexisted)
            .await;
    }

    // ── 12. Marker + ledger entry ─────────────────────────────────────────
    let marker = VendorMarker::new("npm", &base_purl, record, vendored_at);
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
            original: if target_is_ours {
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
            file_inventory: None,
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
/// Test-only shorthand — production routes through
/// [`revert_yarn_berry_opts`] (via
/// [`super::npm_flavor::revert_npm_any_opts`]).
#[cfg(test)]
pub async fn revert_yarn_berry(
    entry: &VendorEntry,
    project_root: &Path,
    dry_run: bool,
) -> RevertOutcome {
    revert_yarn_berry_opts(entry, project_root, RevertOpts::new(dry_run)).await
}

/// [`revert_yarn_berry`] with full [`RevertOpts`]: `keep_artifact` skips the
/// artifact deletion — and the refusals that exist only to protect it —
/// while the wiring restore runs unchanged.
pub async fn revert_yarn_berry_opts(
    entry: &VendorEntry,
    project_root: &Path,
    opts: RevertOpts,
) -> RevertOutcome {
    let RevertOpts {
        dry_run,
        keep_artifact,
    } = opts;
    // SECURITY: shared fail-closed guard on the tamper-able uuid, before any
    // disk access.
    let uuid_dir_rel = match guard_revert_uuid_dir(&entry.uuid) {
        Ok(d) => d,
        Err(outcome) => return outcome,
    };
    // Nothing to replay (a `repair`-reconstructed entry): the artifact may
    // only be removed when the project provably no longer resolves through
    // it — otherwise refuse, fail-closed, instead of silently bricking
    // installs. Berry resolves through BOTH wired files (the yarn.lock
    // entry AND the package.json resolutions value each carry the uuid dir
    // path), so each is probed independently — a dangling `file:` spec in
    // either fails every subsequent install on the missing tarball. Runs
    // before the dry-run return so a preview never advertises a revert the
    // wet run refuses. Skipped under `keep_artifact`: the refusal exists
    // only to protect the deletion, which a preserve-state revert never
    // performs.
    if entry.wiring.is_empty() {
        for wired in [YARN_LOCK, PACKAGE_JSON] {
            if let Some(blocked) = super::npm_lock::guard_unwired_textual_revert(
                project_root,
                &entry.uuid,
                &uuid_dir_rel,
                &[wired],
            )
            .await
            {
                return blocked;
            }
        }
    }
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
        match read_regular_to_string(&lock_path).await {
            Ok(mut text) => {
                let mut changed = false;
                for rec in lock_recs {
                    changed |= revert_recorded_block(
                        &mut text,
                        rec,
                        &entry.uuid,
                        KIND_LOCK_ENTRY,
                        "lock entry",
                        |lines| berry_field(lines, "resolution"),
                        &mut outcome.warnings,
                    );
                }
                if changed {
                    if let Err(e) =
                        atomic_write_bytes_preserving_mode(&lock_path, text.as_bytes()).await
                    {
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
        match read_regular(&pkg_path).await {
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
                            if let Err(e) =
                                atomic_write_bytes_preserving_mode(&pkg_path, &out).await
                            {
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

    // LOSSINESS GUARD (residual #131): when any wiring record was left
    // alone ("drifted; left alone"), the uuid dir may hold the only copy of
    // what the lock — or the redirect ledger's recorded originals — still
    // points at. Keep it (and let the CLI keep the ledger entry) instead of
    // deleting evidence out from under a lock we just refused to touch.
    if outcome.drift_skipped() {
        outcome.keep_artifact(&uuid_dir_rel);
        return outcome;
    }

    // `--preserve-state` (`keep_artifact`): the wiring restore above already
    // ran; the artifact dir stays behind (and the caller keeps the ledger
    // entry), so the deletion — and the still-wired probes that exist only
    // to protect it — are skipped.
    if keep_artifact {
        return outcome;
    }

    // FAIL-CLOSED (same brick class as the unwired guard above, twin of
    // npm_lock's post-restore probe): the restore only rewrites the
    // fragments the wiring recorded, but yarn can still resolve through the
    // artifact via a lock entry or resolutions value the wiring never named
    // (hand-copied or re-keyed since vendoring). Deleting the uuid dir then
    // fails every subsequent install on the missing tarball, silently. Both
    // wired files are probed independently; absent or unprovable keeps the
    // wired revert's existing missing-file tolerance.
    for wired in [YARN_LOCK, PACKAGE_JSON] {
        if super::npm_flavor::lock_text_mentions_uuid(project_root, &[wired], &entry.uuid).await
            == Some(true)
        {
            let detail = format!(
                "refusing to remove {uuid_dir_rel}: after restoring the recorded wiring, \
                 {wired} still resolves through it (was the entry re-keyed or hand-copied \
                 since vendoring?) — deleting the artifact would make every subsequent \
                 install fail; restore the pre-vendor {wired} (or remove the dependency and \
                 re-lock) and re-run `vendor --revert`"
            );
            outcome.success = false;
            outcome.error = Some(detail.clone());
            outcome.warnings.push(VendorWarning::new(
                "vendor_lock_still_wired_revert_blocked",
                detail,
            ));
            return outcome;
        }
    }

    if let Err(e) = remove_tree(&project_root.join(&uuid_dir_rel)).await {
        return RevertOutcome::failed(format!("cannot remove {uuid_dir_rel}: {e}"));
    }

    outcome
}

// ───────────────────────────── revert internals ─────────────────────────────

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
        // ALREADY CONVERGED: for an Added entry (no recorded original) the
        // reverted state IS "no resolutions entry" — an earlier partial
        // revert already removed it (dropping the then-empty table). Not
        // drift: stay silent so the drift-skip keep gate can converge.
        if rec.original.is_none() {
            return;
        }
        warnings.push(VendorWarning::new(
            "vendor_lock_entry_drifted",
            format!("resolutions entry `{key}` no longer exists; nothing to remove"),
        ));
        return;
    };
    let live = res_obj.get(key).and_then(Value::as_str);
    let Some(live) = live else {
        // ALREADY CONVERGED (same as the missing-table case above): our
        // Added entry is already gone.
        if rec.original.is_none() {
            return;
        }
        warnings.push(VendorWarning::new(
            "vendor_lock_entry_drifted",
            format!("resolutions entry `{key}` no longer exists; nothing to remove"),
        ));
        return;
    };
    // ALREADY CONVERGED: a takeover entry already restored to the user's
    // recorded pin. Not drift.
    if rec.original.as_ref().and_then(Value::as_str) == Some(live) {
        return;
    }
    let ours = parse_vendor_path(live).is_some_and(|p| p.eco == "npm" && p.uuid == entry_uuid);
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
    atomic_write_bytes_preserving_mode(&pkg_path, new_pkg)
        .await
        .map_err(|e| format!("cannot write {PACKAGE_JSON}: {e}"))?;
    if let Err(e) =
        atomic_write_bytes_preserving_mode(&project_root.join(YARN_LOCK), new_lock).await
    {
        return match atomic_write_bytes_preserving_mode(&pkg_path, orig_pkg).await {
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

/// The result of [`scan_berry_target`]: the one replaceable entry (when
/// present) plus every alias-descriptor entry a bare-name resolutions entry
/// cannot reach.
struct BerryTargetScan {
    /// `(index into blocks, is_ours)`, where `is_ours` means the entry is
    /// already one of our `file:` entries (stale uuid or current).
    target: Option<(usize, bool)>,
    /// Lock keys of `alias@npm:<name>@…` entries resolving the patched
    /// version — semantically out of reach for a name-keyed resolutions
    /// entry, so the caller must surface them instead of silently skipping.
    alias_keys: Vec<String>,
}

/// Find the one replaceable entry for `name@version` — refusing fail-closed
/// on anything a bare-name resolutions entry would also move (other versions
/// of the name, non-npm protocols, ambiguous duplicates) — and collect the
/// npm-alias descriptor entries of the same package that vendoring can never
/// rewire.
fn scan_berry_target(
    blocks: &[LockBlock],
    name: &str,
    version: &str,
) -> Result<BerryTargetScan, (&'static str, String)> {
    let mut found: Vec<(usize, bool)> = Vec::new();
    let mut alias_keys: Vec<String> = Vec::new();
    for (idx, block) in blocks.iter().enumerate() {
        if block.key == "__metadata" {
            continue;
        }
        let patterns = split_key_patterns(&block.key);
        let parsed: Vec<(&str, &str)> = patterns.iter().filter_map(|p| split_pattern(p)).collect();
        if parsed.len() != patterns.len() || parsed.is_empty() {
            continue; // not a descriptor key we understand; not ours to touch
        }
        if !parsed.iter().any(|(n, _)| *n == name) {
            // `alias@npm:<name>@…` descriptors carry the real name inside
            // the range; a name-keyed resolutions entry cannot move them.
            if berry_field(&block.lines, "version") == Some(version)
                && patterns.iter().any(|p| pattern_real_name(p) == Some(name))
            {
                alias_keys.push(block.key.clone());
            }
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
                found.push((idx, false));
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
            found.push((idx, true));
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
    if found.len() > 1 {
        return Err((
            "vendor_override_conflict",
            format!(
                "multiple yarn.lock entries resolve {name}@{version}; refusing the \
                     ambiguous rewrite"
            ),
        ));
    }
    Ok(BerryTargetScan {
        target: found.into_iter().next(),
        alias_keys,
    })
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
/// value we cannot positively read as `0` makes the caller refuse. Shared
/// with the hosted-redirect rewriter, whose cache-checksum gate is identical.
pub(crate) fn yarnrc_compression_level(rc: &str) -> Option<&str> {
    rc.lines().find_map(|line| {
        let rest = line.strip_prefix("compressionLevel:")?;
        Some(rest.trim().trim_matches(['\'', '"']))
    })
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

    /// An `alias@npm:left-pad@…` descriptor consumes the patched package
    /// under a different ident; the name-keyed resolutions entry can never
    /// move it, so vendoring must warn loudly about the unpatched copy
    /// instead of silently part-patching.
    #[tokio::test]
    async fn alias_descriptor_entry_warns_and_stays_untouched() {
        const ALIAS_BLOCK: &str = "\"safe-pad@npm:left-pad@1.3.0\":\n  version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n  checksum: 10c0/aa\n  languageName: node\n  linkType: hard\n";
        let lock = format!("{B3_BEFORE_LOCK}\n{ALIAS_BLOCK}");
        let fx = fixture_with(B3_BEFORE_PKG, &lock).await;

        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some(), "the plain entry still vendors");
        let warning = warnings
            .iter()
            .find(|w| w.code == "vendor_alias_entry_skipped")
            .unwrap_or_else(|| panic!("expected the alias skip warning: {warnings:?}"));
        assert!(
            warning.detail.contains("safe-pad@npm:left-pad@1.3.0"),
            "names the alias entry: {}",
            warning.detail
        );

        let text = tokio::fs::read_to_string(fx.lock_path()).await.unwrap();
        assert!(
            text.contains("left-pad@file:./"),
            "plain entry rewired: {text}"
        );
        assert!(
            text.contains(ALIAS_BLOCK),
            "alias entry byte-untouched: {text}"
        );

        // An alias of ANOTHER version is out of the patch's scope: no noise.
        let other = ALIAS_BLOCK.replace("1.3.0", "1.2.0");
        let lock = format!("{B3_BEFORE_LOCK}\n{other}");
        let fx = fixture_with(B3_BEFORE_PKG, &lock).await;
        let (result, _, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(
            !warnings
                .iter()
                .any(|w| w.code == "vendor_alias_entry_skipped"),
            "{warnings:?}"
        );
    }

    /// When the ONLY entry for the patched version is an alias descriptor,
    /// the refusal must say so — the generic "make sure the package is
    /// installed" detail would send the user to a `yarn install` that
    /// changes nothing.
    #[tokio::test]
    async fn alias_only_lock_refuses_with_alias_detail() {
        let lock = B3_BEFORE_LOCK.replace(
            "\"left-pad@npm:1.3.0\":",
            "\"safe-pad@npm:left-pad@1.3.0\":",
        );
        let fx = fixture_with(B3_BEFORE_PKG, &lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_not_found");
        assert!(detail.contains("alias"), "{detail}");
        assert!(detail.contains("safe-pad@npm:left-pad@1.3.0"), "{detail}");
        fx.assert_untouched().await;
    }

    /// A wiring failure AFTER the tarball is packed (here: the fail-closed
    /// berry cache checksum refusing a non-ASCII filename) must unwind the
    /// freshly created uuid dir — no ledger entry exists for it, so
    /// `--revert` could never clean it up and the user would commit an
    /// unwired artifact.
    #[tokio::test]
    async fn post_pack_wiring_failure_unwinds_the_staged_artifact() {
        let fx = fixture().await;
        tokio::fs::write(fx.installed().join("café.js"), b"x")
            .await
            .unwrap();

        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(!result.success, "non-ASCII filename must fail the wiring");
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or("")
                .contains("berry cache checksum"),
            "{:?}",
            result.error
        );
        assert!(entry.is_none());
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

    /// package.json and yarn.lock are user-owned files we merely edit: the
    /// vendor pair commit and the revert restore must keep their permission
    /// bits (a 0600 private file must not silently become umask-default 0644).
    #[cfg(unix)]
    #[tokio::test]
    async fn pair_writes_preserve_file_modes() {
        use std::os::unix::fs::PermissionsExt;
        let fx = fixture().await;
        tokio::fs::set_permissions(fx.pkg_path(), std::fs::Permissions::from_mode(0o600))
            .await
            .unwrap();
        tokio::fs::set_permissions(fx.lock_path(), std::fs::Permissions::from_mode(0o640))
            .await
            .unwrap();
        let mode = |path: PathBuf| async move {
            tokio::fs::metadata(path)
                .await
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };

        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();
        assert_eq!(
            mode(fx.pkg_path()).await,
            0o600,
            "vendor must preserve package.json's mode"
        );
        assert_eq!(
            mode(fx.lock_path()).await,
            0o640,
            "vendor must preserve yarn.lock's mode"
        );

        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            mode(fx.pkg_path()).await,
            0o600,
            "revert must preserve package.json's mode"
        );
        assert_eq!(
            mode(fx.lock_path()).await,
            0o640,
            "revert must preserve yarn.lock's mode"
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
        // was removed; the artifact is KEPT (residual #131: the drifted
        // entry's recorded original may still be needed later) and the keep
        // is surfaced.
        let after = tokio::fs::read_to_string(fx.lock_path()).await.unwrap();
        assert!(
            after.contains("left-pad@file:")
                && after.contains("  resolution: \"left-pad@npm:1.3.0\""),
            "drifted entry left alone: {after}"
        );
        let pkg: Value =
            serde_json::from_slice(&tokio::fs::read(fx.pkg_path()).await.unwrap()).unwrap();
        assert!(pkg.get("resolutions").is_none());
        assert!(fx.tgz_path().exists(), "drift-skip must keep the artifact");
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_artifact_kept"),
            "the keep must be surfaced: {:?}",
            outcome.warnings
        );

        // KEEP-GATE LIVENESS: undo ONLY the lock drift (repoint the
        // resolution line back at the vendored locator). The resolutions
        // entry the first revert already removed must now read as CONVERGED
        // (Added record + key absent), not drifted — otherwise every later
        // revert would hit the "no longer exists; nothing to remove" branch
        // and keep the artifacts + ledger entry forever.
        let vendored_resolution = text
            .lines()
            .find(|l| l.starts_with("  resolution: \"left-pad@file:"))
            .expect("the vendored lock must carry our resolution line")
            .to_string();
        let healed = after.replace("  resolution: \"left-pad@npm:1.3.0\"", &vendored_resolution);
        assert_ne!(healed, after, "the undo edit must hit");
        tokio::fs::write(fx.lock_path(), &healed).await.unwrap();

        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome.warnings.is_empty(),
            "the already-removed resolutions entry is converged, not drifted: {:?}",
            outcome.warnings
        );
        assert!(!outcome.kept_artifact);
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes,
            "lock restored byte-for-byte"
        );
        assert!(
            !fx.root()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "artifact pruned once the revert converges"
        );

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
        // The manifest drift-skip keeps the artifact too (residual #131).
        assert!(fx.tgz_path().exists(), "drift-skip must keep the artifact");
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

    // ── empty-wiring (reconstructed) revert guard ──────────────────────────

    /// Reshape a vendored entry into what `repair`'s no-ledger
    /// reconstruction persists: same uuid/artifact, EMPTY wiring. With
    /// nothing to replay, revert must refuse (fail-closed) while yarn.lock
    /// still resolves through the artifact — dry-run preview included —
    /// still remove a genuinely orphaned artifact, fail closed on an
    /// unreadable lock, and proceed when no lock exists at all.
    #[tokio::test]
    async fn empty_wiring_revert_guards_against_bricking_installs() {
        let fx = fixture().await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let mut entry = entry.unwrap();
        entry.wiring.clear();
        let lock_vendored = tokio::fs::read(fx.lock_path()).await.unwrap();

        // Still referenced: refuse, artifact and lock untouched.
        for dry_run in [true, false] {
            let outcome = revert_yarn_berry(&entry, fx.root(), dry_run).await;
            assert!(!outcome.success, "dry_run={dry_run}: must refuse");
            assert!(
                outcome
                    .warnings
                    .iter()
                    .any(|w| w.code == "vendor_wiring_unknown_revert_blocked"),
                "{:?}",
                outcome.warnings
            );
            assert!(fx.tgz_path().exists(), "artifact survives the refusal");
            assert_eq!(
                tokio::fs::read(fx.lock_path()).await.unwrap(),
                lock_vendored,
                "lock untouched"
            );
        }

        // Unreadable lock (not UTF-8): undeterminable, fail closed.
        tokio::fs::write(fx.lock_path(), [0xff, 0xfe, b'x'])
            .await
            .unwrap();
        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(!outcome.success, "unreadable-lock revert must refuse");
        assert!(fx.tgz_path().exists());

        // Re-locked away from the artifact AND the resolutions entry gone
        // (provably orphaned — package.json is probed too, see the
        // dangling-resolutions guard test): removal proceeds, replaying
        // nothing.
        tokio::fs::write(fx.lock_path(), &fx.lock_bytes)
            .await
            .unwrap();
        tokio::fs::write(fx.pkg_path(), &fx.pkg_bytes).await.unwrap();
        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(!fx.tgz_path().exists(), "orphaned artifact removed");
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes,
            "empty wiring replays nothing"
        );

        // No lock and no resolutions reference: nothing can reference the
        // artifact — proceed.
        let fx = fixture().await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let mut entry = entry.unwrap();
        entry.wiring.clear();
        tokio::fs::remove_file(fx.lock_path()).await.unwrap();
        tokio::fs::write(fx.pkg_path(), &fx.pkg_bytes).await.unwrap();
        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(!fx.tgz_path().exists(), "no lock, no reference");
    }

    /// A re-install or hand edit can copy our `file:` entry to a lock key
    /// the wiring never recorded. The recorded fragments then restore
    /// cleanly, but yarn still resolves through the artifact — deleting the
    /// uuid dir would fail every subsequent install on the missing tarball,
    /// silently. Must refuse, fail-closed (twin of npm_lock's post-restore
    /// probe).
    #[tokio::test]
    async fn revert_refuses_when_an_unrecorded_lock_entry_still_resolves_through_the_artifact() {
        let fx = fixture().await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();

        // Duplicate the vendored entry under a key the wiring never recorded.
        let text = tokio::fs::read_to_string(fx.lock_path()).await.unwrap();
        let resolution = text
            .lines()
            .find(|l| l.starts_with("  resolution: \"left-pad@file:"))
            .expect("the vendored lock must carry our resolution line");
        let copied = format!(
            "\n\"left-pad@npm:^1.3.0\":\n  version: 1.3.0\n{resolution}\n  languageName: node\n  linkType: hard\n"
        );
        tokio::fs::write(fx.lock_path(), format!("{text}{copied}"))
            .await
            .unwrap();

        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(
            !outcome.success,
            "must refuse while an unrecorded entry still resolves through the artifact: {:?}",
            outcome.warnings
        );
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_still_wired_revert_blocked"),
            "{:?}",
            outcome.warnings
        );
        assert!(
            fx.tgz_path().exists(),
            "the artifact must survive the refusal"
        );
    }

    /// The user re-keys our resolutions entry (`"left-pad"` →
    /// `"left-pad@npm:1.3.0"`) without changing its `file:` value. The
    /// recorded key then reads as already-converged (Added record, key
    /// absent) and the lock restores cleanly — but package.json still
    /// resolves through the artifact; removing it would make every
    /// `yarn install` fail on the missing tarball. Must refuse, fail-closed.
    #[tokio::test]
    async fn revert_refuses_when_a_rekeyed_resolutions_entry_still_references_the_artifact() {
        let fx = fixture().await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();

        let pkg_text = tokio::fs::read_to_string(fx.pkg_path()).await.unwrap();
        let rekeyed = pkg_text.replace("\"left-pad\": \"file:", "\"left-pad@npm:1.3.0\": \"file:");
        assert_ne!(rekeyed, pkg_text, "the re-key edit must hit");
        tokio::fs::write(fx.pkg_path(), &rekeyed).await.unwrap();

        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(
            !outcome.success,
            "must refuse while a re-keyed resolutions entry still references the artifact: {:?}",
            outcome.warnings
        );
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_still_wired_revert_blocked"),
            "{:?}",
            outcome.warnings
        );
        assert!(
            fx.tgz_path().exists(),
            "the artifact must survive the refusal"
        );
    }

    /// Empty-wiring (repair-reconstructed) entries: yarn resolves through
    /// package.json's resolutions value too, not just the lock — reverting
    /// while the resolutions entry still names the uuid dir would leave a
    /// dangling `file:` spec that fails every subsequent install. Must
    /// refuse even when yarn.lock provably no longer references the
    /// artifact.
    #[tokio::test]
    async fn empty_wiring_revert_refuses_while_resolutions_still_references_the_artifact() {
        let fx = fixture().await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let mut entry = entry.unwrap();
        entry.wiring.clear();
        // Lock re-resolved away from the artifact; package.json untouched
        // (its resolutions entry still points into the uuid dir).
        tokio::fs::write(fx.lock_path(), &fx.lock_bytes)
            .await
            .unwrap();

        for dry_run in [true, false] {
            let outcome = revert_yarn_berry(&entry, fx.root(), dry_run).await;
            assert!(!outcome.success, "dry_run={dry_run}: must refuse");
            assert!(
                outcome
                    .warnings
                    .iter()
                    .any(|w| w.code == "vendor_wiring_unknown_revert_blocked"),
                "{:?}",
                outcome.warnings
            );
            assert!(fx.tgz_path().exists(), "artifact survives the refusal");
        }
    }

    /// Chmod `path` to `mode`, restoring 0o755 on drop so TempDir cleanup
    /// (and a panicking assert mid-test) never leaves an undeletable tree.
    #[cfg(unix)]
    struct ModeGuard(PathBuf);

    #[cfg(unix)]
    impl ModeGuard {
        fn set(path: &Path, mode: u32) -> Self {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
            Self(path.to_path_buf())
        }
    }

    #[cfg(unix)]
    impl Drop for ModeGuard {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
        }
    }

    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c_path =
            std::ffi::CString::new(path.as_os_str().as_bytes()).expect("fifo path has no NUL");
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
        assert_eq!(
            rc,
            0,
            "mkfifo(2) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    /// A FIFO planted as any of the three files this backend reads must
    /// fail fast instead of wedging vendor or revert forever in an
    /// `open(2)` waiting for a writer that never comes. Same
    /// `open_regular_file` guard class as the vendor siblings (npm_lock.rs,
    /// pnpm_lock.rs, lock_inventory.rs).
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_files_fail_fast_instead_of_wedging_vendor_and_revert() {
        // Vendor halves: a FIFO as yarn.lock / .yarnrc.yml / package.json.
        let fx_lock = fixture().await;
        tokio::fs::remove_file(fx_lock.lock_path()).await.unwrap();
        mkfifo(&fx_lock.lock_path());

        let fx_rc = fixture().await;
        tokio::fs::remove_file(fx_rc.root().join(YARNRC))
            .await
            .unwrap();
        mkfifo(&fx_rc.root().join(YARNRC));

        let fx_pkg = fixture().await;
        tokio::fs::remove_file(fx_pkg.pkg_path()).await.unwrap();
        mkfifo(&fx_pkg.pkg_path());

        // Revert halves: vendor normally, then swap each wired file for a
        // FIFO before reverting.
        let fx_rl = fixture().await;
        let (_, entry_rl, _) = expect_done(fx_rl.vendor(false).await);
        let entry_rl = entry_rl.unwrap();
        tokio::fs::remove_file(fx_rl.lock_path()).await.unwrap();
        mkfifo(&fx_rl.lock_path());

        let fx_rp = fixture().await;
        let (_, entry_rp, _) = expect_done(fx_rp.vendor(false).await);
        let entry_rp = entry_rp.unwrap();
        tokio::fs::remove_file(fx_rp.pkg_path()).await.unwrap();
        mkfifo(&fx_rp.pkg_path());

        let deadline = std::time::Duration::from_secs(5);
        let all = async {
            (
                fx_lock.vendor(false).await,
                fx_rc.vendor(false).await,
                fx_pkg.vendor(false).await,
                revert_yarn_berry(&entry_rl, fx_rl.root(), false).await,
                revert_yarn_berry(&entry_rp, fx_rp.root(), false).await,
            )
        };
        let Ok((v_lock, v_rc, v_pkg, r_lock, r_pkg)) = tokio::time::timeout(deadline, all).await
        else {
            // On timeout the open is wedged in a `spawn_blocking` thread the
            // runtime waits for on shutdown; connect a non-blocking writer
            // to release it so the test can FAIL instead of hanging the
            // suite.
            use std::os::unix::fs::OpenOptionsExt;
            for path in [
                fx_lock.lock_path(),
                fx_rc.root().join(YARNRC),
                fx_pkg.pkg_path(),
                fx_rl.lock_path(),
                fx_rp.pkg_path(),
            ] {
                let _ = std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(path);
            }
            panic!("yarn-berry file reads must fail fast on FIFOs");
        };
        let detail = expect_refused(v_lock, "vendor_lockfile_missing");
        assert!(detail.contains("cannot read"), "{detail}");
        let detail = expect_refused(v_rc, "vendor_yarn_berry_cache_unsupported");
        assert!(detail.contains("cannot read"), "{detail}");
        expect_refused(v_pkg, "vendor_yarn_berry_manifest_unreadable");
        assert!(
            !r_lock.success,
            "revert must fail closed on an unreadable lock: {:?}",
            r_lock.warnings
        );
        assert!(
            fx_rl.tgz_path().exists(),
            "the artifact must survive the failed revert"
        );
        assert!(
            !r_pkg.success,
            "revert must fail closed on an unreadable package.json: {:?}",
            r_pkg.warnings
        );
        assert!(
            fx_rp.tgz_path().exists(),
            "the artifact must survive the failed revert"
        );
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

    /// Every remaining pre-write gate refuses BEFORE any project write:
    /// malformed coordinates, a non-berry lock (no `__metadata:`), a lock
    /// with no root `<name>@workspace:.` entry, an unparseable/non-object
    /// package.json, a non-object `resolutions` table, and a bundled-deps
    /// package (the shared pipeline's refusal bubbling verbatim).
    #[tokio::test]
    async fn pre_write_gates_refuse_and_leave_the_project_untouched() {
        // Coordinates guard: a non-npm purl never reaches the disk.
        let fx = fixture().await;
        let blobs = fx.root().join(".socket/blobs");
        let sources = PatchSources::blobs_only(&blobs);
        let outcome = vendor_yarn_berry(
            "pkg:gem/left-pad@1.3.0",
            &fx.installed(),
            fx.root(),
            &fx.record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            None,
        )
        .await;
        let detail = expect_refused(outcome, "unsafe_coordinates");
        assert!(detail.contains("pkg:gem/left-pad@1.3.0"), "{detail}");
        fx.assert_untouched().await;

        // No `__metadata:` block: not a yarn berry lockfile.
        let lock = B3_BEFORE_LOCK.replace("__metadata:\n  version: 8\n  cacheKey: 10c0\n\n", "");
        assert_ne!(lock, B3_BEFORE_LOCK, "the fixture edit must hit");
        let fx = fixture_with(B3_BEFORE_PKG, &lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lockfile_version_unsupported");
        assert!(detail.contains("__metadata"), "{detail}");
        fx.assert_untouched().await;

        // No root `<name>@workspace:.` entry: the locator cannot be built.
        let lock = B3_BEFORE_LOCK
            .replace("vendor-spike@workspace:.", "vendor-spike@workspace:packages/a");
        assert_ne!(lock, B3_BEFORE_LOCK, "the fixture edit must hit");
        let fx = fixture_with(B3_BEFORE_PKG, &lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lockfile_version_unsupported");
        assert!(detail.contains("@workspace:."), "{detail}");
        fx.assert_untouched().await;

        // Unparseable package.json.
        let fx = fixture_with("{\"name\":", B3_BEFORE_LOCK).await;
        let detail = expect_refused(
            fx.vendor(false).await,
            "vendor_yarn_berry_manifest_unreadable",
        );
        assert!(detail.contains("not parseable"), "{detail}");
        fx.assert_untouched().await;

        // Parseable but non-object root.
        let fx = fixture_with("[]", B3_BEFORE_LOCK).await;
        let detail = expect_refused(
            fx.vendor(false).await,
            "vendor_yarn_berry_manifest_unreadable",
        );
        assert!(detail.contains("root is not an object"), "{detail}");
        fx.assert_untouched().await;

        // `resolutions` present but not an object.
        let pkg = B3_BEFORE_PKG.replace("  }\n}", "  },\n  \"resolutions\": \"nope\"\n}");
        assert_ne!(pkg, B3_BEFORE_PKG, "the fixture edit must hit");
        let fx = fixture_with(&pkg, B3_BEFORE_LOCK).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_override_conflict");
        assert!(detail.contains("is not an object"), "{detail}");
        fx.assert_untouched().await;

        // Bundled dependencies: stage_patch_pack's refusal bubbles verbatim
        // before anything inside the project is written.
        let fx = fixture().await;
        tokio::fs::write(
            fx.installed().join("package.json"),
            br#"{"name":"left-pad","version":"1.3.0","bundledDependencies":["x"]}"#,
        )
        .await
        .unwrap();
        let detail = expect_refused(fx.vendor(false).await, "vendor_bundled_deps_unsupported");
        assert!(detail.contains("bundleDependencies"), "{detail}");
        fx.assert_untouched().await;
    }

    /// An unrelated resolutions entry is skipped by the conflict scan and
    /// carried into the rewritten table alongside our new spec.
    #[tokio::test]
    async fn unrelated_resolutions_entry_is_kept_alongside_ours() {
        let pkg = B3_BEFORE_PKG.replace(
            "  }\n}",
            "  },\n  \"resolutions\": {\n    \"is-odd\": \"1.0.0\"\n  }\n}",
        );
        assert_ne!(pkg, B3_BEFORE_PKG, "the fixture edit must hit");
        let fx = fixture_with(&pkg, B3_BEFORE_LOCK).await;

        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());

        let pkg: Value =
            serde_json::from_slice(&tokio::fs::read(fx.pkg_path()).await.unwrap()).unwrap();
        assert_eq!(
            pkg["resolutions"]["is-odd"],
            json!("1.0.0"),
            "unrelated entry kept"
        );
        assert_eq!(
            pkg["resolutions"]["left-pad"],
            json!(format!(
                "file:./.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"
            )),
            "our spec added beside it"
        );
    }

    /// Lock-scan shape guards: a key with no parseable `name@range`
    /// descriptor is skipped (not ours to touch), a multi-pattern key mixing
    /// the target name with another name refuses, and two entries resolving
    /// the same name@version refuse as ambiguous.
    #[tokio::test]
    async fn lock_scan_skips_unparseable_keys_and_refuses_ambiguous_targets() {
        // Unparseable key: skipped, vendor proceeds, block byte-untouched.
        const WEIRD_BLOCK: &str = "\"weird\":\n  version: 9.9.9\n  resolution: \"weird@npm:9.9.9\"\n  checksum: 10c0/aa\n  languageName: node\n  linkType: hard\n";
        let lock = format!("{B3_BEFORE_LOCK}\n{WEIRD_BLOCK}");
        let fx = fixture_with(B3_BEFORE_PKG, &lock).await;
        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());
        let text = tokio::fs::read_to_string(fx.lock_path()).await.unwrap();
        assert!(
            text.contains(WEIRD_BLOCK),
            "unparseable block byte-untouched: {text}"
        );
        assert!(text.contains("left-pad@file:./"), "target still rewired");

        // A key mixing the target name with another descriptor's name
        // (per-pattern quoting — a comma inside ONE quoted key is a single
        // pattern and takes the plain-candidate path instead).
        let lock = B3_BEFORE_LOCK.replace(
            "\"left-pad@npm:1.3.0\":",
            "\"left-pad@npm:1.3.0\", \"is-odd@npm:1.0.0\":",
        );
        assert_ne!(lock, B3_BEFORE_LOCK, "the fixture edit must hit");
        let fx = fixture_with(B3_BEFORE_PKG, &lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_override_conflict");
        assert!(detail.contains("mixes"), "{detail}");
        fx.assert_untouched().await;

        // Two entries resolving the SAME name@version: ambiguous rewrite.
        let lock = format!(
            "{B3_BEFORE_LOCK}\n\"left-pad@npm:^1.3.0\":\n  version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n  checksum: 10c0/aa\n  languageName: node\n  linkType: hard\n"
        );
        let fx = fixture_with(B3_BEFORE_PKG, &lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_override_conflict");
        assert!(detail.contains("multiple yarn.lock entries"), "{detail}");
        fx.assert_untouched().await;
    }

    /// Revert tolerates a deleted wired file (warn + restore the rest +
    /// prune the artifact) but fails CLOSED on a corrupt package.json —
    /// after the lock restore already ran (the partial-restore contract).
    #[tokio::test]
    async fn revert_tolerates_missing_wired_files_and_fails_closed_on_corrupt_manifest() {
        // yarn.lock deleted: warn, restore package.json, prune the artifact.
        let fx = fixture().await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        tokio::fs::remove_file(fx.lock_path()).await.unwrap();
        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        let warning = outcome
            .warnings
            .iter()
            .find(|w| w.code == "vendor_lockfile_missing")
            .unwrap_or_else(|| panic!("expected the missing-lock warning: {:?}", outcome.warnings));
        assert!(warning.detail.contains(YARN_LOCK), "{}", warning.detail);
        assert_eq!(
            tokio::fs::read(fx.pkg_path()).await.unwrap(),
            fx.pkg_bytes,
            "package.json still restored"
        );
        assert!(
            !fx.tgz_path().exists(),
            "artifact pruned despite the missing lock"
        );

        // package.json deleted: warn, restore yarn.lock, prune the artifact.
        let fx = fixture().await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        tokio::fs::remove_file(fx.pkg_path()).await.unwrap();
        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        let warning = outcome
            .warnings
            .iter()
            .find(|w| w.code == "vendor_lockfile_missing")
            .unwrap_or_else(|| {
                panic!("expected the missing-manifest warning: {:?}", outcome.warnings)
            });
        assert!(warning.detail.contains(PACKAGE_JSON), "{}", warning.detail);
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes,
            "yarn.lock still restored"
        );
        assert!(
            !fx.tgz_path().exists(),
            "artifact pruned despite the missing manifest"
        );
        assert!(
            !fx.pkg_path().exists(),
            "the missing manifest is not resurrected"
        );

        // Corrupt package.json: fail closed AFTER the lock restore ran.
        let fx = fixture().await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        tokio::fs::write(fx.pkg_path(), b"{bad").await.unwrap();
        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(!outcome.success, "corrupt manifest must fail the revert");
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or("")
                .contains("not parseable JSON"),
            "{:?}",
            outcome.error
        );
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes,
            "the lock restore already ran when the manifest failed (partial restore)"
        );
        assert!(
            fx.tgz_path().exists(),
            "artifact survives the failed revert"
        );
    }

    /// Write failures fail closed on unix: a read-only project root makes
    /// the vendor commit fail (unwinding the staged uuid dir) and the revert
    /// writes fail; a read-only `.socket/vendor/npm` makes the artifact
    /// removal fail — and a re-run converges once the permission is fixed.
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_write_failures_fail_closed_and_unstage() {
        if unsafe { libc::geteuid() } == 0 {
            return; // chmod is advisory for root — the failures never fire
        }

        // Vendor: commit_pair's package.json temp-write fails on the
        // read-only root (node_modules and .socket stay writable, so
        // staging + packing succeed); the fresh uuid dir is unwound.
        let fx = fixture().await;
        let guard = ModeGuard::set(fx.root(), 0o555);
        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(!result.success, "a read-only root must fail the commit");
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or("")
                .contains("cannot write package.json"),
            "{:?}",
            result.error
        );
        assert!(entry.is_none());
        fx.assert_untouched().await;
        drop(guard);

        // Revert: the yarn.lock restore write fails first.
        let fx = fixture().await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let guard = ModeGuard::set(fx.root(), 0o555);
        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(!outcome.success, "read-only root must fail the lock write");
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or("")
                .contains("cannot write yarn.lock"),
            "{:?}",
            outcome.error
        );
        assert!(
            fx.tgz_path().exists(),
            "the artifact must survive the failed revert"
        );
        drop(guard);

        // Revert with the lock hand-restored (converged — no lock write
        // happens): the package.json restore write fails instead.
        let fx = fixture().await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        tokio::fs::write(fx.lock_path(), &fx.lock_bytes)
            .await
            .unwrap();
        let guard = ModeGuard::set(fx.root(), 0o555);
        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(!outcome.success, "read-only root must fail the pkg write");
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or("")
                .contains("cannot write package.json"),
            "{:?}",
            outcome.error
        );
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes,
            "the converged lock is never rewritten"
        );
        assert!(fx.tgz_path().exists());
        drop(guard);

        // Revert with a read-only .socket/vendor/npm: the wiring restores,
        // the removal fails — and a re-run converges once perms are fixed.
        let fx = fixture().await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let guard = ModeGuard::set(&fx.root().join(".socket/vendor/npm"), 0o555);
        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(!outcome.success, "a read-only parent must fail the removal");
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or("")
                .contains("cannot remove"),
            "{:?}",
            outcome.error
        );
        assert_eq!(
            tokio::fs::read(fx.pkg_path()).await.unwrap(),
            fx.pkg_bytes,
            "the wiring restore ran before the failed removal"
        );
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes
        );
        drop(guard);
        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome.warnings.is_empty(),
            "the converged re-run is silent: {:?}",
            outcome.warnings
        );
        assert!(
            !fx.root().join(format!(".socket/vendor/npm/{UUID}")).exists(),
            "the re-run converges and removes the uuid dir"
        );
    }

    /// Poisoned state.json wiring records are left alone with a drift
    /// warning: a record with no key, an unknown kind, and a non-object
    /// package.json root each warn without touching anything.
    #[test]
    fn revert_resolution_record_leaves_poisoned_records_alone() {
        let rec = |kind: &str, key: Option<&str>| WiringRecord {
            file: PACKAGE_JSON.to_string(),
            kind: kind.to_string(),
            action: WiringAction::Added,
            key: key.map(str::to_string),
            original: None,
            new: Some(json!("file:./x")),
        };
        let pristine = json!({"resolutions": {"left-pad": "file:./x"}});

        // No key.
        let mut pkg = pristine.clone();
        let mut changed = false;
        let mut warnings = Vec::new();
        revert_resolution_record(
            &mut pkg,
            &rec(KIND_RESOLUTION, None),
            UUID,
            &mut changed,
            &mut warnings,
        );
        assert!(!changed);
        assert_eq!(pkg, pristine, "left alone");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert_eq!(warnings[0].code, "vendor_lock_entry_drifted");
        assert!(
            warnings[0].detail.contains("has no key"),
            "{}",
            warnings[0].detail
        );

        // Unknown kind.
        let mut pkg = pristine.clone();
        let mut changed = false;
        let mut warnings = Vec::new();
        revert_resolution_record(
            &mut pkg,
            &rec("bogus", Some("left-pad")),
            UUID,
            &mut changed,
            &mut warnings,
        );
        assert!(!changed);
        assert_eq!(pkg, pristine, "left alone");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].detail.contains("unknown wiring kind `bogus`"),
            "{}",
            warnings[0].detail
        );

        // Non-object package.json root.
        let mut pkg = json!([1]);
        let mut changed = false;
        let mut warnings = Vec::new();
        revert_resolution_record(
            &mut pkg,
            &rec(KIND_RESOLUTION, Some("left-pad")),
            UUID,
            &mut changed,
            &mut warnings,
        );
        assert!(!changed);
        assert_eq!(pkg, json!([1]), "left alone");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].detail.contains("root is not an object"),
            "{}",
            warnings[0].detail
        );
    }

    /// Takeover records (a user pin recorded as `original`) whose
    /// resolutions table or key was removed by the user warn + keep the
    /// artifact; a hand-restored pin reads as CONVERGED — silent, artifact
    /// pruned (the drift-keep liveness contract).
    #[tokio::test]
    async fn takeover_drift_warns_and_keeps_while_a_restored_pin_converges_silently() {
        let pkg_before = B3_BEFORE_PKG.replace(
            "  }\n}",
            "  },\n  \"resolutions\": {\n    \"left-pad\": \"1.3.0\"\n  }\n}",
        );

        // The whole resolutions table was removed since vendoring.
        let fx = fixture_with(&pkg_before, B3_BEFORE_LOCK).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        tokio::fs::write(fx.pkg_path(), B3_BEFORE_PKG).await.unwrap();
        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome.warnings.iter().any(
                |w| w.code == "vendor_lock_entry_drifted" && w.detail.contains("no longer exists")
            ),
            "{:?}",
            outcome.warnings
        );
        assert!(outcome.kept_artifact, "drift-skip keeps the artifact");
        assert!(fx.tgz_path().exists());
        let pkg: Value =
            serde_json::from_slice(&tokio::fs::read(fx.pkg_path()).await.unwrap()).unwrap();
        assert!(
            pkg.get("resolutions").is_none(),
            "the recorded pin is NOT resurrected"
        );
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes,
            "the lock restore still ran (independent fragment)"
        );

        // The table is present but our key was removed by the user.
        let fx = fixture_with(&pkg_before, B3_BEFORE_LOCK).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let mut pkg: Value =
            serde_json::from_slice(&tokio::fs::read(fx.pkg_path()).await.unwrap()).unwrap();
        pkg["resolutions"] = json!({"is-odd": "1.0.0"});
        tokio::fs::write(fx.pkg_path(), serde_json::to_vec_pretty(&pkg).unwrap())
            .await
            .unwrap();
        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome.warnings.iter().any(
                |w| w.code == "vendor_lock_entry_drifted" && w.detail.contains("no longer exists")
            ),
            "{:?}",
            outcome.warnings
        );
        assert!(outcome.kept_artifact && fx.tgz_path().exists());
        let after: Value =
            serde_json::from_slice(&tokio::fs::read(fx.pkg_path()).await.unwrap()).unwrap();
        assert_eq!(
            after["resolutions"],
            json!({"is-odd": "1.0.0"}),
            "the user's table is left alone"
        );

        // The pin was hand-restored: converged, silent, artifact pruned.
        let fx = fixture_with(&pkg_before, B3_BEFORE_LOCK).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let text = tokio::fs::read_to_string(fx.pkg_path()).await.unwrap();
        let healed = text.replace(
            &format!("file:./.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"),
            "1.3.0",
        );
        assert_ne!(healed, text, "the hand-restore edit must hit");
        tokio::fs::write(fx.pkg_path(), &healed).await.unwrap();
        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome.warnings.is_empty(),
            "a converged pin is silent: {:?}",
            outcome.warnings
        );
        assert!(!outcome.kept_artifact);
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes,
            "lock restored byte-for-byte"
        );
        assert!(!fx.tgz_path().exists(), "artifact pruned once converged");
        let after: Value =
            serde_json::from_slice(&tokio::fs::read(fx.pkg_path()).await.unwrap()).unwrap();
        assert_eq!(
            after["resolutions"]["left-pad"],
            json!("1.3.0"),
            "the hand-restored pin stays"
        );
    }

    /// `--preserve-state` (`keep_artifact`): the wiring restore runs, the
    /// artifact dir (tarball + marker) stays, `kept_artifact` stays false
    /// (reserved for drift-keeps) — and a later plain revert converges
    /// silently and prunes the artifact.
    #[tokio::test]
    async fn preserve_state_revert_restores_wiring_but_keeps_the_artifact() {
        let fx = fixture().await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();

        let outcome = revert_yarn_berry_opts(
            &entry,
            fx.root(),
            RevertOpts {
                dry_run: false,
                keep_artifact: true,
            },
        )
        .await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert!(!outcome.kept_artifact, "reserved for drift-keeps");
        assert_eq!(
            tokio::fs::read(fx.pkg_path()).await.unwrap(),
            fx.pkg_bytes,
            "the wiring restore ran"
        );
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes
        );
        assert!(fx.tgz_path().exists(), "artifact kept");
        assert!(
            fx.root()
                .join(format!(
                    ".socket/vendor/npm/{UUID}/socket-patch.vendor.json"
                ))
                .exists(),
            "marker kept"
        );

        // A later plain revert converges silently and prunes the artifact.
        let outcome = revert_yarn_berry(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome.warnings.is_empty(),
            "converged records are silent: {:?}",
            outcome.warnings
        );
        assert!(!fx
            .root()
            .join(format!(".socket/vendor/npm/{UUID}"))
            .exists());
    }

    /// A failed vendor-marker write is a warning, never a failure: the
    /// marker is informational and the pair wiring must stand.
    #[tokio::test]
    async fn marker_write_failure_is_a_warning_not_a_failure() {
        let fx = fixture().await;
        // Staging only create_dir_all's the uuid dir (never wipes it), so a
        // DIRECTORY planted at the marker path survives staging and fails
        // the marker's atomic rename.
        let marker_path = fx.root().join(format!(
            ".socket/vendor/npm/{UUID}/socket-patch.vendor.json"
        ));
        tokio::fs::create_dir_all(&marker_path).await.unwrap();

        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some(), "the wiring stands");
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_marker_write_failed"),
            "{warnings:?}"
        );

        // Both files were still wired normally (the B3 oracles hold).
        assert_eq!(
            tokio::fs::read_to_string(fx.pkg_path()).await.unwrap(),
            B3_AFTER_PKG
        );
        let (hash6, checksum) = fx.packed_berry_facts().await;
        assert_eq!(
            tokio::fs::read_to_string(fx.lock_path()).await.unwrap(),
            spike_after_lock(&hash6, &checksum)
        );
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

        // A `resolutions:` line must not satisfy a `resolution` field read:
        // the prefix match leaves a leading `s`, and the `:` gate skips it.
        let collide: Vec<String> = ["\"k\":", "  resolutions: nope", "  resolution: \"y\""]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(berry_field(&collide, "resolution"), Some("y"));
        assert_eq!(berry_field(&collide, "resolutions"), Some("nope"));

        // A body line that is neither a field line nor preceded by a section
        // header is carried verbatim (the owned scalar still drops).
        let orphan: Vec<String> = ["\"k\":", "    orphan-submap-line", "  version: 1.3.0"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            carried_sections(&orphan),
            vec!["    orphan-submap-line".to_string()]
        );
    }
}
