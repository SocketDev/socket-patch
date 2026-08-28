//! pnpm vendor backend: `package.json` + `pnpm-workspace.yaml` +
//! `pnpm-lock.yaml` surgery.
//!
//! pnpm cross-checks the overrides it reads from config against the
//! lockfile's own `overrides:` section, so a lock-only edit is unsound:
//! `--frozen-lockfile` fails with `ERR_PNPM_LOCKFILE_CONFIG_MISMATCH` and a
//! plain `pnpm install` silently strips the section and reinstalls the
//! unpatched registry bytes (spike P3, `spikes/PHASE0-V2-FINDINGS.txt`).
//!
//! WHERE pnpm reads overrides moved between majors: pnpm <= 10 reads
//! package.json `pnpm.overrides`; pnpm >= 11 no longer reads the package.json
//! `pnpm` field at all and reads `overrides:` from `pnpm-workspace.yaml`
//! instead (https://pnpm.io/settings). Vendoring writes the override to BOTH
//! surfaces (identical `<name>@<version>` → `file:` value) so the committable
//! artifact installs cleanly on pnpm 9/10/11 without a lockfile/config
//! mismatch: the versioned selector (`<name>@<version>` — only that exact
//! version moves, spike P6) points at the vendored tarball. When the project
//! has no `pnpm-workspace.yaml`, one is created carrying a root-only
//! `packages:` list (pnpm 9 refuses a workspace file with no `packages`
//! field) plus the `overrides:` block; `vendor --revert` deletes it again.
//! The lock still gets the four fragments pnpm itself would emit. The surgery
//! is a faithful port of
//! `spikes/pnpm/edit_lock.py`, whose output was verified byte-identical to
//! pnpm's own lock on BOTH supported majors (9.15.9 / 10.34.1 — they emit
//! byte-identical `lockfileVersion: '9.0'` locks; fixtures in `spikes/pnpm/`):
//!
//! 1. `overrides:` section — inserted before `importers:` or extended;
//! 2. every importer's dep entry — `specifier:` AND `version:` rewritten to
//!    the `file:` spec, the specifier re-relativized PER IMPORTER
//!    (`file:../../.socket/...` for `packages/app`; spike P7) while
//!    `version:` and the packages/snapshots keys stay lockfile-root-relative;
//! 3. the `packages:` entry — rekeyed `name@version` → `name@file:<rel-tgz>`
//!    with `resolution: {integrity: sha512-<ours>, tarball: file:<rel-tgz>}`
//!    (the recomputed tarball hash — pnpm enforces it even offline, spike
//!    P5), a new `version: X.Y.Z` line, and any `deprecated:` line dropped;
//! 4. `snapshots:` — the entry rekeyed the same way and every other
//!    snapshot's dep reference rewritten to the bare `name: file:<rel-tgz>`
//!    form (no `name@` prefix).
//!
//! The lock is machine-emitted YAML, edited by LINE-BLOCK SPLICES (never a
//! YAML library): untouched lines stay byte-identical, which is what makes
//! the lock byte-stable under pnpm's own re-serialization (spike P2).
//! package.json is written FIRST and the lock second; a lock write failure
//! unwinds package.json to its original bytes so the P3 desync pair is
//! never left behind.

use std::path::Path;

use serde_json::Value;

use crate::manifest::schema::PatchRecord;
use crate::patch::apply::PatchSources;
use crate::patch::copy_tree::remove_tree;
use crate::utils::fs::atomic_write_bytes_preserving_mode;

use super::common::{already_patched_result, detect_indent, done, refused, serialize_json};
use super::npm_common::{
    done_failure, guard_coordinates, guard_revert_uuid_dir, stage_patch_pack, tgz_rel_leaf,
};
use super::path::parse_vendor_path;
use super::state::{
    write_marker, PnpmMeta, VendorArtifact, VendorEntry, VendorMarker, WiringAction, WiringRecord,
};
use super::{RevertOpts, RevertOutcome, VendorOutcome, VendorWarning};

const PACKAGE_JSON: &str = "package.json";
const PNPM_LOCK: &str = "pnpm-lock.yaml";
const PNPM_WORKSPACE: &str = "pnpm-workspace.yaml";

/// The root-only workspace member list written into a freshly created
/// `pnpm-workspace.yaml`. pnpm 9 refuses a workspace file whose `packages`
/// field is missing or empty; `.` (the root, already the sole importer) is a
/// no-op that cannot accidentally glob a stray `packages/` subtree into a
/// workspace the way `packages/*` would.
const WS_SCAFFOLD_PACKAGES: [&str; 2] = ["packages:", "  - '.'"];

/// The only lockfileVersion the surgery has byte-exact fixtures for (both
/// pnpm 9 and 10 emit it).
const SUPPORTED_LOCK_VERSION: &str = "9.0";

/// Wiring kinds (the `WiringRecord.kind` discriminators this backend owns).
pub(super) const KIND_PKG_OVERRIDE: &str = "pnpm_pkg_override";
const KIND_WS_OVERRIDE: &str = "pnpm_ws_override";
pub(super) const KIND_LOCK_OVERRIDES: &str = "pnpm_lock_overrides";
const KIND_LOCK_IMPORTER_DEP: &str = "pnpm_lock_importer_dep";
const KIND_LOCK_PACKAGE: &str = "pnpm_lock_package";
const KIND_LOCK_SNAPSHOT: &str = "pnpm_lock_snapshot";
const KIND_LOCK_SNAPSHOT_REF: &str = "pnpm_lock_snapshot_ref";

/// SECURITY: revert writes are restricted to exactly the pair vendor edits —
/// a poisoned state.json must not be able to point the rewrite at an
/// arbitrary project file. Records naming anything else are skipped with a
/// warning (fail-closed).
const REVERT_ALLOWLIST: [&str; 3] = [PNPM_LOCK, PACKAGE_JSON, PNPM_WORKSPACE];

/// Vendor one installed npm package into a pnpm project (see the module doc
/// for the wiring shape). Same contract as `npm_lock::vendor_npm`:
/// refuse-early / wire-last, `entry` present iff `result.success` and not a
/// dry run, and an in-sync re-run synthesizes AlreadyPatched with no entry.
#[allow(clippy::too_many_arguments)]
pub async fn vendor_pnpm(
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

    // ── 1. Coordinates (shared fail-closed guard) ─────────────────────────
    let coords = match guard_coordinates(purl, record) {
        Ok(coords) => coords,
        Err(outcome) => return *outcome,
    };
    let (name, version) = (coords.name.as_str(), coords.version.as_str());
    let rel_tgz = format!("{}/{}", coords.uuid_dir_rel, tgz_rel_leaf(name, version));
    // pnpm spells the override target `file:<root-relative path>` with NO
    // `./` (spike P1 fixtures, verbatim).
    let spec = format!("file:{rel_tgz}");
    let override_key = format!("{name}@{version}");

    // ── 2. Read the pair (refuse before any write) ───────────────────────
    let pkg_bytes = match read_regular(&project_root.join(PACKAGE_JSON)).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return refused(
                "vendor_lockfile_missing",
                format!(
                    "cannot read {PACKAGE_JSON}: {e} — the pnpm wiring edits the \
                     package.json + pnpm-lock.yaml PAIR (a lock-only edit silently \
                     unpatches on the next plain `pnpm install`)"
                ),
            );
        }
    };
    let mut pkg: Value = match serde_json::from_slice(&pkg_bytes) {
        Ok(Value::Object(map)) => Value::Object(map),
        Ok(_) | Err(_) => {
            return refused(
                "vendor_pkg_json_unsupported",
                format!("{PACKAGE_JSON} is not a JSON object; cannot add pnpm.overrides"),
            );
        }
    };
    let lock_text = match read_regular_string(&project_root.join(PNPM_LOCK)).await {
        Ok(text) => text,
        Err(e) => {
            return refused(
                "vendor_lockfile_missing",
                format!("cannot read {PNPM_LOCK}: {e} — run `pnpm install` first"),
            );
        }
    };
    if let Err(detail) = check_lock_version(&lock_text) {
        return refused("vendor_lockfile_version_unsupported", detail);
    }
    // CRLF line endings (Windows autocrlf checkouts) break every structural
    // probe below — `split_lines` keeps the trailing `\r`, so section headers
    // like `packages:` never match — which would otherwise surface as a
    // misleading "no packages entry … run `pnpm install`" refusal. pnpm
    // itself tolerates CRLF, so name the real cause and fail closed before
    // any probe runs.
    if lock_text.contains('\r') {
        return refused(
            "vendor_lockfile_crlf_unsupported",
            format!(
                "{PNPM_LOCK} has CRLF line endings, which this rewriter cannot edit \
                 byte-faithfully — normalize the file to LF (re-run `pnpm install`, \
                 or add `pnpm-lock.yaml text eol=lf` to .gitattributes and re-checkout) \
                 and retry"
            ),
        );
    }
    let mut lines = split_lines(&lock_text);
    // `pnpm-workspace.yaml` is optional (single-package projects have none);
    // its `overrides:` is where pnpm >= 11 reads them. ONLY a missing file
    // counts as "no file": an existing one we cannot read (non-UTF-8
    // encoding, permissions, a FIFO) must refuse — treating it as absent
    // would route into the create path, which OVERWRITES the user's
    // workspace definition with the root-only scaffold.
    let ws_text: Option<String> =
        match read_regular_string(&project_root.join(PNPM_WORKSPACE)).await {
            Ok(text) => Some(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                return refused(
                    "vendor_lockfile_missing",
                    format!(
                        "cannot read {PNPM_WORKSPACE}: {e} — vendoring mirrors the override \
                         into it (pnpm >= 11 reads overrides from pnpm-workspace.yaml); fix \
                         the file and retry"
                    ),
                );
            }
        };
    // Same CRLF posture as the lock above: the workspace splices match exact
    // LF lines, so a CRLF file dodges the conflict checks and the edit
    // appends a DUPLICATE `overrides:` section — a duplicated mapping key
    // pnpm refuses to parse. Fail closed naming the real cause.
    if ws_text.as_deref().is_some_and(|t| t.contains('\r')) {
        return refused(
            "vendor_lockfile_crlf_unsupported",
            format!(
                "{PNPM_WORKSPACE} has CRLF line endings, which this rewriter cannot edit \
                 byte-faithfully — normalize the file to LF and retry"
            ),
        );
    }

    // ── 3. Pre-flight refusals (override conflicts, entry present) ───────
    // A user-authored exact-version pin equal to `version` is TAKEN OVER
    // (the pin's key is rewritten to our spec on both surfaces and the
    // original value recorded for revert); anything else same-name refuses.
    let disposition = match classify_pkg_override(&pkg, name, version, &override_key) {
        Ok(d) => d,
        Err(detail) => return refused("vendor_override_conflict", detail),
    };
    let effective_key = disposition.effective_key(&override_key).to_string();
    if let Err(detail) = check_lock_override(&lines, name, version, &effective_key) {
        return refused("vendor_override_conflict", detail);
    }
    if let Err(detail) = check_workspace_override(ws_text.as_deref(), name, version, &effective_key)
    {
        return refused("vendor_override_conflict", detail);
    }
    if !lock_has_target_package(&lines, name, version) {
        return refused(
            "vendor_lock_entry_not_found",
            format!(
                "{PNPM_LOCK} has no packages entry for {name}@{version} — make sure the \
                 package is installed and locked (`pnpm install`) before vendoring"
            ),
        );
    }
    if let Err(detail) = check_rewritable_refs(&lines, name, version) {
        return refused("vendor_lock_entry_unsupported", detail);
    }

    // ── 4. Stage → patch → pack (shared flavor-agnostic pipeline) ────────
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
        // Failed patch or dry run: wiring never ran, project byte-untouched.
        return done(result, None, warnings);
    };
    debug_assert_eq!(staged.rel_tgz, rel_tgz);
    let packed = staged.packed;
    if staged.staged_pkg_json.is_some() {
        // pnpm snapshots mirror the package's own dependency maps; the spike
        // has no fixture for a manifest-rewriting patch, so the mirrors are
        // preserved verbatim and the user is told to re-resolve.
        warnings.push(VendorWarning::new(
            "vendor_dep_manifest_stale",
            format!(
                "the patch rewrites {name}@{version}'s package.json; pnpm-lock.yaml's \
                 dependency mirrors were preserved verbatim — if the patch changed \
                 dependency ranges, run `pnpm install` to re-resolve them"
            ),
        ));
    }

    // ── 5. Compute both edits in memory (nothing written yet) ────────────
    let ctx = EditCtx {
        name,
        version,
        rel_tgz: &rel_tgz,
        spec: &spec,
        integrity: &packed.integrity,
        override_key: &effective_key,
    };
    let mut wiring: Vec<WiringRecord> = Vec::new();

    let (pkg_changed, created_pnpm_table, created_overrides_table) =
        match apply_pkg_override(&mut pkg, &effective_key, &spec, &mut wiring) {
            Ok(out) => out,
            Err(e) => return done_failure(purl, e),
        };
    let mut lock_changed = false;
    for edit in [
        edit_overrides,
        edit_importers,
        edit_packages,
        edit_snapshot_rekey,
        edit_snapshot_refs,
    ] {
        match edit(&mut lines, &ctx, &mut wiring) {
            Ok(changed) => lock_changed |= changed,
            Err(e) => return done_failure(purl, format!("{PNPM_LOCK} surgery failed: {e}")),
        }
    }

    // The pnpm >= 11 override surface. Mirrors the package.json override
    // key-for-key so whichever surface the installed pnpm reads matches the
    // lock's `overrides:` section.
    let ws_edit =
        match apply_workspace_override(ws_text.as_deref(), &effective_key, &spec, &mut wiring) {
            Ok(edit) => edit,
            Err(e) => return done_failure(purl, format!("{PNPM_WORKSPACE} surgery failed: {e}")),
        };

    if !pkg_changed && !lock_changed && ws_edit.new_text.is_none() {
        // Everything already carries this uuid + the packed integrity: the
        // project is in sync. The tarball re-pack above was byte-identical
        // by determinism; synthesize AlreadyPatched and record nothing (the
        // existing ledger entry stays authoritative).
        return done(
            already_patched_result(purl, &project_root.join(&rel_tgz), &record.files),
            None,
            warnings,
        );
    }

    // ── 6. Commit: package.json + pnpm-workspace.yaml FIRST, lock second,
    //    unwind the override surfaces on a lock failure (P3 desync safety).
    let pkg_indent = detect_indent(&String::from_utf8_lossy(&pkg_bytes));
    let new_pkg_bytes = match serialize_json(&pkg, &pkg_indent) {
        Ok(bytes) => bytes,
        Err(e) => return done_failure(purl, format!("cannot serialize {PACKAGE_JSON}: {e}")),
    };
    let lock_out = lines.join("\n");
    if let Err(e) = commit_surfaces(
        project_root,
        pkg_changed.then_some(new_pkg_bytes.as_slice()),
        &pkg_bytes,
        ws_edit.new_text.as_deref().map(str::as_bytes),
        ws_text.as_deref().map(str::as_bytes),
        ws_edit.created_file,
        lock_changed.then_some(lock_out.as_bytes()),
    )
    .await
    {
        return done_failure(purl, e);
    }

    // ── 7. Marker + ledger entry ─────────────────────────────────────────
    let marker = VendorMarker::new("npm", &coords.base_purl, record, vendored_at);
    if let Err(e) = write_marker(&project_root.join(&coords.uuid_dir_rel), &marker).await {
        warnings.push(VendorWarning::new(
            "vendor_marker_write_failed",
            format!("could not write the informational vendor marker: {e}"),
        ));
    }

    let entry = VendorEntry {
        ecosystem: "npm".to_string(),
        base_purl: coords.base_purl,
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
        flavor: Some("pnpm".to_string()),
        uv: None,
        pnpm: Some(PnpmMeta {
            created_overrides_table,
            created_pnpm_table,
            created_workspace_file: ws_edit.created_file,
            created_workspace_overrides: ws_edit.created_overrides,
        }),
        poetry: None,
        pdm: None,
        pipenv: None,
    };
    done(result, Some(entry), warnings)
}

/// Is this pnpm-vendored entry still consumed by the lock's dependency
/// graph?
///
/// `Some(true)`: a `packages:`/`snapshots:` block resolves to the entry's
/// artifact (`<name>@file:.socket/vendor/npm/<uuid>/...`) — some importer
/// still depends on the package. `Some(false)`: the lock parses cleanly
/// and carries NO such block — the dependency was removed and re-locked
/// (the `overrides:` declaration alone does NOT count as usage: pnpm
/// keeps it mirrored from package.json even when nothing matches it).
/// `None`: cannot determine (missing/unreadable/unsupported lock) —
/// callers must keep the entry, fail-safe.
pub async fn pnpm_entry_in_use(entry: &VendorEntry, project_root: &Path) -> Option<bool> {
    let text = read_regular_string(&project_root.join(PNPM_LOCK))
        .await
        .ok()?;
    if check_lock_version(&text).is_err() {
        return None;
    }
    // CRLF (a Windows autocrlf checkout) breaks every structural probe
    // below: the scan would find nothing and call a lock that still
    // resolves through the artifact "provably orphaned" — undeterminable,
    // keep (the unwired-revert guard then refuses, fail-closed).
    if text.contains('\r') {
        return None;
    }
    let lines = split_lines(&text);
    for section in ["packages", "snapshots"] {
        let Some((start, end)) = section_bounds(&lines, section) else {
            continue;
        };
        let mut i = start + 1;
        while let Some(block) = next_block(&lines, i, end) {
            let resolved_to_ours = block
                .key
                .find("@file:")
                .map(|at| &block.key[at + 1..])
                .and_then(parse_vendor_path)
                .is_some_and(|p| p.eco == "npm" && p.uuid == entry.uuid);
            if resolved_to_ours {
                return Some(true);
            }
            i = block.end;
        }
    }
    Some(false)
}

/// FAIL-CLOSED revert guard for a ledger entry with NO wiring records,
/// shared by both pnpm backends.
///
/// Such entries come out of `repair`'s no-ledger reconstruction (the
/// npm-family pre-vendor lock fragments are not offline-recoverable, so the
/// restored entry carries empty wiring). Revert has nothing to replay for
/// them — it cannot un-wire the lock — so removing the artifact while
/// `pnpm-lock.yaml` still resolves through it bricks every subsequent
/// install (ENOENT on the missing `file:` tarball), and used to do so
/// silently. `in_use` is the calling backend's own lock probe result
/// ([`pnpm_entry_in_use`] / its legacy twin): `Some(true)` refuses;
/// `Some(false)` (provably orphaned) returns `None` and the caller's
/// removal proceeds unchanged; undeterminable (`None`) refuses too UNLESS
/// the lock is absent altogether — a missing lock cannot reference the
/// artifact, matching the wired revert's own missing-lock tolerance.
pub(super) async fn guard_unwired_revert(
    project_root: &Path,
    in_use: Option<bool>,
    uuid_dir_rel: &str,
) -> Option<RevertOutcome> {
    let clause = match in_use {
        Some(false) => return None,
        Some(true) => format!("{PNPM_LOCK} still resolves through it"),
        None => match tokio::fs::try_exists(project_root.join(PNPM_LOCK)).await {
            Ok(false) => return None,
            // Fail-closed: a lock we cannot read or parse may still
            // resolve through the artifact.
            _ => format!(
                "{PNPM_LOCK} exists but could not be parsed to prove it no longer references it"
            ),
        },
    };
    let detail = format!(
        "refusing to remove {uuid_dir_rel}: the ledger entry records no pre-vendor wiring to \
         replay (it was likely reconstructed by `socket-patch repair`; pnpm's pre-vendor lock \
         fragments are not offline-recoverable) and {clause} — deleting the artifact would make \
         every subsequent install fail; run `socket-patch repair` to keep the vendored artifact \
         healthy, and revert by restoring the pre-vendor {PNPM_LOCK}/{PACKAGE_JSON} (or by \
         removing the override and re-locking) before re-running `vendor --revert`"
    );
    Some(RevertOutcome {
        success: false,
        warnings: vec![VendorWarning::new(
            "vendor_wiring_unknown_revert_blocked",
            detail.clone(),
        )],
        error: Some(detail),
        // Refusal, not a drift-skip: `kept_artifact` is never set on
        // failure (the entry and artifact survive because the whole
        // revert is blocked, not counted as a Skipped keep).
        kept_artifact: false,
    })
}

/// Undo one pnpm-vendored package: restore the recorded pair fragments and
/// remove the artifact dir. Reverse application order; per-record ownership
/// is re-checked against the live fragment (drift ⇒ warning, left alone).
pub async fn revert_pnpm(entry: &VendorEntry, project_root: &Path, dry_run: bool) -> RevertOutcome {
    revert_pnpm_opts(entry, project_root, RevertOpts::new(dry_run)).await
}

/// [`revert_pnpm`] with full [`RevertOpts`]: `keep_artifact` skips the
/// artifact deletion — and the refusals that exist only to protect it —
/// while the wiring restore runs unchanged.
pub async fn revert_pnpm_opts(
    entry: &VendorEntry,
    project_root: &Path,
    opts: RevertOpts,
) -> RevertOutcome {
    let RevertOpts {
        dry_run,
        keep_artifact,
    } = opts;
    // SECURITY: `entry.uuid` comes from the committed, tamper-able
    // state.json and names the directory tree we are about to DELETE.
    // Validate through the same fail-closed grammar vendor used.
    let uuid_dir_rel = match guard_revert_uuid_dir(&entry.uuid) {
        Ok(d) => d,
        Err(outcome) => return outcome,
    };
    // Nothing to replay (a `repair`-reconstructed entry): the artifact may
    // only be removed when the lock provably no longer resolves through it —
    // otherwise refuse, fail-closed, instead of silently bricking installs.
    // Runs before the dry-run return so a preview never advertises a revert
    // the wet run refuses (same precedent as the uuid guard above). Skipped
    // under `keep_artifact`: the refusal exists only to protect the
    // deletion, which a preserve-state revert never performs.
    if entry.wiring.is_empty() {
        let in_use = pnpm_entry_in_use(entry, project_root).await;
        if let Some(blocked) = guard_unwired_revert(project_root, in_use, &uuid_dir_rel).await {
            return blocked;
        }
    }
    if dry_run {
        return RevertOutcome::ok();
    }
    let mut outcome = RevertOutcome::ok();

    // Partition by file through the allowlist (fail-closed skip+warning on
    // anything else — see REVERT_ALLOWLIST's security note).
    let mut touches_pkg = false;
    let mut touches_lock = false;
    for rec in &entry.wiring {
        if !REVERT_ALLOWLIST.contains(&rec.file.as_str()) {
            outcome.warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "ignoring wiring record for non-allowlisted file `{}`",
                    rec.file
                ),
            ));
            continue;
        }
        if rec.file == PACKAGE_JSON {
            touches_pkg = true;
        } else {
            touches_lock = true;
        }
    }

    // Load both surfaces up front (fail-closed on unparseable; a missing
    // file degrades to a warning and the artifact removal still proceeds).
    let mut lock_lines: Option<Vec<String>> = None;
    if touches_lock {
        match read_regular_string(&project_root.join(PNPM_LOCK)).await {
            Ok(text) => lock_lines = Some(split_lines(&text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                outcome.warnings.push(VendorWarning::new(
                    "vendor_lockfile_missing",
                    format!("{PNPM_LOCK} is missing; lock fragments cannot be restored"),
                ));
            }
            Err(e) => return RevertOutcome::failed(format!("cannot read {PNPM_LOCK}: {e}")),
        }
    }
    let mut pkg_state: Option<(Value, String)> = None; // (doc, indent)
    if touches_pkg {
        match read_regular(&project_root.join(PACKAGE_JSON)).await {
            Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                Ok(doc) if doc.is_object() => {
                    let indent = detect_indent(&String::from_utf8_lossy(&bytes));
                    pkg_state = Some((doc, indent));
                }
                // Fail-closed: editing a manifest we cannot parse risks
                // destroying it; the user must repair it first.
                _ => {
                    return RevertOutcome::failed(format!(
                        "{PACKAGE_JSON} is not a JSON object; fix it and re-run revert"
                    ))
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                outcome.warnings.push(VendorWarning::new(
                    "vendor_lockfile_missing",
                    format!("{PACKAGE_JSON} is missing; the pnpm override cannot be removed"),
                ));
            }
            Err(e) => return RevertOutcome::failed(format!("cannot read {PACKAGE_JSON}: {e}")),
        }
    }

    let mut lock_dirty = false;
    let mut pkg_dirty = false;
    for rec in entry.wiring.iter().rev() {
        match rec.file.as_str() {
            PNPM_LOCK => {
                if let Some(lines) = lock_lines.as_mut() {
                    revert_lock_record(
                        lines,
                        rec,
                        &entry.uuid,
                        &mut lock_dirty,
                        &mut outcome.warnings,
                    );
                }
            }
            PACKAGE_JSON => {
                if let Some((doc, _)) = pkg_state.as_mut() {
                    revert_pkg_record(doc, rec, &entry.uuid, &mut pkg_dirty, &mut outcome.warnings);
                }
            }
            _ => {} // warned above
        }
    }

    // Remove the now-empty tables iff vendor created them (third-party keys
    // added since keep the table alive).
    if let Some((doc, _)) = pkg_state.as_mut() {
        let (created_overrides, created_pnpm) = match &entry.pnpm {
            Some(meta) => (meta.created_overrides_table, meta.created_pnpm_table),
            None => (false, false),
        };
        if let Some(obj) = doc.as_object_mut() {
            if let Some(pnpm_tbl) = obj.get_mut("pnpm").and_then(Value::as_object_mut) {
                if created_overrides
                    && pnpm_tbl
                        .get("overrides")
                        .and_then(Value::as_object)
                        .is_some_and(serde_json::Map::is_empty)
                {
                    pnpm_tbl.shift_remove("overrides");
                    pkg_dirty = true;
                }
            }
            if created_pnpm
                && obj
                    .get("pnpm")
                    .and_then(Value::as_object)
                    .is_some_and(serde_json::Map::is_empty)
            {
                obj.shift_remove("pnpm");
                pkg_dirty = true;
            }
        }
    }

    // Reverse write order: lock first, package.json second.
    if lock_dirty {
        if let Some(lines) = &lock_lines {
            if let Err(e) = atomic_write_bytes_preserving_mode(
                &project_root.join(PNPM_LOCK),
                lines.join("\n").as_bytes(),
            )
            .await
            {
                return RevertOutcome::failed(format!("cannot write {PNPM_LOCK}: {e}"));
            }
        }
    }
    if pkg_dirty {
        if let Some((doc, indent)) = &pkg_state {
            let bytes = match serialize_json(doc, indent) {
                Ok(b) => b,
                Err(e) => {
                    return RevertOutcome::failed(format!("cannot serialize {PACKAGE_JSON}: {e}"))
                }
            };
            if let Err(e) =
                atomic_write_bytes_preserving_mode(&project_root.join(PACKAGE_JSON), &bytes).await
            {
                return RevertOutcome::failed(format!("cannot write {PACKAGE_JSON}: {e}"));
            }
        }
    }

    // pnpm-workspace.yaml override surface (pnpm >= 11): delete a file we
    // created, or splice our override back out of one we edited.
    if let Some(rec) = entry
        .wiring
        .iter()
        .find(|r| r.file == PNPM_WORKSPACE && r.kind == KIND_WS_OVERRIDE)
    {
        let (created_file, created_overrides) = match &entry.pnpm {
            Some(meta) => (
                meta.created_workspace_file,
                meta.created_workspace_overrides,
            ),
            None => (false, false),
        };
        if let Err(e) = revert_workspace(
            project_root,
            rec,
            created_file,
            created_overrides,
            &entry.uuid,
            &mut outcome.warnings,
        )
        .await
        {
            return RevertOutcome::failed(e);
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
    // entry), so only the deletion is skipped.
    if !keep_artifact {
        if let Err(e) = remove_tree(&project_root.join(&uuid_dir_rel)).await {
            return RevertOutcome::failed(format!("cannot remove {uuid_dir_rel}: {e}"));
        }
    }
    outcome
}

/// Undo the pnpm-workspace.yaml override: delete a file we created (when it
/// still holds only the vendoring scaffold), or splice our override key back
/// out of a file we edited (restoring the taken-over value, and dropping an
/// `overrides:` section we created once it empties). Drift ⇒ warning, left
/// alone. `Err` is a genuine write failure.
async fn revert_workspace(
    project_root: &Path,
    rec: &WiringRecord,
    created_file: bool,
    created_overrides: bool,
    entry_uuid: &str,
    warnings: &mut Vec<VendorWarning>,
) -> Result<(), String> {
    let path = project_root.join(PNPM_WORKSPACE);
    let text = match read_regular_string(&path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // ALREADY CONVERGED: for an Added override (no recorded
            // original) the reverted state is "no override" — a missing
            // file trivially satisfies it (an earlier partial revert may
            // have deleted the scaffold we created). Not drift.
            if rec.original.is_none() {
                return Ok(());
            }
            warnings.push(drifted(format!(
                "{PNPM_WORKSPACE} is missing; the pnpm >= 11 override cannot be removed"
            )));
            return Ok(());
        }
        Err(e) => return Err(format!("cannot read {PNPM_WORKSPACE}: {e}")),
    };
    // CRLF blindness fails CLOSED: the splices below match exact LF lines,
    // so a CRLF-converted file would read an Added override as "already
    // converged" and let the artifact it still points at be removed. Drift,
    // not convergence — the keep gate holds the artifact until the user
    // normalizes the file.
    if text.contains('\r') {
        warnings.push(drifted(format!(
            "{PNPM_WORKSPACE} has CRLF line endings the revert splices cannot edit; \
             left alone — normalize the file to LF and re-run `vendor --revert`"
        )));
        return Ok(());
    }

    // Fast path: a file we created that is still byte-identical to the
    // scaffold we wrote → delete it (byte-restore to "no file").
    if created_file {
        let scaffold = match (rec.key.as_deref(), rec.new.as_ref().and_then(Value::as_str)) {
            (Some(key), Some(spec)) => Some(ws_scaffold_text(key, spec)),
            _ => None,
        };
        if scaffold.as_deref() == Some(text.as_str()) {
            return tokio::fs::remove_file(&path)
                .await
                .map_err(|e| format!("cannot remove {PNPM_WORKSPACE}: {e}"));
        }
        // Drifted since vendoring: keep the user's file, remove only our key.
    }

    let mut lines = split_lines(&text);
    let mut dirty = false;
    revert_ws_record(&mut lines, rec, entry_uuid, &mut dirty, warnings);
    if dirty && created_overrides {
        remove_empty_ws_overrides_section(&mut lines);
    }
    if dirty {
        atomic_write_bytes_preserving_mode(&path, lines.join("\n").as_bytes())
            .await
            .map_err(|e| format!("cannot write {PNPM_WORKSPACE}: {e}"))?;
    }
    Ok(())
}

/// Remove our override key from the pnpm-workspace.yaml `overrides:` section
/// (or restore a taken-over value in place). Fail-closed on drift.
fn revert_ws_record(
    lines: &mut Vec<String>,
    rec: &WiringRecord,
    entry_uuid: &str,
    dirty: &mut bool,
    warnings: &mut Vec<VendorWarning>,
) {
    let Some(key) = rec.key.as_deref() else {
        warnings.push(drifted(format!(
            "wiring record in {PNPM_WORKSPACE} has no key; left alone"
        )));
        return;
    };
    let Some((start, end, indent)) = ws_overrides_section(lines) else {
        // ALREADY CONVERGED: an Added override's reverted state is "no
        // override" — the section being gone satisfies it (an earlier
        // partial revert removed our key and pruned the section). Not drift.
        if rec.original.is_none() {
            return;
        }
        warnings.push(drifted(format!(
            "{PNPM_WORKSPACE} overrides section is gone; `{key}` not removed"
        )));
        return;
    };
    for i in (start + 1)..end {
        let Some((k, repr, rest)) = parse_key_line(&lines[i], indent) else {
            continue;
        };
        if k != key {
            continue;
        }
        // ALREADY CONVERGED: a takeover entry already restored to the
        // user's recorded pin. Not drift.
        if rec.original.as_ref().and_then(Value::as_str) == Some(rest.as_str()) {
            return;
        }
        let ours = Some(rest.as_str()) == rec.new.as_ref().and_then(Value::as_str)
            || parse_vendor_path(&rest).is_some_and(|p| p.eco == "npm" && p.uuid == entry_uuid);
        if !ours {
            warnings.push(drifted(format!(
                "{PNPM_WORKSPACE} override `{key}` was changed since vendoring ({rest}); left alone"
            )));
            return;
        }
        match rec.original.as_ref().and_then(Value::as_str) {
            Some(orig) => {
                lines[i] = format!(
                    "{}{}: {orig}",
                    " ".repeat(indent),
                    yaml_key_like(key, &repr)
                );
            }
            None => {
                lines.remove(i);
            }
        }
        *dirty = true;
        return;
    }
    // ALREADY CONVERGED: an Added override's reverted state is "no
    // override" — an earlier partial revert already removed our key.
    if rec.original.is_none() {
        return;
    }
    warnings.push(drifted(format!(
        "{PNPM_WORKSPACE} override `{key}` no longer exists; nothing to remove"
    )));
}

/// Drop an `overrides:` section header we created once its last entry is
/// gone (the append added no blank separator, so removing the header alone
/// restores the file's original trailing bytes).
fn remove_empty_ws_overrides_section(lines: &mut Vec<String>) {
    let Some((start, end, indent)) = ws_overrides_section(lines) else {
        return;
    };
    let still_has_entry = lines[start + 1..end]
        .iter()
        .any(|l| parse_key_line(l, indent).is_some());
    if !still_has_entry {
        lines.remove(start);
    }
}

// ───────────────────────────── edit context ──────────────────────────────

struct EditCtx<'a> {
    name: &'a str,
    version: &'a str,
    /// `.socket/vendor/npm/<uuid>/<leaf>` (forward slashes, root-relative).
    rel_tgz: &'a str,
    /// `file:<rel_tgz>` — the exact override/lock value spelling (no `./`).
    spec: &'a str,
    /// `sha512-<base64>` of the packed tarball.
    integrity: &'a str,
    /// The override key BOTH surfaces edit (see
    /// [`OverrideDisposition::effective_key`]): our canonical
    /// `name@version` on a fresh insert, or the user's existing key on a
    /// takeover / re-run over a taken-over key.
    override_key: &'a str,
}

impl EditCtx<'_> {
    /// Registry-shaped key (`name@version`).
    fn reg_key(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }

    /// Our rekeyed packages/snapshots key (`name@file:<rel-tgz>`).
    fn new_key(&self) -> String {
        format!("{}@{}", self.name, self.spec)
    }

    /// Does `value` point at OUR vendored tarball for THIS name@version
    /// (any uuid — a stale uuid is rewritten to the current one with
    /// `original: None`)? See [`vendor_value_is_for`] on why the leaf
    /// binding is load-bearing.
    fn is_ours(&self, value: &str) -> bool {
        vendor_value_is_for(value, self.name, self.version)
    }

    /// Is `key` our rekeyed `name@file:<rel-tgz>` packages/snapshots key for
    /// THIS name@version (any uuid)?
    fn is_ours_key(&self, key: &str) -> bool {
        key.strip_prefix(self.name)
            .and_then(|rest| rest.strip_prefix("@file:"))
            .is_some_and(|rest| self.is_ours(rest))
    }

    /// The per-importer `specifier:` spelling: re-relativized for nested
    /// importers, root-relative for `.` (spike P7).
    fn spec_for_importer(&self, importer: &str) -> String {
        if importer == "." {
            self.spec.to_string()
        } else {
            format!(
                "file:{}{}",
                "../".repeat(importer.split('/').count()),
                self.rel_tgz
            )
        }
    }
}

// ─────────────────────────── pre-flight checks ───────────────────────────

/// `lockfileVersion: '9.0'` head check (accept pnpm's single quotes plus
/// double-quoted/bare spellings) — the v9 BACKEND's own guard. The flavor
/// router sniffs with [`super::pnpm_lock_legacy::sniff_lock_grammar`]
/// instead, whose allowlist also routes the legacy 5.4/6.0 grammars to
/// their backend; this check only fires if a non-9.0 lock reaches
/// `vendor_pnpm` directly.
pub(super) fn check_lock_version(text: &str) -> Result<(), String> {
    let version = text
        .lines()
        .take(5)
        .find_map(|line| line.strip_prefix("lockfileVersion:"))
        .map(|rest| rest.trim().trim_matches(['\'', '"']).to_string());
    match version {
        Some(v) if v == SUPPORTED_LOCK_VERSION => Ok(()),
        Some(v) => {
            // The remedy must point the right way: 5.x (pnpm 7) / 6.x
            // (pnpm 8) locks predate the v9 grammar and upgrading pnpm
            // re-locks them, but a HIGHER version means the user's pnpm
            // already outgrew this build — telling them "re-lock with
            // pnpm >= 9" would loop them back to the lock they have.
            let major = v.split('.').next().and_then(|m| m.parse::<u32>().ok());
            Err(match major {
                Some(m) if m < 9 => format!(
                    "{PNPM_LOCK} has lockfileVersion {v}; only {SUPPORTED_LOCK_VERSION} is \
                     supported — re-lock with pnpm >= 9"
                ),
                _ => format!(
                    "{PNPM_LOCK} has lockfileVersion {v}; this socket-patch build supports \
                     lockfileVersion {SUPPORTED_LOCK_VERSION} — re-lock with a pnpm release \
                     that emits it, or update socket-patch"
                ),
            })
        }
        None => Err(format!(
            "{PNPM_LOCK} has no lockfileVersion in its head; only \
             {SUPPORTED_LOCK_VERSION} is supported — re-lock with pnpm >= 9"
        )),
    }
}

/// The package-name component of a pnpm override key
/// (`[@scope/]name[@range]`, possibly behind a `parent>child` selector
/// chain — the override targets the LAST segment).
pub(super) fn override_key_name(key: &str) -> &str {
    let last = key.rsplit('>').next().unwrap_or(key).trim();
    if let Some(rest) = last.strip_prefix('@') {
        match rest.find('@') {
            Some(i) => &last[..i + 1],
            None => last,
        }
    } else {
        match last.find('@') {
            Some(i) => &last[..i],
            None => last,
        }
    }
}

/// Does `value` point into `.socket/vendor/npm/` (ours — any uuid)?
pub(super) fn is_vendor_value(value: &str) -> bool {
    parse_vendor_path(value).is_some_and(|p| p.eco == "npm")
}

/// A vendor value belonging to THIS `name@version`'s tarball (any uuid).
/// The leaf binding matters: a project can vendor the same package at
/// several versions, and edits must never treat a SIBLING version's
/// override/entry as their own.
pub(super) fn vendor_value_is_for(value: &str, name: &str, version: &str) -> bool {
    parse_vendor_path(value)
        .is_some_and(|p| p.eco == "npm" && p.leaf == tgz_rel_leaf(name, version))
}

/// How the package.json `pnpm.overrides` table relates to the package
/// being vendored. The lock's `overrides:` section must mirror this map
/// key-for-key (pnpm hard-checks the two and fails
/// `ERR_PNPM_LOCKFILE_CONFIG_MISMATCH` on any drift), so whichever key
/// this classification yields is the one BOTH surfaces edit.
pub(super) enum OverrideDisposition {
    /// No same-name key: insert our canonical `name@version` key.
    Insert,
    /// A same-name key already points into `.socket/vendor/npm/` — ours
    /// (any uuid; possibly a user key an earlier vendor took over).
    /// Rewrite that key's value in place; our own value is never
    /// recorded as an `original`.
    Ours { key: String },
    /// A user-authored exact-version pin equal to the version being
    /// vendored (`"tar-fs": "3.1.0"` or `"tar-fs@3.1.0": "3.1.0"`): take
    /// the key over — rewrite its VALUE to the `file:` spec (the user's
    /// pin already forces every `tar-fs` to this exact version, so
    /// redirecting the same key preserves their semantics). The edit
    /// sites re-read the pin from the live surface and record it as the
    /// wiring `original` so revert restores it exactly.
    Takeover { key: String },
}

impl OverrideDisposition {
    /// The override key both surfaces edit: the matched existing key, or
    /// our canonical `name@version` on a fresh insert.
    pub(super) fn effective_key<'a>(&'a self, our_key: &'a str) -> &'a str {
        match self {
            OverrideDisposition::Insert => our_key,
            OverrideDisposition::Ours { key } | OverrideDisposition::Takeover { key } => key,
        }
    }
}

/// Classify the package.json override state for `name` (see
/// [`OverrideDisposition`]). `Err` is a genuine conflict (fail-closed):
/// a range/different-version value, a `parent>child` selector chain
/// (scoped to one dependent — our whole-graph rewrite has different
/// semantics), a non-string value, or several same-name keys.
pub(super) fn classify_pkg_override(
    pkg: &Value,
    name: &str,
    version: &str,
    our_key: &str,
) -> Result<OverrideDisposition, String> {
    let Some(overrides) = pkg.get("pnpm").and_then(|p| p.get("overrides")) else {
        return Ok(OverrideDisposition::Insert);
    };
    let Some(map) = overrides.as_object() else {
        return Err("package.json pnpm.overrides is not an object".to_string());
    };
    let mut found: Option<OverrideDisposition> = None;
    for (key, value) in map {
        if override_key_name(key) != name {
            continue;
        }
        let value_str = value.as_str().unwrap_or("");
        // A SIBLING version's vendored override coexists — not ours to
        // touch (and not a conflict): skip it entirely.
        if is_vendor_value(value_str) && !vendor_value_is_for(value_str, name, version) {
            continue;
        }
        if found.is_some() {
            return Err(format!(
                "package.json carries more than one pnpm override for `{name}`; vendoring \
                 cannot pick one — remove the extras first"
            ));
        }
        let classified = if key.contains('>') {
            None
        } else if is_vendor_value(value_str) {
            Some(OverrideDisposition::Ours { key: key.clone() })
        } else if value_str == version && (key == name || key == our_key) {
            Some(OverrideDisposition::Takeover { key: key.clone() })
        } else {
            None
        };
        match classified {
            Some(d) => found = Some(d),
            None => {
                return Err(format!(
                    "package.json already carries a pnpm override for `{key}` ({value}); \
                     vendoring would fight it — remove the override (or vendor --revert) \
                     first (an exact-version pin equal to {version} is taken over \
                     automatically)"
                ))
            }
        }
    }
    Ok(found.unwrap_or(OverrideDisposition::Insert))
}

/// Lock-side mirror check against the effective key. Every same-name key
/// in the lock's `overrides:` section must BE `effective_key` (pnpm
/// requires the lock's override map to equal package.json's — a key-shape
/// drift means the pair is already desynced) with a value the edit can
/// own: ours, the exact pinned `version` (takeover), or already our spec.
/// A missing section/key is fine — the edit inserts it, restoring parity.
pub(super) fn check_lock_override(
    lines: &[String],
    name: &str,
    version: &str,
    effective_key: &str,
) -> Result<(), String> {
    let Some((start, end)) = section_bounds(lines, "overrides") else {
        return Ok(());
    };
    for line in &lines[start + 1..end] {
        if let Some((key, _repr, rest)) = parse_key_line(line, 2) {
            if override_key_name(&key) != name {
                continue;
            }
            // A sibling version's vendored override coexists — skip it.
            if is_vendor_value(&rest) && !vendor_value_is_for(&rest, name, version) {
                continue;
            }
            if key != effective_key {
                return Err(format!(
                    "{PNPM_LOCK} carries an override key `{key}` for `{name}` that does not \
                     match package.json's `{effective_key}` — the two override maps must \
                     agree (run `pnpm install` to re-sync them) before vendoring"
                ));
            }
            if !(is_vendor_value(&rest) || rest == version) {
                return Err(format!(
                    "{PNPM_LOCK} already carries an override for `{key}` ({rest}); vendoring \
                     would fight it — remove the override (or vendor --revert) first"
                ));
            }
        }
    }
    Ok(())
}

/// Pre-flight: does the lock have a packages entry vendoring can target —
/// the registry `name@version` key, or our own rekeyed `name@file:` key
/// (the in-sync / stale-uuid re-run)? The ours-probe binds to THIS
/// version's leaf — a sibling version's vendored entry is not a target
/// (see `vendor_value_is_for`).
fn lock_has_target_package(lines: &[String], name: &str, version: &str) -> bool {
    let Some((start, end)) = section_bounds(lines, "packages") else {
        return false;
    };
    let reg_key = format!("{name}@{version}");
    let ours_prefix = format!("{name}@file:");
    let mut i = start + 1;
    while let Some(block) = next_block(lines, i, end) {
        if block.key == reg_key {
            return true;
        }
        if let Some(rest) = block.key.strip_prefix(&ours_prefix) {
            if vendor_value_is_for(rest, name, version) {
                return true;
            }
        }
        i = block.end;
    }
    false
}

/// Pre-flight fail-closed guard against reference forms the surgery does
/// not rewrite. The five edits move the plain registry forms only — the
/// `name@version` packages/snapshots keys, bare-`version` importer fields
/// and snapshot dep refs. The same package instance can also be referenced
/// through a PEER-SUFFIXED dep path (`name@version(peer@…)`, emitted
/// whenever the package has peerDependencies) or an ALIASED value
/// (`npm:name@version` specs record `name@version` as the dep value).
/// Those spellings would survive the rekey verbatim and dangle — pnpm then
/// hard-rejects the lock (a snapshot/importer referencing a dep path whose
/// packages entry no longer exists) — so refuse before anything is staged
/// or written. The spike has no pnpm-blessed fixtures for either shape;
/// guessing their rewritten spelling risks worse corruption than refusing.
///
/// CATALOG-consumed deps (pnpm >= 9.5: importer `specifier: catalog:…` plus
/// a top-level `catalogs:` snapshot section) also refuse: the real range
/// lives in pnpm-workspace.yaml — a file outside the package.json + lock
/// PAIR this surgery owns — and package.json keeps its `catalog:`
/// specifier, so rewriting the importer entry to `file:` desyncs the lock
/// from the manifest and `pnpm install --frozen-lockfile` rejects it with
/// ERR_PNPM_OUTDATED_LOCKFILE (verified against real pnpm).
fn check_rewritable_refs(lines: &[String], name: &str, version: &str) -> Result<(), String> {
    let reg_key = format!("{name}@{version}");
    let key_peer_prefix = format!("{reg_key}(");
    let val_peer_prefix = format!("{version}(");
    let refuse = |what: &str, spelling: &str| {
        Err(format!(
            "{PNPM_LOCK} references {reg_key} through {what} (`{spelling}`) that the \
             pair surgery cannot rewrite — vendoring would leave a dangling reference \
             pnpm rejects; this lock shape is not supported yet"
        ))
    };
    let refuse_catalog = |where_: &str, spelling: &str| {
        Err(format!(
            "{PNPM_LOCK} resolves {reg_key} through a pnpm catalog ({where_}: \
             `{spelling}`) that the pair surgery cannot rewrite — the catalog range \
             lives in pnpm-workspace.yaml and package.json keeps its `catalog:` \
             specifier, so a rewritten lock fails `pnpm install --frozen-lockfile`; \
             this lock shape is not supported yet"
        ))
    };
    if let Some((start, end)) = section_bounds(lines, "catalogs") {
        let mut i = start + 1;
        while let Some(catalog) = next_block(lines, i, end) {
            let mut k = catalog.header + 1;
            while k < catalog.end {
                let Some((dep, _repr, rest)) = parse_key_line(&lines[k], 4) else {
                    k += 1;
                    continue;
                };
                if dep != name || !rest.is_empty() {
                    k += 1;
                    continue;
                }
                let mut f = k + 1;
                while f < catalog.end {
                    let Some((field, _repr, fval)) = parse_key_line(&lines[f], 6) else {
                        break;
                    };
                    if field == "version" && (fval == version || fval.starts_with(&val_peer_prefix))
                    {
                        return refuse_catalog(
                            "catalogs: entry",
                            &format!("{}/{name}", catalog.key),
                        );
                    }
                    f += 1;
                }
                k = f;
            }
            i = catalog.end;
        }
    }
    if let Some((start, end)) = section_bounds(lines, "snapshots") {
        let mut i = start + 1;
        while let Some(block) = next_block(lines, i, end) {
            if block.key.starts_with(&key_peer_prefix) {
                return refuse("a peer-suffixed snapshot key", &block.key);
            }
            for line in &lines[block.header + 1..block.end] {
                let Some((dep, _repr, rest)) = parse_key_line(line, 6) else {
                    continue;
                };
                if rest == reg_key || rest.starts_with(&key_peer_prefix) {
                    return refuse("an aliased snapshot reference", &rest);
                }
                if dep == name && rest.starts_with(&val_peer_prefix) {
                    return refuse("a peer-suffixed snapshot reference", &rest);
                }
            }
            i = block.end;
        }
    }
    if let Some((start, end)) = section_bounds(lines, "importers") {
        let mut i = start + 1;
        while let Some(importer) = next_block(lines, i, end) {
            let mut k = importer.header + 1;
            while k < importer.end {
                let Some((dep, _repr, rest)) = parse_key_line(&lines[k], 6) else {
                    k += 1;
                    continue;
                };
                if !rest.is_empty() {
                    k += 1;
                    continue;
                }
                let (spec, ver, f) = dep_field_lines(lines, k + 1, importer.end);
                if let Some((_, v)) = ver {
                    if v == reg_key || v.starts_with(&key_peer_prefix) {
                        return refuse("an aliased importer version", &v);
                    }
                    if dep == name && v.starts_with(&val_peer_prefix) {
                        return refuse("a peer-suffixed importer version", &v);
                    }
                    if dep == name && v == version {
                        if let Some((_, s)) = spec {
                            // pnpm spells the default catalog `'catalog:'`
                            // (quoted) and named ones `catalog:<name>` (bare).
                            if unquote_value(&s).starts_with("catalog:") {
                                return refuse_catalog(
                                    &format!("importer `{}` specifier", importer.key),
                                    &s,
                                );
                            }
                        }
                    }
                }
                k = f;
            }
            i = importer.end;
        }
    }
    Ok(())
}

// ───────────────────────── package.json override ─────────────────────────

/// Add/refresh `pnpm.overrides[<name>@<version>] = file:<rel-tgz>` on the
/// parsed (preserve_order) document. Returns
/// `(changed, created_pnpm_table, created_overrides_table)`.
pub(super) fn apply_pkg_override(
    pkg: &mut Value,
    our_key: &str,
    spec: &str,
    wiring: &mut Vec<WiringRecord>,
) -> Result<(bool, bool, bool), String> {
    let obj = pkg
        .as_object_mut()
        .ok_or("package.json root is not an object")?;
    let created_pnpm_table = !obj.contains_key("pnpm");
    let pnpm_tbl = obj
        .entry("pnpm")
        .or_insert_with(|| Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .ok_or("package.json `pnpm` is not an object")?;
    let created_overrides_table = !pnpm_tbl.contains_key("overrides");
    let overrides = pnpm_tbl
        .entry("overrides")
        .or_insert_with(|| Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .ok_or("package.json `pnpm.overrides` is not an object")?;

    let existing = overrides.get(our_key).and_then(Value::as_str);
    if existing == Some(spec) {
        return Ok((false, false, false)); // in sync, no record
    }
    // The classify pre-flight guarantees an existing value here is either
    // OURS (a stale uuid — never recorded as an "original") or the user's
    // exact-version pin being TAKEN OVER (recorded so revert restores it).
    let was_present = existing.is_some();
    let original = existing
        .filter(|v| !is_vendor_value(v))
        .map(|v| Value::String(v.to_string()));
    overrides.insert(our_key.to_string(), Value::String(spec.to_string()));
    wiring.push(WiringRecord {
        file: PACKAGE_JSON.to_string(),
        kind: KIND_PKG_OVERRIDE.to_string(),
        action: if was_present {
            WiringAction::Rewritten
        } else {
            WiringAction::Added
        },
        key: Some(our_key.to_string()),
        original,
        new: Some(Value::String(spec.to_string())),
    });
    Ok((true, created_pnpm_table, created_overrides_table))
}

// ─────────────────────── pnpm-workspace.yaml override ─────────────────────
// pnpm >= 11 reads `overrides:` only from pnpm-workspace.yaml, so the same
// `<name>@<version>` → `file:` mapping is mirrored here. Edits are line
// splices (never a YAML library) so untouched lines stay byte-identical and
// revert restores the file byte-for-byte (or deletes a file we created).

/// The bytes of a freshly created pnpm-workspace.yaml: a root-only
/// `packages:` list (pnpm 9 refuses a workspace file with no `packages`
/// field) plus the single `overrides:` entry. Kept in one place so the
/// create edit and the revert equality-check cannot drift apart.
fn ws_scaffold_text(key: &str, spec: &str) -> String {
    format!(
        "{}\n{}\noverrides:\n  {}: {spec}\n",
        WS_SCAFFOLD_PACKAGES[0],
        WS_SCAFFOLD_PACKAGES[1],
        yaml_key(key),
    )
}

/// The outcome of applying the override to pnpm-workspace.yaml.
struct WorkspaceEdit {
    /// New file content to write (`None` ⇒ already in sync, nothing to do).
    new_text: Option<String>,
    /// We created pnpm-workspace.yaml from scratch (revert deletes it).
    created_file: bool,
    /// We created the `overrides:` section in a pre-existing file (revert
    /// removes just that section once emptied).
    created_overrides: bool,
}

/// Locate the top-level `overrides:` block and the indent its entries use
/// (pnpm's canonical is 2 spaces; a hand-authored file may differ). `None`
/// when there is no block-style `overrides:` section.
fn ws_overrides_section(lines: &[String]) -> Option<(usize, usize, usize)> {
    let (start, end) = section_bounds(lines, "overrides")?;
    let indent = lines[start + 1..end]
        .iter()
        .find(|l| !l.trim().is_empty())
        .map(|l| indent_of(l))
        .filter(|&n| n >= 1)
        .unwrap_or(2);
    Some((start, end, indent))
}

/// Pre-flight mirror check for pnpm-workspace.yaml (analogous to
/// [`check_lock_override`]): a block-style `overrides:` section may only
/// carry a same-name key equal to `effective_key` with an ownable value.
/// A flow-style/inline `overrides:` mapping is refused (the line surgery
/// cannot splice into it). A missing file/section is fine.
fn check_workspace_override(
    ws_text: Option<&str>,
    name: &str,
    version: &str,
    effective_key: &str,
) -> Result<(), String> {
    let Some(text) = ws_text else {
        return Ok(());
    };
    let lines = split_lines(text);
    if lines
        .iter()
        .any(|l| l.starts_with("overrides:") && l.trim_end() != "overrides:")
    {
        return Err(format!(
            "{PNPM_WORKSPACE} has an inline `overrides:` mapping the pair surgery cannot \
             edit — rewrite it as a block mapping (`overrides:` then indented entries) \
             and re-run"
        ));
    }
    let Some((start, end, indent)) = ws_overrides_section(&lines) else {
        return Ok(());
    };
    for line in &lines[start + 1..end] {
        let Some((key, _repr, rest)) = parse_key_line(line, indent) else {
            continue;
        };
        if override_key_name(&key) != name {
            continue;
        }
        // A sibling version's vendored override coexists — skip it.
        if is_vendor_value(&rest) && !vendor_value_is_for(&rest, name, version) {
            continue;
        }
        if key != effective_key {
            return Err(format!(
                "{PNPM_WORKSPACE} carries an override key `{key}` for `{name}` that does not \
                 match `{effective_key}` — remove it (or vendor --revert) first"
            ));
        }
        if !(is_vendor_value(&rest) || rest == version) {
            return Err(format!(
                "{PNPM_WORKSPACE} already carries an override for `{key}` ({rest}); vendoring \
                 would fight it — remove the override (or vendor --revert) first"
            ));
        }
    }
    Ok(())
}

/// Add/refresh the `effective_key` → `file:<rel-tgz>` override in
/// pnpm-workspace.yaml (creating the file, or the section, when absent).
fn apply_workspace_override(
    ws_text: Option<&str>,
    our_key: &str,
    spec: &str,
    wiring: &mut Vec<WiringRecord>,
) -> Result<WorkspaceEdit, String> {
    let Some(text) = ws_text else {
        // No workspace file: write the root-only scaffold + our override.
        wiring.push(ws_record(our_key, spec, WiringAction::Added, None));
        return Ok(WorkspaceEdit {
            new_text: Some(ws_scaffold_text(our_key, spec)),
            created_file: true,
            created_overrides: false,
        });
    };
    let mut lines = split_lines(text);

    if let Some((start, end, indent)) = ws_overrides_section(&lines) {
        let pad = " ".repeat(indent);
        // Immutable scan: our line (if present) + the append anchor.
        let mut ours = None;
        let mut last_entry = start;
        for (i, line) in lines.iter().enumerate().take(end).skip(start + 1) {
            if let Some((key, repr, rest)) = parse_key_line(line, indent) {
                last_entry = i;
                if key == our_key {
                    ours = Some((i, repr, rest));
                    break;
                }
            }
        }
        if let Some((i, repr, rest)) = ours {
            if rest == spec {
                return Ok(WorkspaceEdit {
                    new_text: None,
                    created_file: false,
                    created_overrides: false,
                });
            }
            // Ours (stale uuid, no original) or the user's exact-version pin
            // being TAKEN OVER (recorded, live quoting preserved).
            let original = (!is_vendor_value(&rest)).then(|| rest.clone());
            lines[i] = format!("{pad}{}: {spec}", yaml_key_like(our_key, &repr));
            wiring.push(ws_record(our_key, spec, WiringAction::Rewritten, original));
        } else {
            lines.insert(
                last_entry + 1,
                format!("{pad}{}: {spec}", yaml_key(our_key)),
            );
            wiring.push(ws_record(our_key, spec, WiringAction::Added, None));
        }
        return Ok(WorkspaceEdit {
            new_text: Some(lines.join("\n")),
            created_file: false,
            created_overrides: false,
        });
    }

    // File exists without an `overrides:` section: append one after the last
    // non-empty line (no blank separator, so revert removes exactly two
    // lines and the file's trailing bytes stay put).
    let anchor = lines
        .iter()
        .rposition(|l| !l.trim().is_empty())
        .map(|i| i + 1)
        .unwrap_or(lines.len());
    lines.splice(
        anchor..anchor,
        [
            "overrides:".to_string(),
            format!("  {}: {spec}", yaml_key(our_key)),
        ],
    );
    wiring.push(ws_record(our_key, spec, WiringAction::Added, None));
    Ok(WorkspaceEdit {
        new_text: Some(lines.join("\n")),
        created_file: false,
        created_overrides: true,
    })
}

fn ws_record(
    key: &str,
    spec: &str,
    action: WiringAction,
    original: Option<String>,
) -> WiringRecord {
    WiringRecord {
        file: PNPM_WORKSPACE.to_string(),
        kind: KIND_WS_OVERRIDE.to_string(),
        action,
        key: Some(key.to_string()),
        original: original.map(Value::String),
        new: Some(Value::String(spec.to_string())),
    }
}

// ───────────────────────────── lock edits ─────────────────────────────────

/// Edit 1: the `overrides:` section — insert it before `importers:` when
/// absent (pnpm emits it between `settings:` and `importers:`), or splice
/// our entry into the existing one.
fn edit_overrides(
    lines: &mut Vec<String>,
    ctx: &EditCtx<'_>,
    wiring: &mut Vec<WiringRecord>,
) -> Result<bool, String> {
    let our_key = ctx.override_key.to_string();
    let entry_line = format!("  {}: {}", yaml_key(&our_key), ctx.spec);
    if let Some((start, end)) = section_bounds(lines, "overrides") {
        // Immutable scan first: our line's position (if present) + the last
        // entry line (the append anchor).
        let mut ours = None;
        let mut last_entry = start;
        for (i, line) in lines.iter().enumerate().take(end).skip(start + 1) {
            if let Some((key, repr, rest)) = parse_key_line(line, 2) {
                last_entry = i;
                if key == our_key {
                    ours = Some((i, repr, rest));
                    break;
                }
            }
        }
        if let Some((i, repr, rest)) = ours {
            if rest == ctx.spec {
                return Ok(false); // in sync
            }
            // Ours with a stale uuid (no original), or the user's pinned
            // value being TAKEN OVER (recorded as original; the live key
            // repr/quoting is preserved so revert is byte-faithful).
            let original = (!is_vendor_value(&rest)).then(|| rest.clone());
            lines[i] = format!("  {}: {}", yaml_key_like(&our_key, &repr), ctx.spec);
            wiring.push(overrides_record(
                &our_key,
                ctx.spec,
                WiringAction::Rewritten,
                original,
            ));
            return Ok(true);
        }
        lines.insert(last_entry + 1, entry_line);
        wiring.push(overrides_record(
            &our_key,
            ctx.spec,
            WiringAction::Added,
            None,
        ));
        return Ok(true);
    }
    // No overrides section: insert one right before `importers:` (with the
    // blank separator pnpm emits — byte-identical to the P1/P4 fixtures).
    let (importers, _) =
        section_bounds(lines, "importers").ok_or("no importers: section to anchor on")?;
    lines.splice(
        importers..importers,
        ["overrides:".to_string(), entry_line, String::new()],
    );
    wiring.push(overrides_record(
        &our_key,
        ctx.spec,
        WiringAction::Added,
        None,
    ));
    Ok(true)
}

pub(super) fn overrides_record(
    key: &str,
    spec: &str,
    action: WiringAction,
    original: Option<String>,
) -> WiringRecord {
    WiringRecord {
        file: PNPM_LOCK.to_string(),
        kind: KIND_LOCK_OVERRIDES.to_string(),
        action,
        key: Some(key.to_string()),
        // `Some` only on a takeover (the user's pinned value); Added and
        // rewritten-over-ours never record an original.
        original: original.map(Value::String),
        new: Some(Value::String(spec.to_string())),
    }
}

/// Locate a dep entry's `specifier:`/`version:` field lines (8-space
/// indent) starting at `f`. Returns the two `(line_idx, value)` pairs plus
/// the index of the first non-field line.
#[allow(clippy::type_complexity)]
fn dep_field_lines(
    lines: &[String],
    mut f: usize,
    end: usize,
) -> (Option<(usize, String)>, Option<(usize, String)>, usize) {
    let mut spec = None;
    let mut ver = None;
    while f < end {
        let Some((field, _repr, fval)) = parse_key_line(&lines[f], 8) else {
            break;
        };
        match field.as_str() {
            "specifier" => spec = Some((f, fval)),
            "version" => ver = Some((f, fval)),
            _ => {}
        }
        f += 1;
    }
    (spec, ver, f)
}

/// Edit 2: every importer's dep entry for the exact `name@version` —
/// `specifier:` (re-relativized per importer) AND `version:` move to the
/// `file:` spec.
// &mut Vec keeps all five edit functions' signatures unifiable into the one
// fn array `vendor_pnpm` iterates (the section-splicing edits need the Vec).
#[allow(clippy::ptr_arg)]
fn edit_importers(
    lines: &mut Vec<String>,
    ctx: &EditCtx<'_>,
    wiring: &mut Vec<WiringRecord>,
) -> Result<bool, String> {
    let Some((start, end)) = section_bounds(lines, "importers") else {
        return Ok(false);
    };
    let mut changed = false;
    let mut i = start + 1;
    while let Some(importer) = next_block(lines, i, end) {
        let importer_key = importer.key.clone();
        // Dep entries sit at 6-space indent under the 4-space dep-type
        // headers; their fields at 8.
        let mut k = importer.header + 1;
        while k < importer.end {
            let Some((dep, _repr, rest)) = parse_key_line(&lines[k], 6) else {
                k += 1;
                continue;
            };
            if dep != ctx.name || !rest.is_empty() {
                k += 1;
                continue;
            }
            let (spec_idx, ver_idx, f) = dep_field_lines(lines, k + 1, importer.end);
            if let (Some((si, old_spec)), Some((vi, old_ver))) = (spec_idx, ver_idx) {
                let target =
                    old_ver == ctx.version || (old_ver != ctx.spec && ctx.is_ours(&old_ver));
                if target {
                    let was_ours = ctx.is_ours(&old_ver);
                    let importer_spec = ctx.spec_for_importer(&importer_key);
                    lines[si] = format!("        specifier: {importer_spec}");
                    lines[vi] = format!("        version: {}", ctx.spec);
                    wiring.push(WiringRecord {
                        file: PNPM_LOCK.to_string(),
                        kind: KIND_LOCK_IMPORTER_DEP.to_string(),
                        action: WiringAction::Rewritten,
                        key: Some(format!("{importer_key}|{dep}")),
                        original: if was_ours {
                            None
                        } else {
                            Some(serde_json::json!({
                                "specifier": old_spec,
                                "version": old_ver,
                            }))
                        },
                        new: Some(serde_json::json!({
                            "specifier": importer_spec,
                            "version": ctx.spec,
                        })),
                    });
                    changed = true;
                }
            }
            k = f;
        }
        i = importer.end;
    }
    Ok(changed)
}

/// Fail closed on a half-drifted lock: when a `[start, end)` section
/// carries BOTH the registry-keyed entry and a socket file:-keyed entry
/// for this package, a rekey would splice a DUPLICATE mapping key (pnpm
/// refuses to parse those) and surgery cannot decide which block carries
/// the truth.
fn check_no_split_entry(
    lines: &[String],
    start: usize,
    end: usize,
    ctx: &EditCtx<'_>,
    section: &str,
) -> Result<(), String> {
    let reg_key = ctx.reg_key();
    let mut has_registry = false;
    let mut has_ours = false;
    let mut j = start + 1;
    while let Some(block) = next_block(lines, j, end) {
        if block.key == reg_key {
            has_registry = true;
        } else if ctx.is_ours_key(&block.key) {
            has_ours = true;
        }
        j = block.end;
    }
    if has_registry && has_ours {
        return Err(format!(
            "{section} section carries BOTH `{reg_key}` and a `{}@file:…` entry (a \
             half-edited lock); run `pnpm install` to re-resolve it, then re-vendor",
            ctx.name
        ));
    }
    Ok(())
}

/// Edit 3: rekey the `packages:` entry and rewrite its body —
/// `resolution: {integrity: <ours>, tarball: <spec>}`, a `version:` line
/// inserted after it, `deprecated:` dropped, everything else verbatim.
fn edit_packages(
    lines: &mut Vec<String>,
    ctx: &EditCtx<'_>,
    wiring: &mut Vec<WiringRecord>,
) -> Result<bool, String> {
    let (start, end) = section_bounds(lines, "packages").ok_or("no packages: section")?;
    let reg_key = ctx.reg_key();
    let new_key = ctx.new_key();
    check_no_split_entry(lines, start, end, ctx, "packages")?;

    let mut i = start + 1;
    while let Some(block) = next_block(lines, i, end) {
        let is_registry = block.key == reg_key;
        let is_ours_key = ctx.is_ours_key(&block.key);
        if !is_registry && !is_ours_key {
            i = block.end;
            continue;
        }
        let original_lines: Vec<String> = lines[block.header..block.end].to_vec();
        let expected_resolution = format!(
            "    resolution: {{integrity: {}, tarball: {}}}",
            ctx.integrity, ctx.spec
        );
        if block.key == new_key && original_lines.iter().any(|l| l == &expected_resolution) {
            return Ok(false); // in sync (only the exact version moves: done)
        }
        // Rebuild the block (registry → ours, or stale-ours → current).
        let mut new_lines = Vec::with_capacity(original_lines.len() + 1);
        new_lines.push(format!(
            "  {}:{}",
            yaml_key_like(&new_key, &block.repr),
            block.rest_suffix()
        ));
        let mut replaced_resolution = false;
        for line in &original_lines[1..] {
            if line.trim_start().starts_with("resolution:") {
                new_lines.push(expected_resolution.clone());
                new_lines.push(format!("    version: {}", ctx.version));
                replaced_resolution = true;
            } else if line.starts_with("    deprecated:") || line.starts_with("    version:") {
                // deprecated: dropped (pnpm drops it for file: entries);
                // version: re-inserted canonically after resolution. Exact
                // 4-space match: `version`/`deprecated` are also real npm
                // package names, and a PEER DEP on one puts the same
                // spelling at 6-space indent — those lines stay verbatim.
            } else {
                new_lines.push(line.clone());
            }
        }
        if !replaced_resolution {
            return Err(format!(
                "packages entry `{}` has no resolution line",
                block.key
            ));
        }
        lines.splice(block.header..block.end, new_lines.clone());
        wiring.push(WiringRecord {
            file: PNPM_LOCK.to_string(),
            kind: KIND_LOCK_PACKAGE.to_string(),
            action: WiringAction::Rewritten,
            // Always the registry key: a stale-ours block's key embeds the
            // OLD uuid, and recording it would break the carry-forward
            // original-fill's file+kind+key match against the first
            // vendoring's record (revert locates the live block via `new`'s
            // embedded key, never via `key`).
            key: Some(reg_key.clone()),
            original: if is_ours_key {
                None
            } else {
                Some(lines_value(&original_lines))
            },
            new: Some(lines_value(&new_lines)),
        });
        return Ok(true);
    }
    // Pre-flight proved an entry exists; reaching here means it vanished
    // mid-run (impossible in-process) — fail loudly rather than wire half.
    Err(format!("packages entry for {reg_key} vanished mid-rewrite"))
}

/// Edit 4a: rekey the `snapshots:` entry (`name@version` →
/// `name@file:<rel-tgz>`), body verbatim.
fn edit_snapshot_rekey(
    lines: &mut Vec<String>,
    ctx: &EditCtx<'_>,
    wiring: &mut Vec<WiringRecord>,
) -> Result<bool, String> {
    let Some((start, end)) = section_bounds(lines, "snapshots") else {
        return Ok(false); // a lock without snapshots has nothing to rekey
    };
    let reg_key = ctx.reg_key();
    let new_key = ctx.new_key();
    check_no_split_entry(lines, start, end, ctx, "snapshots")?;

    let mut i = start + 1;
    while let Some(block) = next_block(lines, i, end) {
        let is_registry = block.key == reg_key;
        let is_ours_key = ctx.is_ours_key(&block.key);
        if !is_registry && !is_ours_key {
            i = block.end;
            continue;
        }
        if block.key == new_key {
            return Ok(false); // in sync
        }
        let original_lines: Vec<String> = lines[block.header..block.end].to_vec();
        let mut new_lines = original_lines.clone();
        new_lines[0] = format!(
            "  {}:{}",
            yaml_key_like(&new_key, &block.repr),
            block.rest_suffix()
        );
        lines.splice(block.header..block.end, new_lines.clone());
        wiring.push(WiringRecord {
            file: PNPM_LOCK.to_string(),
            kind: KIND_LOCK_SNAPSHOT.to_string(),
            action: WiringAction::Rewritten,
            // Registry key for the same generation-stability reason as the
            // packages record above.
            key: Some(reg_key.clone()),
            original: if is_ours_key {
                None
            } else {
                Some(lines_value(&original_lines))
            },
            new: Some(lines_value(&new_lines)),
        });
        return Ok(true);
    }
    Ok(false)
}

/// Edit 4b: every OTHER snapshot's dep reference to the exact version —
/// `name: <version>` → bare `name: file:<rel-tgz>` (spike P1: dependents
/// reference the override with no `name@` prefix).
// &mut Vec keeps all five edit functions' signatures unifiable into the one
// fn array `vendor_pnpm` iterates (the section-splicing edits need the Vec).
#[allow(clippy::ptr_arg)]
fn edit_snapshot_refs(
    lines: &mut Vec<String>,
    ctx: &EditCtx<'_>,
    wiring: &mut Vec<WiringRecord>,
) -> Result<bool, String> {
    let Some((start, end)) = section_bounds(lines, "snapshots") else {
        return Ok(false);
    };
    let mut changed = false;
    let mut i = start + 1;
    while let Some(block) = next_block(lines, i, end) {
        for line in lines[block.header + 1..block.end].iter_mut() {
            let Some((dep, _repr, rest)) = parse_key_line(line, 6) else {
                continue;
            };
            if dep != ctx.name {
                continue;
            }
            let target = rest == ctx.version || (rest != ctx.spec && ctx.is_ours(&rest));
            if !target {
                continue;
            }
            let was_ours = ctx.is_ours(&rest);
            *line = format!("      {}: {}", yaml_key(&dep), ctx.spec);
            wiring.push(WiringRecord {
                file: PNPM_LOCK.to_string(),
                kind: KIND_LOCK_SNAPSHOT_REF.to_string(),
                action: WiringAction::Rewritten,
                key: Some(format!("{}|{dep}", block.key)),
                original: if was_ours {
                    None
                } else {
                    Some(Value::String(rest.clone()))
                },
                new: Some(Value::String(ctx.spec.to_string())),
            });
            changed = true;
        }
        i = block.end;
    }
    Ok(changed)
}

// ───────────────────────────── revert helpers ─────────────────────────────

pub(super) fn revert_pkg_record(
    doc: &mut Value,
    rec: &WiringRecord,
    entry_uuid: &str,
    dirty: &mut bool,
    warnings: &mut Vec<VendorWarning>,
) {
    if rec.kind != KIND_PKG_OVERRIDE {
        warnings.push(VendorWarning::new(
            "vendor_lock_entry_drifted",
            format!(
                "unknown wiring kind `{}` for {PACKAGE_JSON}; left alone",
                rec.kind
            ),
        ));
        return;
    }
    let Some(key) = rec.key.as_deref() else {
        warnings.push(drifted(
            "package.json override record has no key; left alone",
        ));
        return;
    };
    let overrides = doc
        .get_mut("pnpm")
        .and_then(|p| p.get_mut("overrides"))
        .and_then(Value::as_object_mut);
    let Some(overrides) = overrides else {
        // ALREADY CONVERGED: an Added override's reverted state is "no
        // override" — the table being gone satisfies it (an earlier
        // partial revert removed our key and dropped the empty table).
        // Not drift: stay silent so the drift-skip keep gate can converge.
        if rec.original.is_none() {
            return;
        }
        warnings.push(drifted(format!(
            "pnpm.overrides is gone; `{key}` not removed"
        )));
        return;
    };
    let live = overrides.get(key).and_then(Value::as_str);
    // ALREADY CONVERGED: the live state already equals the reverted state —
    // key absent for an Added entry, or the user's recorded pin restored in
    // place for a takeover. Not drift.
    let converged = match rec.original.as_ref().and_then(Value::as_str) {
        Some(orig) => live == Some(orig),
        None => live.is_none() && !overrides.contains_key(key),
    };
    if converged {
        return;
    }
    let ours = live.is_some_and(|v| {
        Some(v) == rec.new.as_ref().and_then(Value::as_str)
            || parse_vendor_path(v).is_some_and(|p| p.eco == "npm" && p.uuid == entry_uuid)
    });
    if !ours {
        warnings.push(drifted(format!(
            "pnpm.overrides[`{key}`] was changed since vendoring ({live:?}); left alone"
        )));
        return;
    }
    // A takeover recorded the user's pinned value as `original`: restore
    // it in place (the key stays). A plain Added/Rewritten-over-ours
    // record has no original — remove the key as before.
    match rec.original.as_ref().and_then(Value::as_str) {
        Some(orig) => {
            overrides.insert(key.to_string(), Value::String(orig.to_string()));
        }
        None => {
            overrides.shift_remove(key);
        }
    }
    *dirty = true;
}

fn revert_lock_record(
    lines: &mut Vec<String>,
    rec: &WiringRecord,
    entry_uuid: &str,
    dirty: &mut bool,
    warnings: &mut Vec<VendorWarning>,
) {
    let Some(key) = rec.key.as_deref() else {
        warnings.push(drifted(format!(
            "wiring record in {PNPM_LOCK} has no key; left alone"
        )));
        return;
    };
    match rec.kind.as_str() {
        KIND_LOCK_OVERRIDES => revert_overrides_line(lines, rec, key, entry_uuid, dirty, warnings),
        KIND_LOCK_IMPORTER_DEP => revert_importer_dep(lines, rec, key, entry_uuid, dirty, warnings),
        KIND_LOCK_PACKAGE => revert_block(lines, rec, key, "packages", entry_uuid, dirty, warnings),
        KIND_LOCK_SNAPSHOT => {
            revert_block(lines, rec, key, "snapshots", entry_uuid, dirty, warnings)
        }
        KIND_LOCK_SNAPSHOT_REF => revert_snapshot_ref(lines, rec, key, entry_uuid, dirty, warnings),
        other => warnings.push(drifted(format!(
            "unknown wiring kind `{other}` for `{key}`; left alone"
        ))),
    }
}

pub(super) fn revert_overrides_line(
    lines: &mut Vec<String>,
    rec: &WiringRecord,
    key: &str,
    entry_uuid: &str,
    dirty: &mut bool,
    warnings: &mut Vec<VendorWarning>,
) {
    let Some((start, end)) = section_bounds(lines, "overrides") else {
        // ALREADY CONVERGED: an Added override's reverted state is "no
        // override" — the section being gone satisfies it (an earlier
        // partial revert removed our line and pruned the section). Not
        // drift: stay silent so the drift-skip keep gate can converge.
        if rec.original.is_none() {
            return;
        }
        warnings.push(drifted(format!(
            "overrides section is gone; `{key}` not removed"
        )));
        return;
    };
    // First pass: locate our line + count the other entries (the section is
    // pruned only when ours was the last one).
    let mut ours_at = None;
    let mut others = 0usize;
    for (i, line) in lines.iter().enumerate().take(end).skip(start + 1) {
        if let Some((k, repr, rest)) = parse_key_line(line, 2) {
            if k == key && ours_at.is_none() {
                ours_at = Some((i, repr, rest));
            } else {
                others += 1;
            }
        }
    }
    let Some((idx, repr, rest)) = ours_at else {
        // ALREADY CONVERGED: an Added override's reverted state is "no
        // override" — an earlier partial revert already removed our line.
        if rec.original.is_none() {
            return;
        }
        warnings.push(drifted(format!("overrides entry `{key}` no longer exists")));
        return;
    };
    // ALREADY CONVERGED: a takeover entry already restored to the user's
    // recorded pin. Not drift.
    if rec.original.as_ref().and_then(Value::as_str) == Some(rest.as_str()) {
        return;
    }
    let ours = Some(rest.as_str()) == rec.new.as_ref().and_then(Value::as_str)
        || parse_vendor_path(&rest).is_some_and(|p| p.eco == "npm" && p.uuid == entry_uuid);
    if !ours {
        warnings.push(drifted(format!(
            "overrides entry `{key}` was changed since vendoring ({rest}); left alone"
        )));
        return;
    }
    // A takeover recorded the user's pinned value: restore it in place
    // (key + quoting preserved; the section obviously stays).
    if let Some(orig) = rec.original.as_ref().and_then(Value::as_str) {
        lines[idx] = format!("  {}: {orig}", yaml_key_like(key, &repr));
        *dirty = true;
        return;
    }
    lines.remove(idx);
    *dirty = true;
    if others == 0 {
        // Ours was the last entry: drop the section header (and its blank
        // separator) too — pnpm never emits an empty overrides section.
        lines.remove(start);
        if start < lines.len() && lines[start].is_empty() {
            lines.remove(start);
        }
    }
}

fn revert_importer_dep(
    lines: &mut [String],
    rec: &WiringRecord,
    key: &str,
    entry_uuid: &str,
    dirty: &mut bool,
    warnings: &mut Vec<VendorWarning>,
) {
    let Some((importer_key, dep)) = key.rsplit_once('|') else {
        warnings.push(drifted(format!(
            "malformed importer-dep key `{key}`; left alone"
        )));
        return;
    };
    let Some((start, end)) = section_bounds(lines, "importers") else {
        warnings.push(drifted(
            "importers section is gone; nothing to restore".to_string(),
        ));
        return;
    };
    let mut i = start + 1;
    while let Some(importer) = next_block(lines, i, end) {
        if importer.key != importer_key {
            i = importer.end;
            continue;
        }
        let mut k = importer.header + 1;
        while k < importer.end {
            let Some((d, _repr, rest)) = parse_key_line(&lines[k], 6) else {
                k += 1;
                continue;
            };
            if d != dep || !rest.is_empty() {
                k += 1;
                continue;
            }
            let (spec_idx, ver_idx, _) = dep_field_lines(lines, k + 1, importer.end);
            let (Some((si, live_spec)), Some((vi, live_ver))) = (spec_idx, ver_idx) else {
                break;
            };
            // ALREADY CONVERGED: both fields already equal the recorded
            // pre-vendor original — an earlier partial revert (or the
            // user, by hand) already restored this record. Not drift:
            // stay silent so the drift-skip keep gate can converge.
            if let Some(original) = rec.original.as_ref() {
                if original.get("specifier").and_then(Value::as_str) == Some(live_spec.as_str())
                    && original.get("version").and_then(Value::as_str) == Some(live_ver.as_str())
                {
                    return;
                }
            }
            let new_ver = rec
                .new
                .as_ref()
                .and_then(|n| n.get("version"))
                .and_then(Value::as_str);
            let ours = Some(live_ver.as_str()) == new_ver
                || parse_vendor_path(&live_ver)
                    .is_some_and(|p| p.eco == "npm" && p.uuid == entry_uuid);
            if !ours {
                warnings.push(drifted(format!(
                    "importer dep `{key}` was re-resolved since vendoring ({live_ver}); left alone"
                )));
                return;
            }
            let Some(original) = rec.original.as_ref() else {
                warnings.push(drifted(format!(
                    "importer dep `{key}` has no recorded pre-vendor original; left as-is \
                     (re-run `pnpm install` to re-resolve it)"
                )));
                return;
            };
            let (Some(orig_spec), Some(orig_ver)) = (
                original.get("specifier").and_then(Value::as_str),
                original.get("version").and_then(Value::as_str),
            ) else {
                warnings.push(drifted(format!(
                    "importer dep `{key}` original is malformed"
                )));
                return;
            };
            lines[si] = format!("        specifier: {orig_spec}");
            lines[vi] = format!("        version: {orig_ver}");
            *dirty = true;
            return;
        }
        break;
    }
    warnings.push(drifted(format!(
        "importer dep `{key}` no longer exists; nothing to restore"
    )));
}

/// Restore a rekeyed packages/snapshots block: locate the block by the NEW
/// key (from `rec.new`'s first line), verify ownership, splice the original
/// lines back.
fn revert_block(
    lines: &mut Vec<String>,
    rec: &WiringRecord,
    key: &str,
    section: &str,
    entry_uuid: &str,
    dirty: &mut bool,
    warnings: &mut Vec<VendorWarning>,
) {
    let new_lines = rec.new.as_ref().and_then(value_lines);
    let Some(new_lines) = new_lines else {
        warnings.push(drifted(format!(
            "record for `{key}` has no `new` fragment; left alone"
        )));
        return;
    };
    let Some((new_key, _repr, _rest)) = new_lines.first().and_then(|l| parse_key_line(l, 2)) else {
        warnings.push(drifted(format!(
            "record for `{key}` has a malformed fragment"
        )));
        return;
    };
    let Some((start, end)) = section_bounds(lines, section) else {
        warnings.push(drifted(format!(
            "{section} section is gone; `{key}` not restored"
        )));
        return;
    };
    let mut i = start + 1;
    while let Some(block) = next_block(lines, i, end) {
        if block.key != new_key {
            i = block.end;
            continue;
        }
        // Ours iff the live block is exactly what we wrote, or its key still
        // points into OUR uuid dir (a re-serialized but unmoved entry).
        let live: Vec<String> = lines[block.header..block.end].to_vec();
        let key_is_ours = new_key.rsplit_once("@file:").is_some_and(|(_, p)| {
            parse_vendor_path(p).is_some_and(|v| v.eco == "npm" && v.uuid == entry_uuid)
        });
        if live != new_lines && !key_is_ours {
            warnings.push(drifted(format!(
                "{section} entry `{new_key}` was changed since vendoring; left alone"
            )));
            return;
        }
        let Some(original) = rec.original.as_ref().and_then(value_lines) else {
            warnings.push(drifted(format!(
                "{section} entry `{key}` has no recorded pre-vendor original; left as-is \
                 (re-run `pnpm install` to re-resolve it)"
            )));
            return;
        };
        lines.splice(block.header..block.end, original);
        *dirty = true;
        return;
    }
    // ALREADY CONVERGED: an earlier partial revert restored this record —
    // the splice rekeys the block back to its pre-vendor key, so the
    // recorded `file:` key no longer matches while the original block is
    // live verbatim. Not drift: stay silent so the drift-skip keep gate can
    // converge instead of keeping the artifacts forever.
    if let Some(orig) = rec.original.as_ref().and_then(value_lines) {
        let mut j = start + 1;
        while let Some(block) = next_block(lines, j, end) {
            if lines[block.header..block.end] == orig[..] {
                return;
            }
            j = block.end;
        }
    }
    warnings.push(drifted(format!(
        "{section} entry `{new_key}` no longer exists; nothing to restore"
    )));
}

fn revert_snapshot_ref(
    lines: &mut [String],
    rec: &WiringRecord,
    key: &str,
    entry_uuid: &str,
    dirty: &mut bool,
    warnings: &mut Vec<VendorWarning>,
) {
    let Some((snapshot_key, dep)) = key.rsplit_once('|') else {
        warnings.push(drifted(format!(
            "malformed snapshot-ref key `{key}`; left alone"
        )));
        return;
    };
    let Some((start, end)) = section_bounds(lines, "snapshots") else {
        warnings.push(drifted(
            "snapshots section is gone; nothing to restore".to_string(),
        ));
        return;
    };
    let mut i = start + 1;
    while let Some(block) = next_block(lines, i, end) {
        if block.key != snapshot_key {
            i = block.end;
            continue;
        }
        for line in lines[block.header + 1..block.end].iter_mut() {
            let Some((d, _repr, rest)) = parse_key_line(line, 6) else {
                continue;
            };
            if d != dep {
                continue;
            }
            // ALREADY CONVERGED: the live ref already equals the recorded
            // pre-vendor original — an earlier partial revert (or the
            // user, by hand) already restored it. Not drift.
            if rec.original.as_ref().and_then(Value::as_str) == Some(rest.as_str()) {
                return;
            }
            let ours = Some(rest.as_str()) == rec.new.as_ref().and_then(Value::as_str)
                || parse_vendor_path(&rest).is_some_and(|p| p.eco == "npm" && p.uuid == entry_uuid);
            if !ours {
                warnings.push(drifted(format!(
                    "snapshot ref `{key}` was re-resolved since vendoring ({rest}); left alone"
                )));
                return;
            }
            let Some(original) = rec.original.as_ref().and_then(Value::as_str) else {
                warnings.push(drifted(format!(
                    "snapshot ref `{key}` has no recorded pre-vendor original; left as-is"
                )));
                return;
            };
            *line = format!("      {}: {original}", yaml_key(dep));
            *dirty = true;
            return;
        }
        break;
    }
    warnings.push(drifted(format!(
        "snapshot ref `{key}` no longer exists; nothing to restore"
    )));
}

pub(super) fn drifted(detail: impl Into<String>) -> VendorWarning {
    VendorWarning::new("vendor_lock_entry_drifted", detail.into())
}

// ────────────────────────── surfaces commit + unwind ──────────────────────

/// Write the override surfaces FIRST (package.json, then pnpm-workspace.yaml),
/// the lock LAST; a lock failure unwinds both override surfaces so the P3
/// desync (an override with no matching lock entry, which pnpm silently
/// unpatches or rejects as a config mismatch) is never left on disk.
pub(super) async fn commit_surfaces(
    project_root: &Path,
    new_pkg: Option<&[u8]>,
    original_pkg: &[u8],
    new_ws: Option<&[u8]>,
    original_ws: Option<&[u8]>,
    ws_created: bool,
    new_lock: Option<&[u8]>,
) -> Result<(), String> {
    if let Some(bytes) = new_pkg {
        atomic_write_bytes_preserving_mode(&project_root.join(PACKAGE_JSON), bytes)
            .await
            .map_err(|e| format!("cannot write {PACKAGE_JSON}: {e}"))?;
    }
    if let Some(bytes) = new_ws {
        if let Err(e) =
            atomic_write_bytes_preserving_mode(&project_root.join(PNPM_WORKSPACE), bytes).await
        {
            unwind_override_surfaces(project_root, new_pkg, original_pkg, false, None, false).await;
            return Err(format!(
                "cannot write {PNPM_WORKSPACE}: {e} ({PACKAGE_JSON} restored to its original bytes)"
            ));
        }
    }
    if let Some(bytes) = new_lock {
        if let Err(e) =
            atomic_write_bytes_preserving_mode(&project_root.join(PNPM_LOCK), bytes).await
        {
            // Best effort: a lock write failing usually means the restores
            // fail identically loudly, but we still try so the override
            // surfaces do not outlive the lock they depend on.
            unwind_override_surfaces(
                project_root,
                new_pkg,
                original_pkg,
                new_ws.is_some(),
                original_ws,
                ws_created,
            )
            .await;
            return Err(format!(
                "cannot write {PNPM_LOCK}: {e} (override surfaces restored to their original state)"
            ));
        }
    }
    Ok(())
}

/// Best-effort restore of the already-written override surfaces after a
/// downstream write failure: package.json back to its original bytes; a
/// created pnpm-workspace.yaml deleted, an edited one rewritten.
async fn unwind_override_surfaces(
    project_root: &Path,
    new_pkg: Option<&[u8]>,
    original_pkg: &[u8],
    ws_written: bool,
    original_ws: Option<&[u8]>,
    ws_created: bool,
) {
    if new_pkg.is_some() {
        let _ = atomic_write_bytes_preserving_mode(&project_root.join(PACKAGE_JSON), original_pkg)
            .await;
    }
    if ws_written {
        let ws_path = project_root.join(PNPM_WORKSPACE);
        if ws_created {
            let _ = tokio::fs::remove_file(&ws_path).await;
        } else if let Some(orig) = original_ws {
            let _ = atomic_write_bytes_preserving_mode(&ws_path, orig).await;
        }
    }
}

// ───────────────────────────── guarded reads ──────────────────────────────

/// Guarded read shared in shape with the vendor siblings' twins
/// (npm_lock.rs, npm_flavor.rs, lock_inventory.rs): `open_regular_file`
/// opens with `O_NONBLOCK` and rejects non-regular files, so a FIFO planted
/// as one of the pair files fails fast instead of wedging vendor / revert /
/// the in-use probe forever in an `open(2)` waiting for a writer.
pub(super) async fn read_regular(path: &Path) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt as _;

    let (mut file, metadata) = crate::utils::fs::open_regular_file(path).await?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes).await?;
    Ok(bytes)
}

/// [`read_regular`], decoded as UTF-8 (`InvalidData` on failure, matching
/// `read_to_string`'s error kind).
pub(super) async fn read_regular_string(path: &Path) -> std::io::Result<String> {
    let bytes = read_regular(path).await?;
    String::from_utf8(bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

// ─────────────────────── yaml-ish line-block helpers ──────────────────────
// pnpm-lock.yaml is machine-emitted with a fixed 2/4/6/8-space shape; these
// helpers splice line blocks and never interpret YAML generically.

pub(super) fn split_lines(text: &str) -> Vec<String> {
    text.split('\n').map(str::to_string).collect()
}

/// `(header_idx, end_idx)` of a top-level `name:` section; `end` is the
/// first following column-0 line (exclusive), so trailing blank separator
/// lines belong to the section.
pub(super) fn section_bounds(lines: &[String], name: &str) -> Option<(usize, usize)> {
    let header = format!("{name}:");
    let start = lines.iter().position(|l| l == &header)?;
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, l)| !l.is_empty() && !l.starts_with(' '))
        .map(|(i, _)| i)
        .unwrap_or(lines.len());
    Some((start, end))
}

/// One 2-space-keyed block inside a section (`[header, end)`; `end` stops at
/// the blank separator / next block header, so the captured fragment is the
/// verbatim entry without surrounding blanks).
pub(super) struct YamlBlock {
    pub(super) header: usize,
    pub(super) end: usize,
    pub(super) key: String,
    /// The key exactly as spelled in the file (incl. quotes) — rekeys
    /// preserve the file's quoting style.
    repr: String,
    /// Inline value after `:` (e.g. `{}` for empty snapshots), `""` if none.
    rest: String,
}

impl YamlBlock {
    /// The inline-rest suffix to re-emit after the (re)written key.
    fn rest_suffix(&self) -> String {
        if self.rest.is_empty() {
            String::new()
        } else {
            format!(" {}", self.rest)
        }
    }
}

/// The next block at or after line `i` (within `[i, end)`).
pub(super) fn next_block(lines: &[String], mut i: usize, end: usize) -> Option<YamlBlock> {
    while i < end {
        if let Some((key, repr, rest)) = parse_key_line(&lines[i], 2) {
            let mut j = i + 1;
            while j < end && !lines[j].is_empty() && indent_of(&lines[j]) >= 4 {
                j += 1;
            }
            return Some(YamlBlock {
                header: i,
                end: j,
                key,
                repr,
                rest,
            });
        }
        i += 1;
    }
    None
}

pub(super) fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// Parse a mapping line at exactly `indent` spaces into
/// `(key, verbatim_key_repr, value_after_colon)`. Accepts pnpm's bare keys
/// and both quote styles (single quotes are what pnpm emits for `@`-leading
/// keys); the value separator is the first `:` followed by a space or EOL
/// (keys themselves contain `:` in `file:` specs).
pub(super) fn parse_key_line(line: &str, indent: usize) -> Option<(String, String, String)> {
    if line.len() <= indent || !line.as_bytes()[..indent].iter().all(|&b| b == b' ') {
        return None;
    }
    let s = &line[indent..];
    let c0 = s.as_bytes()[0];
    if c0 == b' ' {
        return None;
    }
    if c0 == b'\'' || c0 == b'"' {
        let quote = c0 as char;
        let close = s[1..].find(quote)? + 1;
        let after = &s[close + 1..];
        let rest = after.strip_prefix(':')?;
        let rest = rest.strip_prefix(' ').unwrap_or(rest);
        return Some((
            s[1..close].to_string(),
            s[..close + 1].to_string(),
            rest.to_string(),
        ));
    }
    let bytes = s.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b':' && (i + 1 == bytes.len() || bytes[i + 1] == b' ') {
            if i == 0 {
                return None;
            }
            let rest = if i + 1 < bytes.len() { &s[i + 2..] } else { "" };
            return Some((s[..i].to_string(), s[..i].to_string(), rest.to_string()));
        }
    }
    None
}

/// Strip one matching pair of surrounding quotes from a mapping VALUE
/// (pnpm quotes values that would misparse as plain YAML scalars, e.g. the
/// default-catalog specifier `'catalog:'`).
fn unquote_value(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && (bytes[0] == b'\'' || bytes[0] == b'"')
        && bytes[bytes.len() - 1] == bytes[0]
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

/// pnpm quotes `@`-leading keys with single quotes; everything we write is
/// otherwise bare.
pub(super) fn yaml_key(key: &str) -> String {
    if key.starts_with('@') {
        format!("'{key}'")
    } else {
        key.to_string()
    }
}

/// Re-spell `key` in the same quoting style as the original `repr`.
pub(super) fn yaml_key_like(key: &str, original_repr: &str) -> String {
    match original_repr.as_bytes().first() {
        Some(b'\'') => format!("'{key}'"),
        Some(b'"') => format!("\"{key}\""),
        _ => yaml_key(key),
    }
}

pub(super) fn lines_value(lines: &[String]) -> Value {
    Value::Array(lines.iter().map(|l| Value::String(l.clone())).collect())
}

pub(super) fn value_lines(v: &Value) -> Option<Vec<String>> {
    v.as_array().map(|a| {
        a.iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::PatchFileInfo;
    use crate::patch::apply::{ApplyResult, VerifyStatus};
    use base64::Engine as _;
    use sha2::{Digest, Sha512};
    use std::collections::HashMap;
    use std::path::PathBuf;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const ORIG_INDEX: &[u8] = b"module.exports = () => 'orig';\n";
    const PATCHED_INDEX: &[u8] = b"module.exports = () => 'patched';\n";

    /// The spike tarball's integrity, as committed in the after-fixtures.
    /// Our pack pipeline produces a DIFFERENT (deterministic) tarball, so
    /// fixture comparisons substitute the actual integrity for this token —
    /// everything else must be byte-identical.
    const SPIKE_INTEGRITY: &str =
        "sha512-VR8nCbFxvOcFX5Rxku2psjaj0+xzKdzFkcuqZJSHf597bMVomG100t6+cJkMBFRLhyVdSVwufbCwVzlCzZkUwg==";

    // ── tool-generated byte-exact oracles ─────────────────────────────────
    // Provenance: spikes/pnpm/p1-multi-dep/{before,after}/ — generated by
    // pnpm 9.15.9 AND 10.34.1 (byte-identical on both majors), spike P1/P2.
    const P1_BEFORE_PKG: &str = r#"{
  "name": "vendor-spike",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "consumer": "file:./consumer",
    "left-pad": "1.3.0",
    "left-pad-old": "npm:left-pad@1.2.0"
  }
}
"#;
    const P1_AFTER_PKG: &str = r#"{
  "name": "vendor-spike",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "consumer": "file:./consumer",
    "left-pad": "1.3.0",
    "left-pad-old": "npm:left-pad@1.2.0"
  },
  "pnpm": {
    "overrides": {
      "left-pad@1.3.0": "file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz"
    }
  }
}
"#;
    const P1_BEFORE_LOCK: &str = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      consumer:
        specifier: file:./consumer
        version: file:consumer
      left-pad:
        specifier: 1.3.0
        version: 1.3.0
      left-pad-old:
        specifier: npm:left-pad@1.2.0
        version: left-pad@1.2.0

packages:

  consumer@file:consumer:
    resolution: {directory: consumer, type: directory}

  left-pad@1.2.0:
    resolution: {integrity: sha512-OQadpCyFCT/VLniZQgym8d3/ofIJtuZyw2ibsVeIUOexKgW/osn8+mMFJbwGMPeDC4GnLzD8q115WPCDx4YRWg==}
    deprecated: use String.prototype.padStart()

  left-pad@1.3.0:
    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==}
    deprecated: use String.prototype.padStart()

snapshots:

  consumer@file:consumer:
    dependencies:
      left-pad: 1.3.0

  left-pad@1.2.0: {}

  left-pad@1.3.0: {}
";
    const P1_AFTER_LOCK: &str = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

overrides:
  left-pad@1.3.0: file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz

importers:

  .:
    dependencies:
      consumer:
        specifier: file:./consumer
        version: file:consumer
      left-pad:
        specifier: file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz
        version: file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz
      left-pad-old:
        specifier: npm:left-pad@1.2.0
        version: left-pad@1.2.0

packages:

  consumer@file:consumer:
    resolution: {directory: consumer, type: directory}

  left-pad@1.2.0:
    resolution: {integrity: sha512-OQadpCyFCT/VLniZQgym8d3/ofIJtuZyw2ibsVeIUOexKgW/osn8+mMFJbwGMPeDC4GnLzD8q115WPCDx4YRWg==}
    deprecated: use String.prototype.padStart()

  left-pad@file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz:
    resolution: {integrity: sha512-VR8nCbFxvOcFX5Rxku2psjaj0+xzKdzFkcuqZJSHf597bMVomG100t6+cJkMBFRLhyVdSVwufbCwVzlCzZkUwg==, tarball: file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz}
    version: 1.3.0

snapshots:

  consumer@file:consumer:
    dependencies:
      left-pad: file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz

  left-pad@1.2.0: {}

  left-pad@file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz: {}
";

    // Provenance: spikes/pnpm/p7-workspace/{before,after}/ (spike P7) — the
    // per-importer re-relativized specifier vs root-relative version.
    const P7_BEFORE_PKG: &str = r#"{
  "name": "ws-root",
  "version": "1.0.0",
  "private": true
}
"#;
    const P7_AFTER_PKG: &str = r#"{
  "name": "ws-root",
  "version": "1.0.0",
  "private": true,
  "pnpm": {
    "overrides": {
      "left-pad@1.3.0": "file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz"
    }
  }
}
"#;
    const P7_BEFORE_LOCK: &str = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .: {}

  packages/app:
    dependencies:
      left-pad:
        specifier: ^1.3.0
        version: 1.3.0

packages:

  left-pad@1.3.0:
    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==}
    deprecated: use String.prototype.padStart()

snapshots:

  left-pad@1.3.0: {}
";
    const P7_AFTER_LOCK: &str = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

overrides:
  left-pad@1.3.0: file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz

importers:

  .: {}

  packages/app:
    dependencies:
      left-pad:
        specifier: file:../../.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz
        version: file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz

packages:

  left-pad@file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz:
    resolution: {integrity: sha512-VR8nCbFxvOcFX5Rxku2psjaj0+xzKdzFkcuqZJSHf597bMVomG100t6+cJkMBFRLhyVdSVwufbCwVzlCzZkUwg==, tarball: file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz}
    version: 1.3.0

snapshots:

  left-pad@file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz: {}
";

    struct Fixture {
        tmp: tempfile::TempDir,
        record: PatchRecord,
    }

    impl Fixture {
        fn root(&self) -> &Path {
            self.tmp.path()
        }

        fn installed(&self) -> PathBuf {
            self.root().join("node_modules/left-pad")
        }

        fn rel_tgz(&self) -> String {
            format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz")
        }

        async fn read(&self, name: &str) -> String {
            tokio::fs::read_to_string(self.root().join(name))
                .await
                .unwrap()
        }

        /// The actual SRI of the tarball our pack produced.
        async fn actual_integrity(&self) -> String {
            let tgz = tokio::fs::read(self.root().join(self.rel_tgz()))
                .await
                .unwrap();
            format!(
                "sha512-{}",
                base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&tgz))
            )
        }

        async fn vendor(&self, dry_run: bool) -> VendorOutcome {
            let blobs = self.root().join(".socket/blobs");
            let sources = PatchSources::blobs_only(&blobs);
            vendor_pnpm(
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
    }

    async fn fixture_with(pkg_json: &str, lock: &str) -> Fixture {
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

        tokio::fs::write(root.join(PACKAGE_JSON), pkg_json)
            .await
            .unwrap();
        tokio::fs::write(root.join(PNPM_LOCK), lock).await.unwrap();

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
        Fixture { tmp, record }
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
    async fn p1_fixture_oracle_transform_is_byte_identical_for_both_files() {
        let fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("success carries a ledger entry");

        // package.json: byte-identical to the pnpm-blessed after fixture.
        assert_eq!(fx.read(PACKAGE_JSON).await, P1_AFTER_PKG);

        // Lock: byte-identical modulo the integrity (ours is recomputed from
        // the deterministic tarball we packed — never the spike's bytes).
        let actual = fx.actual_integrity().await;
        assert_ne!(
            actual, SPIKE_INTEGRITY,
            "different tarballs, different hashes"
        );
        let expected_lock = P1_AFTER_LOCK.replace(SPIKE_INTEGRITY, &actual);
        assert_eq!(fx.read(PNPM_LOCK).await, expected_lock);

        // Ledger facts: flavor + meta + wiring kinds.
        assert_eq!(entry.flavor.as_deref(), Some("pnpm"));
        assert_eq!(
            entry.pnpm,
            Some(PnpmMeta {
                created_overrides_table: true,
                created_pnpm_table: true,
                created_workspace_file: true,
                ..Default::default()
            })
        );
        assert_eq!(entry.artifact.path, fx.rel_tgz());
        let kinds: Vec<&str> = entry.wiring.iter().map(|r| r.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec![
                KIND_PKG_OVERRIDE,
                KIND_LOCK_OVERRIDES,
                KIND_LOCK_IMPORTER_DEP,
                KIND_LOCK_PACKAGE,
                KIND_LOCK_SNAPSHOT,
                KIND_LOCK_SNAPSHOT_REF,
                KIND_WS_OVERRIDE,
            ],
            "{:?}",
            entry.wiring
        );
        // The transitive consumer snapshot-ref is keyed snapshot|dep.
        let snap_ref = entry
            .wiring
            .iter()
            .find(|r| r.kind == KIND_LOCK_SNAPSHOT_REF)
            .unwrap();
        assert_eq!(
            snap_ref.key.as_deref(),
            Some("consumer@file:consumer|left-pad")
        );
        assert_eq!(snap_ref.original, Some(Value::String("1.3.0".into())));

        // Scoping: the 1.2.0 sibling stayed registry (asserted by the byte
        // oracle above, re-asserted explicitly here).
        let lock = fx.read(PNPM_LOCK).await;
        assert!(lock.contains("  left-pad@1.2.0:\n    resolution: {integrity: sha512-OQadpCyF"));
        assert!(
            lock.contains("        version: left-pad@1.2.0\n"),
            "aliased 1.2.0 importer untouched"
        );
    }

    #[tokio::test]
    async fn p7_workspace_fixture_re_relativizes_the_sub_importer_specifier() {
        let fx = fixture_with(P7_BEFORE_PKG, P7_BEFORE_LOCK).await;
        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();

        assert_eq!(fx.read(PACKAGE_JSON).await, P7_AFTER_PKG);
        let expected_lock = P7_AFTER_LOCK.replace(SPIKE_INTEGRITY, &fx.actual_integrity().await);
        assert_eq!(fx.read(PNPM_LOCK).await, expected_lock);

        let dep = entry
            .wiring
            .iter()
            .find(|r| r.kind == KIND_LOCK_IMPORTER_DEP)
            .unwrap();
        assert_eq!(dep.key.as_deref(), Some("packages/app|left-pad"));
        assert_eq!(
            dep.new.as_ref().unwrap()["specifier"],
            Value::String(format!("file:../../{}", fx.rel_tgz())),
            "specifier is re-relativized per importer"
        );
        assert_eq!(
            dep.new.as_ref().unwrap()["version"],
            Value::String(format!("file:{}", fx.rel_tgz())),
            "version stays lockfile-root-relative"
        );
    }

    #[tokio::test]
    async fn existing_user_override_for_the_name_is_refused() {
        // Name-keyed, range-keyed, and exact-key-but-foreign-value overrides
        // all conflict; an override for a DIFFERENT package does not.
        for key in ["left-pad", "left-pad@^1", "left-pad@1.3.0"] {
            let pkg = format!(
                "{{\n  \"name\": \"x\",\n  \"pnpm\": {{\n    \"overrides\": {{\n      \"{key}\": \"1.2.0\"\n    }}\n  }}\n}}\n"
            );
            let fx = fixture_with(&pkg, P1_BEFORE_LOCK).await;
            let detail = expect_refused(fx.vendor(false).await, "vendor_override_conflict");
            assert!(detail.contains(key), "{detail}");
            assert!(
                !fx.root().join(".socket/vendor").exists(),
                "refusal writes nothing"
            );
            assert_eq!(fx.read(PNPM_LOCK).await, P1_BEFORE_LOCK, "lock untouched");
        }

        // Lock-side desynced override conflicts too.
        let lock =
            P1_BEFORE_LOCK.replace("importers:", "overrides:\n  left-pad: 1.2.0\n\nimporters:");
        let fx = fixture_with(P1_BEFORE_PKG, &lock).await;
        expect_refused(fx.vendor(false).await, "vendor_override_conflict");

        // Unrelated override: fine.
        let pkg = r#"{
  "name": "x",
  "dependencies": { "left-pad": "1.3.0" },
  "pnpm": {
    "overrides": {
      "other-pkg": "2.0.0"
    }
  }
}
"#;
        let lock =
            P1_BEFORE_LOCK.replace("importers:", "overrides:\n  other-pkg: 2.0.0\n\nimporters:");
        let fx = fixture_with(pkg, &lock).await;
        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();
        assert_eq!(
            entry.pnpm,
            Some(PnpmMeta {
                created_workspace_file: true,
                ..Default::default()
            })
        );
        // Our entry extends the existing overrides section, theirs intact.
        let live = fx.read(PNPM_LOCK).await;
        assert!(live.contains("overrides:\n  other-pkg: 2.0.0\n  left-pad@1.3.0: file:"));

        // Revert removes only ours, keeping the user's table + section.
        let outcome = revert_pnpm(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        let live: Value = serde_json::from_str(&fx.read(PACKAGE_JSON).await).unwrap();
        assert_eq!(
            live["pnpm"]["overrides"]["other-pkg"],
            Value::String("2.0.0".into())
        );
        assert!(live["pnpm"]["overrides"].get("left-pad@1.3.0").is_none());
        let live_lock = fx.read(PNPM_LOCK).await;
        assert!(live_lock.contains("overrides:\n  other-pkg: 2.0.0\n\nimporters:"));
    }

    // ── in-use probe ───────────────────────────────────────────────────────

    /// The prune-time in-use probe: a packages/snapshots block resolving to
    /// the artifact means in use; an overrides declaration ALONE (the state
    /// pnpm leaves after the dependency is removed and re-locked) does not;
    /// a missing or unsupported-version lock is undeterminable (keep).
    #[tokio::test]
    async fn pnpm_entry_in_use_reflects_lock_graph() {
        let fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();

        // Freshly vendored: the rekeyed file: blocks are in the graph.
        assert_eq!(pnpm_entry_in_use(&entry, fx.root()).await, Some(true));

        // Dep removed + re-locked: pnpm prunes the file: blocks but keeps
        // the overrides declaration mirrored from package.json.
        let removed_lock = format!(
            "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n\
             \noverrides:\n  left-pad@1.3.0: file:{}\n\nimporters:\n\n  .:\n    \
             dependencies:\n      consumer:\n        specifier: file:./consumer\n        \
             version: file:consumer\n\npackages:\n\n  consumer@file:consumer:\n    \
             resolution: {{directory: consumer, type: directory}}\n\nsnapshots:\n\n  \
             consumer@file:consumer: {{}}\n",
            fx.rel_tgz()
        );
        tokio::fs::write(fx.root().join(PNPM_LOCK), &removed_lock)
            .await
            .unwrap();
        assert_eq!(
            pnpm_entry_in_use(&entry, fx.root()).await,
            Some(false),
            "the lingering overrides declaration alone is not usage"
        );

        // Unsupported lock version: undeterminable.
        tokio::fs::write(fx.root().join(PNPM_LOCK), "lockfileVersion: '6.0'\n")
            .await
            .unwrap();
        assert_eq!(pnpm_entry_in_use(&entry, fx.root()).await, None);

        // Missing lock: undeterminable.
        tokio::fs::remove_file(fx.root().join(PNPM_LOCK))
            .await
            .unwrap();
        assert_eq!(pnpm_entry_in_use(&entry, fx.root()).await, None);
    }

    // ── empty-wiring (reconstructed) revert guard ──────────────────────────

    /// Vendor, then reshape the entry into what `repair`'s no-ledger
    /// reconstruction persists: same uuid/artifact, EMPTY wiring, no meta.
    async fn reconstructed_fixture() -> (Fixture, VendorEntry) {
        let fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let mut entry = entry.unwrap();
        entry.wiring.clear();
        entry.pnpm = None;
        (fx, entry)
    }

    /// P1 regression (empirically confirmed vs a real pnpm@10.34.5 project,
    /// 2026-08-18): a `repair`-reconstructed entry carries no wiring
    /// records; revert used to remove the artifact dir unconditionally,
    /// leaving the lock resolving through a deleted tarball — every later
    /// install failed ENOENT, and nothing said so. With nothing to replay,
    /// revert must refuse (fail-closed) while the lock still resolves
    /// through the artifact.
    #[tokio::test]
    async fn empty_wiring_revert_refuses_while_lock_resolves_through_artifact() {
        let (fx, entry) = reconstructed_fixture().await;
        let tgz_path = fx.root().join(fx.rel_tgz());
        let lock_before = fx.read(PNPM_LOCK).await;

        // The dry-run preview must refuse too (same precedent as the uuid
        // grammar guard: never advertise a revert the wet run refuses).
        for dry_run in [true, false] {
            let outcome = revert_pnpm(&entry, fx.root(), dry_run).await;
            assert!(!outcome.success, "dry_run={dry_run}: must refuse");
            let err = outcome.error.as_deref().unwrap_or_default();
            assert!(err.contains("socket-patch repair"), "{err}");
            assert!(
                outcome
                    .warnings
                    .iter()
                    .any(|w| w.code == "vendor_wiring_unknown_revert_blocked"),
                "{:?}",
                outcome.warnings
            );
            assert!(tgz_path.exists(), "the artifact must survive the refusal");
            assert_eq!(fx.read(PNPM_LOCK).await, lock_before, "lock untouched");
        }
    }

    /// The flip side: when the lock provably no longer resolves through the
    /// artifact (dependency removed and re-locked; only the mirrored
    /// overrides declaration lingers), the empty-wiring revert keeps its
    /// pre-guard behavior and removes the genuinely orphaned artifact.
    #[tokio::test]
    async fn empty_wiring_revert_removes_a_genuinely_orphaned_artifact() {
        let (fx, entry) = reconstructed_fixture().await;
        let removed_lock = format!(
            "lockfileVersion: '9.0'\n\noverrides:\n  left-pad@1.3.0: file:{}\n\nimporters:\n\n  \
             .:\n    dependencies:\n      consumer:\n        specifier: file:./consumer\n        \
             version: file:consumer\n\npackages:\n\n  consumer@file:consumer:\n    \
             resolution: {{directory: consumer, type: directory}}\n\nsnapshots:\n\n  \
             consumer@file:consumer: {{}}\n",
            fx.rel_tgz()
        );
        tokio::fs::write(fx.root().join(PNPM_LOCK), &removed_lock)
            .await
            .unwrap();

        let outcome = revert_pnpm(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !fx.root()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "orphaned artifact dir removed"
        );
        assert_eq!(
            fx.read(PNPM_LOCK).await,
            removed_lock,
            "empty wiring replays nothing"
        );
    }

    /// Undeterminable lock (present but unsupported grammar): fail closed —
    /// it may still resolve through the artifact. A lock that is absent
    /// altogether cannot reference anything, so removal proceeds.
    #[tokio::test]
    async fn empty_wiring_revert_fails_closed_on_undeterminable_lock() {
        let (fx, entry) = reconstructed_fixture().await;
        let tgz_path = fx.root().join(fx.rel_tgz());

        tokio::fs::write(fx.root().join(PNPM_LOCK), "lockfileVersion: '6.0'\n")
            .await
            .unwrap();
        let outcome = revert_pnpm(&entry, fx.root(), false).await;
        assert!(!outcome.success, "unparseable-lock revert must refuse");
        assert!(tgz_path.exists());

        tokio::fs::remove_file(fx.root().join(PNPM_LOCK))
            .await
            .unwrap();
        let outcome = revert_pnpm(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(!tgz_path.exists(), "no lock, no reference: removal is safe");
    }

    // ── exact-version pin takeover ─────────────────────────────────────────

    /// package.json with a user-authored override pin (`key: value`) plus the
    /// matching lock-side `overrides:` mirror line.
    fn pin_fixture_inputs(key: &str, value: &str) -> (String, String) {
        let pkg = format!(
            "{{\n  \"name\": \"vendor-spike\",\n  \"version\": \"1.0.0\",\n  \"private\": true,\n  \"dependencies\": {{\n    \"consumer\": \"file:./consumer\",\n    \"left-pad\": \"1.3.0\",\n    \"left-pad-old\": \"npm:left-pad@1.2.0\"\n  }},\n  \"pnpm\": {{\n    \"overrides\": {{\n      \"{key}\": \"{value}\"\n    }}\n  }}\n}}\n"
        );
        let lock = P1_BEFORE_LOCK.replace(
            "importers:",
            &format!("overrides:\n  {key}: {value}\n\nimporters:"),
        );
        (pkg, lock)
    }

    /// A user-authored EXACT-version pin equal to the patched version is
    /// taken over: the user's key keeps its spelling on both surfaces, its
    /// value moves to our `file:` spec, the wiring records the pin as
    /// `original`, and a full revert restores both files byte-identically.
    #[tokio::test]
    async fn user_exact_pin_bare_key_is_taken_over_and_revert_restores_it() {
        let (pkg_before, lock_before) = pin_fixture_inputs("left-pad", "1.3.0");
        let fx = fixture_with(&pkg_before, &lock_before).await;

        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();

        // package.json: the USER'S key (`left-pad`) now carries our spec;
        // no `left-pad@1.3.0` key was added; tables pre-existed.
        let pkg: Value = serde_json::from_str(&fx.read(PACKAGE_JSON).await).unwrap();
        let overrides = &pkg["pnpm"]["overrides"];
        assert_eq!(
            overrides["left-pad"],
            Value::String(format!("file:{}", fx.rel_tgz()))
        );
        assert!(overrides.get("left-pad@1.3.0").is_none());
        assert_eq!(
            entry.pnpm,
            Some(PnpmMeta {
                created_workspace_file: true,
                ..Default::default()
            })
        );

        // Lock: same key, same value (map parity — pnpm hard-checks it).
        let live_lock = fx.read(PNPM_LOCK).await;
        assert!(
            live_lock.contains(&format!("overrides:\n  left-pad: file:{}", fx.rel_tgz())),
            "{live_lock}"
        );

        // Wiring: both override records carry the user's key, action
        // Rewritten, and the pin as `original`.
        for kind in [KIND_PKG_OVERRIDE, KIND_LOCK_OVERRIDES] {
            let rec = entry
                .wiring
                .iter()
                .find(|r| r.kind == kind)
                .unwrap_or_else(|| panic!("no {kind} record: {:?}", entry.wiring));
            assert_eq!(rec.key.as_deref(), Some("left-pad"), "{kind}");
            assert_eq!(rec.action, WiringAction::Rewritten, "{kind}");
            assert_eq!(
                rec.original,
                Some(Value::String("1.3.0".to_string())),
                "{kind}: the user's pin is the original"
            );
        }

        // Full revert restores the pin on both surfaces byte-identically.
        let outcome = revert_pnpm(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(fx.read(PACKAGE_JSON).await, pkg_before);
        assert_eq!(fx.read(PNPM_LOCK).await, lock_before);
    }

    /// The versioned key shape (`left-pad@1.3.0: 1.3.0`) is taken over the
    /// same way — the key happens to equal our canonical key.
    #[tokio::test]
    async fn user_exact_pin_versioned_key_is_taken_over() {
        let (pkg_before, lock_before) = pin_fixture_inputs("left-pad@1.3.0", "1.3.0");
        let fx = fixture_with(&pkg_before, &lock_before).await;

        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();

        let pkg: Value = serde_json::from_str(&fx.read(PACKAGE_JSON).await).unwrap();
        assert_eq!(
            pkg["pnpm"]["overrides"]["left-pad@1.3.0"],
            Value::String(format!("file:{}", fx.rel_tgz()))
        );
        let rec = entry
            .wiring
            .iter()
            .find(|r| r.kind == KIND_PKG_OVERRIDE)
            .unwrap();
        assert_eq!(rec.original, Some(Value::String("1.3.0".to_string())));

        // Revert restores the pin.
        let outcome = revert_pnpm(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(fx.read(PACKAGE_JSON).await, pkg_before);
        assert_eq!(fx.read(PNPM_LOCK).await, lock_before);
    }

    /// A second vendor over a taken-over key is the in-sync hot path:
    /// AlreadyPatched, no new ledger entry, bytes stable. (Guards the
    /// `Ours` classification accepting the user-keyed vendor value — the
    /// old `key == our_key` requirement would refuse its own wiring.)
    #[tokio::test]
    async fn takeover_rerun_is_in_sync_and_records_nothing() {
        let (pkg_before, lock_before) = pin_fixture_inputs("left-pad", "1.3.0");
        let fx = fixture_with(&pkg_before, &lock_before).await;
        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());
        let pkg_after = fx.read(PACKAGE_JSON).await;
        let lock_after = fx.read(PNPM_LOCK).await;

        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_none(), "in-sync rerun records nothing");
        assert!(result
            .files_verified
            .iter()
            .all(|v| v.status == crate::patch::apply::VerifyStatus::AlreadyPatched));
        assert_eq!(fx.read(PACKAGE_JSON).await, pkg_after, "bytes stable");
        assert_eq!(fx.read(PNPM_LOCK).await, lock_after, "bytes stable");
    }

    /// Selector chains and duplicate same-name keys still refuse — only a
    /// plain exact pin is taken over. (Range keys and different-version
    /// values are covered by `existing_user_override_for_the_name_is_refused`.)
    #[tokio::test]
    async fn chain_and_duplicate_override_keys_still_refuse() {
        // `parent>child` chain, even with the exact version value.
        let (pkg, lock) = pin_fixture_inputs("consumer>left-pad", "1.3.0");
        let fx = fixture_with(&pkg, &lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_override_conflict");
        assert!(detail.contains("consumer>left-pad"), "{detail}");

        // Two same-name keys (one ours-shaped pin + one bare pin).
        let pkg = "{\n  \"name\": \"x\",\n  \"pnpm\": {\n    \"overrides\": {\n      \"left-pad\": \"1.3.0\",\n      \"left-pad@1.3.0\": \"1.3.0\"\n    }\n  }\n}\n".to_string();
        let fx = fixture_with(&pkg, P1_BEFORE_LOCK).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_override_conflict");
        assert!(detail.contains("more than one"), "{detail}");
    }

    /// pkg↔lock override-key shape drift refuses (pnpm itself would fail
    /// `ERR_PNPM_LOCKFILE_CONFIG_MISMATCH`); a pkg-side pin with NO lock
    /// mirror is fine — the edit inserts the same key, restoring parity.
    #[tokio::test]
    async fn takeover_lock_shape_mismatch_refuses_but_missing_section_inserts() {
        // Shape drift: pkg keys `left-pad`, lock keys `left-pad@1.3.0`.
        let (pkg, _) = pin_fixture_inputs("left-pad", "1.3.0");
        let lock = P1_BEFORE_LOCK.replace(
            "importers:",
            "overrides:\n  left-pad@1.3.0: 1.3.0\n\nimporters:",
        );
        let fx = fixture_with(&pkg, &lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_override_conflict");
        assert!(detail.contains("must"), "{detail}");

        // No lock overrides section at all: takeover inserts the pkg key.
        let fx = fixture_with(&pkg, P1_BEFORE_LOCK).await;
        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        let live_lock = fx.read(PNPM_LOCK).await;
        assert!(
            live_lock.contains(&format!("overrides:\n  left-pad: file:{}", fx.rel_tgz())),
            "lock key matches the pkg key: {live_lock}"
        );
        assert!(entry.is_some());
    }

    #[tokio::test]
    async fn created_tables_bookkeeping_and_revert_prunes_them() {
        // pnpm table exists (other keys), overrides created by us: revert
        // must remove the emptied overrides table but KEEP the pnpm table.
        let pkg = r#"{
  "name": "x",
  "dependencies": { "left-pad": "1.3.0" },
  "pnpm": {
    "onlyBuiltDependencies": []
  }
}
"#;
        let fx = fixture_with(pkg, P1_BEFORE_LOCK).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        assert_eq!(
            entry.pnpm,
            Some(PnpmMeta {
                created_overrides_table: true,
                created_workspace_file: true,
                ..Default::default()
            })
        );

        let outcome = revert_pnpm(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        let live: Value = serde_json::from_str(&fx.read(PACKAGE_JSON).await).unwrap();
        assert!(
            live["pnpm"].get("overrides").is_none(),
            "created overrides table pruned"
        );
        assert!(
            live["pnpm"].get("onlyBuiltDependencies").is_some(),
            "pre-existing pnpm table kept: {live}"
        );

        // Both created (P1): revert prunes pnpm entirely → byte round-trip.
        let fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let outcome = revert_pnpm(&entry.unwrap(), fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(fx.read(PACKAGE_JSON).await, P1_BEFORE_PKG);
    }

    #[tokio::test]
    async fn commit_surfaces_unwinds_override_surfaces_on_lock_write_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::write(root.join(PACKAGE_JSON), P1_BEFORE_PKG)
            .await
            .unwrap();
        // A directory where the lock should be makes the atomic rename fail
        // AFTER package.json and a freshly created pnpm-workspace.yaml were
        // written.
        tokio::fs::create_dir(root.join(PNPM_LOCK)).await.unwrap();

        let err = commit_surfaces(
            root,
            Some(P1_AFTER_PKG.as_bytes()),
            P1_BEFORE_PKG.as_bytes(),
            Some(b"overrides:\n  x: y\n"),
            None,
            true, // ws created from scratch → unwind deletes it
            Some(b"lock bytes"),
        )
        .await
        .unwrap_err();
        assert!(err.contains(PNPM_LOCK), "{err}");
        assert_eq!(
            tokio::fs::read_to_string(root.join(PACKAGE_JSON))
                .await
                .unwrap(),
            P1_BEFORE_PKG,
            "package.json restored byte-for-byte after the lock failure"
        );
        assert!(
            !root.join(PNPM_WORKSPACE).exists(),
            "the created pnpm-workspace.yaml is deleted on unwind"
        );
    }

    #[tokio::test]
    async fn rerun_is_in_sync_and_byte_stable() {
        let fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        assert!(entry.is_some());
        let pkg_first = fx.read(PACKAGE_JSON).await;
        let lock_first = fx.read(PNPM_LOCK).await;
        let tgz_first = tokio::fs::read(fx.root().join(fx.rel_tgz())).await.unwrap();

        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success);
        assert!(entry.is_none(), "in-sync re-run records nothing");
        assert!(
            result
                .files_verified
                .iter()
                .all(|v| v.status == VerifyStatus::AlreadyPatched),
            "{:?}",
            result.files_verified
        );
        assert_eq!(fx.read(PACKAGE_JSON).await, pkg_first);
        assert_eq!(fx.read(PNPM_LOCK).await, lock_first);
        assert_eq!(
            tokio::fs::read(fx.root().join(fx.rel_tgz())).await.unwrap(),
            tgz_first,
            "tarball byte-identical across re-runs"
        );
    }

    /// A half-edited lock carrying BOTH the registry-keyed packages entry
    /// AND a socket file:-keyed one: a rekey would splice a DUPLICATE
    /// mapping key (pnpm refuses to parse those) — fail closed, nothing
    /// written.
    #[tokio::test]
    async fn half_drifted_duplicate_keys_fail_closed() {
        let dup_lock = P1_BEFORE_LOCK.replace(
            "  left-pad@1.3.0:\n    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==}\n    deprecated: use String.prototype.padStart()",
            &format!(
                "  left-pad@1.3.0:\n    resolution: {{integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==}}\n    deprecated: use String.prototype.padStart()\n\n  left-pad@file:.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz:\n    resolution: {{integrity: sha512-stale==, tarball: file:.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz}}\n    version: 1.3.0"
            ),
        );
        assert_ne!(dup_lock, P1_BEFORE_LOCK, "fixture edit must apply");
        let fx = fixture_with(P1_BEFORE_PKG, &dup_lock).await;
        let lock_before = fx.read(PNPM_LOCK).await;
        let pkg_before = fx.read(PACKAGE_JSON).await;

        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(!result.success, "half-drifted lock must fail closed");
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|e| e.contains("half-edited lock")),
            "{:?}",
            result.error
        );
        assert!(entry.is_none());
        assert_eq!(fx.read(PNPM_LOCK).await, lock_before, "lock untouched");
        assert_eq!(fx.read(PACKAGE_JSON).await, pkg_before, "pkg untouched");
    }

    /// Two VERSIONS of the same package vendored in sequence: each edit
    /// must bind to its own version's entries — a name-only "ours" match
    /// would let the second vendor clobber/rekey the first one's blocks
    /// (live-debugged on Flowise: identical duplicated mapping keys).
    /// 1.2.0 is reachable through a transitive dependent's snapshot ref
    /// (the Flowise shape) — the P1 `npm:` ALIAS shape now refuses
    /// fail-closed instead (see
    /// `aliased_same_version_reference_refuses_fail_closed`; the surgery
    /// cannot rewrite alias dep paths and used to strand them dangling).
    #[tokio::test]
    async fn multi_version_vendor_does_not_clobber_sibling_entries() {
        // P1 with the `left-pad-old` alias swapped for a `dep-two`
        // dependent whose snapshot pulls left-pad@1.2.0 transitively.
        let pkg = P1_BEFORE_PKG.replace(
            "\"left-pad-old\": \"npm:left-pad@1.2.0\"",
            "\"dep-two\": \"1.0.0\"",
        );
        assert_ne!(pkg, P1_BEFORE_PKG);
        let lock = P1_BEFORE_LOCK
            .replace(
                "      left-pad-old:\n        specifier: npm:left-pad@1.2.0\n        version: left-pad@1.2.0",
                "      dep-two:\n        specifier: 1.0.0\n        version: 1.0.0",
            )
            .replace(
                "  left-pad@1.2.0:\n    resolution: {integrity: sha512-OQadpCyF",
                "  dep-two@1.0.0:\n    resolution: {integrity: sha512-depTwo==}\n\n  left-pad@1.2.0:\n    resolution: {integrity: sha512-OQadpCyF",
            )
            .replace(
                "  left-pad@1.2.0: {}",
                "  dep-two@1.0.0:\n    dependencies:\n      left-pad: 1.2.0\n\n  left-pad@1.2.0: {}",
            );
        assert_ne!(lock, P1_BEFORE_LOCK);
        let fx = fixture_with(&pkg, &lock).await;
        let (r1, e1, _) = expect_done(fx.vendor(false).await);
        assert!(r1.success, "{:?}", r1.error);
        assert!(e1.is_some());
        let tgz_13 = fx.rel_tgz();

        // Vendor left-pad@1.2.0 under a DIFFERENT uuid.
        let uuid2 = "22222222-3333-4444-8555-666666666666";
        let installed2 = fx.root().join("node_modules/dep-two/node_modules/left-pad");
        tokio::fs::create_dir_all(&installed2).await.unwrap();
        tokio::fs::write(
            installed2.join("package.json"),
            br#"{"name":"left-pad","version":"1.2.0"}"#,
        )
        .await
        .unwrap();
        tokio::fs::write(installed2.join("index.js"), ORIG_INDEX)
            .await
            .unwrap();
        let mut record2 = fx.record.clone();
        record2.uuid = uuid2.to_string();
        let blobs = fx.root().join(".socket/blobs");
        let sources = PatchSources::blobs_only(&blobs);
        let outcome = vendor_pnpm(
            "pkg:npm/left-pad@1.2.0",
            &installed2,
            fx.root(),
            &record2,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            None,
        )
        .await;
        let (r2, e2, _) = expect_done(outcome);
        assert!(r2.success, "{:?}", r2.error);
        assert!(e2.is_some());

        let lock = fx.read(PNPM_LOCK).await;
        let key13 = format!("  left-pad@file:{tgz_13}:");
        let key12 = format!("  left-pad@file:.socket/vendor/npm/{uuid2}/left-pad-1.2.0.tgz:");
        // dep-two's transitive snapshot ref moved to the bare file form.
        assert!(
            lock.contains(&format!(
                "      left-pad: file:.socket/vendor/npm/{uuid2}/left-pad-1.2.0.tgz"
            )),
            "transitive 1.2.0 ref rewritten:\n{lock}"
        );
        // Both versions' packages + snapshots blocks exist exactly once
        // each (snapshot entries may be inline `key: {}`).
        for (key, label) in [(&key13, "1.3.0"), (&key12, "1.2.0")] {
            assert_eq!(
                lock.lines().filter(|l| l.starts_with(key.as_str())).count(),
                2, // packages + snapshots
                "{label} entries intact:\n{lock}"
            );
        }
        // No duplicated mapping keys within a section (what pnpm
        // hard-rejects): each section's 2-space keys are unique.
        for section in ["overrides", "packages", "snapshots"] {
            let Some((start, end)) = section_bounds(&split_lines(&lock), section) else {
                continue;
            };
            let lines = split_lines(&lock);
            let mut keys: Vec<String> = lines[start + 1..end]
                .iter()
                .filter_map(|l| parse_key_line(l, 2).map(|(k, _, _)| k))
                .collect();
            let total = keys.len();
            keys.sort_unstable();
            keys.dedup();
            assert_eq!(total, keys.len(), "duplicated keys in {section}:\n{lock}");
        }
    }

    /// Re-vendor over a wired lock whose recorded integrity DRIFTED (e.g.
    /// the artifact was rebuilt from a differently-shaped source): the
    /// stale-ours refresh must REPLACE the file:-keyed blocks, never
    /// duplicate them.
    #[tokio::test]
    async fn integrity_drift_refresh_never_duplicates_keys() {
        let fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        assert!(entry.is_some());

        // Simulate drift: the lock records a DIFFERENT integrity for OUR
        // file: entry (only) than the tarball the next run will pack.
        let lock = fx.read(PNPM_LOCK).await;
        let drifted = lock
            .lines()
            .map(|l| {
                if l.contains("tarball: file:.socket") {
                    l.replace("integrity: sha512-", "integrity: sha512-DRIFT")
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert_ne!(drifted, lock);
        tokio::fs::write(fx.root().join(PNPM_LOCK), &drifted)
            .await
            .unwrap();

        let (result, _, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        let healed = fx.read(PNPM_LOCK).await;
        let ours_key = format!("  left-pad@file:{}:", fx.rel_tgz());
        let count = healed.lines().filter(|l| *l == ours_key.as_str()).count();
        assert_eq!(
            count, 1,
            "exactly one file:-keyed packages/snapshots block per section; lock:
{healed}"
        );
        let snap_count = healed
            .matches(&format!("left-pad@file:{}", fx.rel_tgz()))
            .count();
        assert!(
            !healed.contains("sha512-DRIFT"),
            "drifted integrity healed: {snap_count} refs
{healed}"
        );
    }

    /// The pair are user-owned files the surgery merely edits: vendor and
    /// revert writes must keep their permission bits (a 0600 private lock
    /// must not silently become umask-default 0644) — same contract as
    /// npm_lock's `lock_writes_preserve_file_mode`.
    #[cfg(unix)]
    #[tokio::test]
    async fn pair_writes_preserve_file_modes() {
        use std::os::unix::fs::PermissionsExt;
        let fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        tokio::fs::set_permissions(
            fx.root().join(PNPM_LOCK),
            std::fs::Permissions::from_mode(0o600),
        )
        .await
        .unwrap();
        tokio::fs::set_permissions(
            fx.root().join(PACKAGE_JSON),
            std::fs::Permissions::from_mode(0o640),
        )
        .await
        .unwrap();
        let mode_of = |name: &str| {
            let path = fx.root().join(name);
            async move {
                tokio::fs::metadata(path)
                    .await
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777
            }
        };

        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();
        assert_eq!(mode_of(PNPM_LOCK).await, 0o600, "vendor: lock mode kept");
        assert_eq!(mode_of(PACKAGE_JSON).await, 0o640, "vendor: pkg mode kept");

        let outcome = revert_pnpm(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(mode_of(PNPM_LOCK).await, 0o600, "revert: lock mode kept");
        assert_eq!(mode_of(PACKAGE_JSON).await, 0o640, "revert: pkg mode kept");
    }

    /// A lock referencing the target through a PEER-SUFFIXED dep path
    /// (`left-pad@1.3.0(react@18.2.0)` — what pnpm emits whenever the
    /// package has peerDependencies): the surgery rewrites only the plain
    /// registry forms, so proceeding would rekey the `packages:` entry
    /// while the suffixed snapshot key and importer version keep pointing
    /// at the now-missing `left-pad@1.3.0` — a lock pnpm hard-rejects.
    /// Must refuse fail-closed BEFORE anything is staged or written.
    #[tokio::test]
    async fn peer_suffixed_target_refuses_fail_closed() {
        let peer_lock = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      left-pad:
        specifier: 1.3.0
        version: 1.3.0(react@18.2.0)
      react:
        specifier: 18.2.0
        version: 18.2.0

packages:

  left-pad@1.3.0:
    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==}
    peerDependencies:
      react: '>=16'

  react@18.2.0:
    resolution: {integrity: sha512-reactreactreactreactreactreactreactreactreactreactreactreactreactreactreactreactreactre==}

snapshots:

  left-pad@1.3.0(react@18.2.0):
    dependencies:
      react: 18.2.0

  react@18.2.0: {}
";
        let fx = fixture_with(P1_BEFORE_PKG, peer_lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_unsupported");
        assert!(detail.contains("left-pad@1.3.0(react@18.2.0)"), "{detail}");
        assert_eq!(fx.read(PNPM_LOCK).await, peer_lock, "lock untouched");
        assert_eq!(fx.read(PACKAGE_JSON).await, P1_BEFORE_PKG, "pkg untouched");
        assert!(
            !fx.root().join(".socket/vendor").exists(),
            "refusal stages nothing"
        );
    }

    /// A lock referencing the target through an ALIAS at the exact patched
    /// version (`renamed-pad: npm:left-pad@1.3.0` → `version: left-pad@1.3.0`,
    /// same for snapshot dep refs): the surgery leaves those spellings
    /// verbatim, so the rekey would strand them pointing at a
    /// packages/snapshots entry that no longer exists. Must refuse
    /// fail-closed, nothing staged or written.
    #[tokio::test]
    async fn aliased_same_version_reference_refuses_fail_closed() {
        // Importer-level alias.
        let importer_alias_lock = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      left-pad:
        specifier: 1.3.0
        version: 1.3.0
      renamed-pad:
        specifier: npm:left-pad@1.3.0
        version: left-pad@1.3.0

packages:

  left-pad@1.3.0:
    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==}

snapshots:

  left-pad@1.3.0: {}
";
        let fx = fixture_with(P1_BEFORE_PKG, importer_alias_lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_unsupported");
        assert!(detail.contains("left-pad@1.3.0"), "{detail}");
        assert_eq!(fx.read(PNPM_LOCK).await, importer_alias_lock);
        assert!(!fx.root().join(".socket/vendor").exists());

        // Snapshot-level alias ref inside a dependent's block.
        let snapshot_alias_lock = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      host:
        specifier: 1.0.0
        version: 1.0.0
      left-pad:
        specifier: 1.3.0
        version: 1.3.0

packages:

  host@1.0.0:
    resolution: {integrity: sha512-hosthosthosthosthosthosthosthosthosthosthosthosthosthosthosthosthosthosthosthosthosthos==}

  left-pad@1.3.0:
    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==}

snapshots:

  host@1.0.0:
    dependencies:
      renamed-pad: left-pad@1.3.0

  left-pad@1.3.0: {}
";
        let fx = fixture_with(P1_BEFORE_PKG, snapshot_alias_lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_unsupported");
        assert!(detail.contains("left-pad@1.3.0"), "{detail}");
        assert_eq!(fx.read(PNPM_LOCK).await, snapshot_alias_lock);
        assert!(!fx.root().join(".socket/vendor").exists());
    }

    /// package.json declaring the dep through a pnpm catalog. Lock oracles
    /// generated by real pnpm (v11.21.0) from `"left-pad": "catalog:"` +
    /// pnpm-workspace.yaml `catalog:` — the importer carries
    /// `specifier: 'catalog:'` and the lock a top-level `catalogs:`
    /// snapshot. The surgery cannot rewrite these (the range lives in
    /// pnpm-workspace.yaml, outside the pair): rewriting the importer to
    /// `file:` was empirically confirmed to make `pnpm install
    /// --frozen-lockfile` fail with ERR_PNPM_OUTDATED_LOCKFILE. Must refuse
    /// fail-closed BEFORE anything is staged or written.
    #[tokio::test]
    async fn catalog_consumed_target_refuses_fail_closed() {
        let catalog_pkg = r#"{
  "name": "vendor-spike",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "left-pad": "catalog:"
  }
}
"#;
        // Default catalog (importer specifier is the quoted `'catalog:'`).
        let default_catalog_lock = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

catalogs:
  default:
    left-pad:
      specifier: ^1.3.0
      version: 1.3.0

importers:

  .:
    dependencies:
      left-pad:
        specifier: 'catalog:'
        version: 1.3.0

packages:

  left-pad@1.3.0:
    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==}
    deprecated: use String.prototype.padStart()

snapshots:

  left-pad@1.3.0: {}
";
        let fx = fixture_with(catalog_pkg, default_catalog_lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_unsupported");
        assert!(detail.contains("catalog"), "{detail}");
        assert!(detail.contains("pnpm-workspace.yaml"), "{detail}");
        assert_eq!(
            fx.read(PNPM_LOCK).await,
            default_catalog_lock,
            "lock untouched"
        );
        assert_eq!(fx.read(PACKAGE_JSON).await, catalog_pkg, "pkg untouched");
        assert!(
            !fx.root().join(".socket/vendor").exists(),
            "refusal stages nothing"
        );

        // Named catalog (bare `catalog:tools` specifier, real-pnpm spelling).
        let named_catalog_lock = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

catalogs:
  tools:
    left-pad:
      specifier: ^1.3.0
      version: 1.3.0

importers:

  .:
    dependencies:
      left-pad:
        specifier: catalog:tools
        version: 1.3.0

packages:

  left-pad@1.3.0:
    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==}
    deprecated: use String.prototype.padStart()

snapshots:

  left-pad@1.3.0: {}
";
        let fx = fixture_with(catalog_pkg, named_catalog_lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_unsupported");
        assert!(detail.contains("catalog"), "{detail}");
        assert_eq!(
            fx.read(PNPM_LOCK).await,
            named_catalog_lock,
            "lock untouched"
        );
        assert!(!fx.root().join(".socket/vendor").exists());

        // Drifted shape: catalog importer specifier WITHOUT a `catalogs:`
        // section — the importer-side guard must refuse on its own.
        let importer_only_lock = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      left-pad:
        specifier: 'catalog:'
        version: 1.3.0

packages:

  left-pad@1.3.0:
    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==}
    deprecated: use String.prototype.padStart()

snapshots:

  left-pad@1.3.0: {}
";
        let fx = fixture_with(catalog_pkg, importer_only_lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_unsupported");
        assert!(detail.contains("catalog"), "{detail}");
        assert_eq!(
            fx.read(PNPM_LOCK).await,
            importer_only_lock,
            "lock untouched"
        );
        assert!(!fx.root().join(".socket/vendor").exists());
    }

    /// A catalog resolving a SIBLING version (1.2.0) must not block
    /// vendoring 1.3.0 consumed through a plain specifier: the guard binds
    /// to the exact target version, and the sibling's catalog wiring stays
    /// valid because its `left-pad@1.2.0` packages entry is never rekeyed.
    #[test]
    fn sibling_version_catalog_entry_does_not_block_vendoring() {
        let lock = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

catalogs:
  default:
    left-pad:
      specifier: ^1.2.0
      version: 1.2.0

importers:

  .:
    dependencies:
      left-pad:
        specifier: 1.3.0
        version: 1.3.0

  packages/legacy:
    dependencies:
      left-pad:
        specifier: 'catalog:'
        version: 1.2.0

packages:

  left-pad@1.2.0:
    resolution: {integrity: sha512-OQadpCyFCT/VLniZQgym8d3/ofIJtuZyw2ibsVeIUOexKgW/osn8+mMFJbwGMPeDC4GnLzD8q115WPCDx4YRWg==}

  left-pad@1.3.0:
    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==}

snapshots:

  left-pad@1.2.0: {}

  left-pad@1.3.0: {}
";
        assert!(
            check_rewritable_refs(&split_lines(lock), "left-pad", "1.3.0").is_ok(),
            "sibling-version catalog must not refuse the plain 1.3.0 target"
        );
        let refused = check_rewritable_refs(&split_lines(lock), "left-pad", "1.2.0")
            .expect_err("the catalog-consumed 1.2.0 itself must refuse");
        assert!(refused.contains("catalog"), "{refused}");
    }

    /// A lock whose ONLY same-name entry is a SIBLING version's vendored
    /// key (`left-pad@file:…/left-pad-1.2.0.tgz` while vendoring 1.3.0)
    /// has no entry the surgery can target: pre-flight must refuse
    /// `vendor_lock_entry_not_found` BEFORE staging, not pass a
    /// version-blind ours-probe and then die mid-surgery with a
    /// misleading "vanished mid-rewrite" error + an orphaned artifact dir.
    #[tokio::test]
    async fn sibling_only_vendored_lock_refuses_entry_not_found() {
        let uuid2 = "22222222-3333-4444-8555-666666666666";
        let tgz12 = format!(".socket/vendor/npm/{uuid2}/left-pad-1.2.0.tgz");
        let pkg = format!(
            "{{\n  \"name\": \"x\",\n  \"dependencies\": {{\n    \"left-pad\": \"1.2.0\"\n  }},\n  \"pnpm\": {{\n    \"overrides\": {{\n      \"left-pad@1.2.0\": \"file:{tgz12}\"\n    }}\n  }}\n}}\n"
        );
        let lock = format!(
            "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

overrides:
  left-pad@1.2.0: file:{tgz12}

importers:

  .:
    dependencies:
      left-pad:
        specifier: file:{tgz12}
        version: file:{tgz12}

packages:

  left-pad@file:{tgz12}:
    resolution: {{integrity: sha512-sibling==, tarball: file:{tgz12}}}
    version: 1.2.0

snapshots:

  left-pad@file:{tgz12}: {{}}
"
        );
        let fx = fixture_with(&pkg, &lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_not_found");
        assert!(detail.contains("left-pad@1.3.0"), "{detail}");
        assert_eq!(fx.read(PNPM_LOCK).await, lock, "lock untouched");
        assert!(
            !fx.root()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "refusal stages no artifact"
        );
    }

    /// A CRLF pnpm-lock.yaml (Windows autocrlf checkout) passes the version
    /// sniff (`str::lines` strips `\r`) but breaks every structural probe —
    /// the refusal must name the line endings as the cause, not the
    /// misleading "no packages entry … run `pnpm install`".
    #[tokio::test]
    async fn crlf_lock_refuses_naming_line_endings() {
        let crlf_lock = P1_BEFORE_LOCK.replace('\n', "\r\n");
        let fx = fixture_with(P1_BEFORE_PKG, &crlf_lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lockfile_crlf_unsupported");
        assert!(detail.contains("CRLF"), "{detail}");
        assert!(
            !detail.contains("make sure the package is installed"),
            "no misleading install remedy: {detail}"
        );
        assert_eq!(fx.read(PNPM_LOCK).await, crlf_lock, "lock untouched");
        assert_eq!(fx.read(PACKAGE_JSON).await, P1_BEFORE_PKG, "pkg untouched");
        assert!(
            !fx.root().join(".socket/vendor").exists(),
            "refusal stages no artifact"
        );
    }

    #[tokio::test]
    async fn dry_run_writes_nothing() {
        let fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        let (result, entry, _) = expect_done(fx.vendor(true).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_none());
        assert!(result.files_patched.is_empty());

        assert_eq!(fx.read(PACKAGE_JSON).await, P1_BEFORE_PKG);
        assert_eq!(fx.read(PNPM_LOCK).await, P1_BEFORE_LOCK);
        assert!(!fx.root().join(".socket/vendor").exists());
        assert_eq!(
            tokio::fs::read(fx.installed().join("index.js"))
                .await
                .unwrap(),
            ORIG_INDEX,
            "vendor never patches in place"
        );
    }

    #[tokio::test]
    async fn revert_round_trips_both_files_and_removes_the_artifact() {
        let fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let tgz_path = fx.root().join(fx.rel_tgz());
        assert!(tgz_path.exists());

        // Dry-run revert touches nothing.
        let outcome = revert_pnpm(&entry, fx.root(), true).await;
        assert!(outcome.success);
        assert!(tgz_path.exists());
        assert_ne!(fx.read(PNPM_LOCK).await, P1_BEFORE_LOCK);

        let outcome = revert_pnpm(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert_eq!(
            fx.read(PACKAGE_JSON).await,
            P1_BEFORE_PKG,
            "package.json byte-restored"
        );
        assert_eq!(
            fx.read(PNPM_LOCK).await,
            P1_BEFORE_LOCK,
            "lock byte-restored"
        );
        assert!(!tgz_path.exists());
        assert!(!fx
            .root()
            .join(format!(".socket/vendor/npm/{UUID}"))
            .exists());
    }

    #[tokio::test]
    async fn revert_allowlist_is_fail_closed() {
        let fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let mut entry = entry.unwrap();
        // A poisoned ledger names a file outside the pair.
        tokio::fs::write(fx.root().join("Cargo.toml"), b"[package]\n")
            .await
            .unwrap();
        entry.wiring.push(WiringRecord {
            file: "Cargo.toml".to_string(),
            kind: KIND_LOCK_OVERRIDES.to_string(),
            action: WiringAction::Added,
            key: Some("left-pad@1.3.0".to_string()),
            original: None,
            new: Some(Value::String("evil".to_string())),
        });

        let outcome = revert_pnpm(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted" && w.detail.contains("Cargo.toml")),
            "{:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read(fx.root().join("Cargo.toml")).await.unwrap(),
            b"[package]\n",
            "non-allowlisted file never touched"
        );
        // And the real pair still round-tripped.
        assert_eq!(fx.read(PNPM_LOCK).await, P1_BEFORE_LOCK);
    }

    #[tokio::test]
    async fn revert_leaves_drifted_fragments_alone_with_warnings() {
        let fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();

        // The user re-resolved the importer dep behind our back.
        let live = fx.read(PNPM_LOCK).await;
        let drifted_lock = live.replace(
            &format!(
                "      left-pad:\n        specifier: file:{rel}\n        version: file:{rel}\n",
                rel = fx.rel_tgz()
            ),
            "      left-pad:\n        specifier: 1.3.1\n        version: 1.3.1\n",
        );
        assert_ne!(
            drifted_lock, live,
            "test setup must actually drift the entry"
        );
        tokio::fs::write(fx.root().join(PNPM_LOCK), &drifted_lock)
            .await
            .unwrap();

        let outcome = revert_pnpm(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted" && w.detail.contains(".|left-pad")),
            "{:?}",
            outcome.warnings
        );
        let after = fx.read(PNPM_LOCK).await;
        assert!(
            after.contains("        specifier: 1.3.1\n        version: 1.3.1\n"),
            "drifted importer dep left alone: {after}"
        );
        // Non-drifted fragments still restored.
        assert!(after.contains("  left-pad@1.3.0:\n    resolution: {integrity: sha512-XI5MPzVN"));
        // Residual #131: a drift-skip keeps the artifact dir (the drifted
        // fragment's recorded original may still be needed later) and says so.
        assert!(
            fx.root()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "drift-skip must keep the artifact dir"
        );
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_artifact_kept"),
            "the keep must be surfaced: {:?}",
            outcome.warnings
        );

        // KEEP-GATE LIVENESS: undo ONLY the drift (repoint the importer dep
        // back at the vendored spec). Everything the first revert already
        // restored — the rekeyed packages/snapshots blocks and the removed
        // overrides — must now read as CONVERGED, not drifted; otherwise
        // every later revert would re-classify it as drift and keep the
        // artifacts + ledger entry forever.
        let healed = after.replace(
            "      left-pad:\n        specifier: 1.3.1\n        version: 1.3.1\n",
            &format!(
                "      left-pad:\n        specifier: file:{rel}\n        version: file:{rel}\n",
                rel = fx.rel_tgz()
            ),
        );
        assert_ne!(healed, after, "the undo edit must hit");
        tokio::fs::write(fx.root().join(PNPM_LOCK), &healed)
            .await
            .unwrap();

        let outcome = revert_pnpm(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome.warnings.is_empty(),
            "already-reverted fragments are converged, not drifted: {:?}",
            outcome.warnings
        );
        assert!(!outcome.kept_artifact);
        assert_eq!(
            fx.read(PNPM_LOCK).await,
            P1_BEFORE_LOCK,
            "lock byte-restored"
        );
        assert_eq!(
            fx.read(PACKAGE_JSON).await,
            P1_BEFORE_PKG,
            "package.json byte-restored"
        );
        assert!(
            !fx.root()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "artifact pruned once the revert converges"
        );
    }

    #[tokio::test]
    async fn preflight_refusals_fire_before_any_write() {
        // Missing lock.
        let fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        tokio::fs::remove_file(fx.root().join(PNPM_LOCK))
            .await
            .unwrap();
        let detail = expect_refused(fx.vendor(false).await, "vendor_lockfile_missing");
        assert!(detail.contains("pnpm install"), "{detail}");

        // Unsupported lockfileVersion.
        let fx = fixture_with(P1_BEFORE_PKG, &P1_BEFORE_LOCK.replace("'9.0'", "'6.0'")).await;
        let detail = expect_refused(
            fx.vendor(false).await,
            "vendor_lockfile_version_unsupported",
        );
        assert!(detail.contains("6.0"), "{detail}");

        // Missing package.json (the PAIR requirement).
        let fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        tokio::fs::remove_file(fx.root().join(PACKAGE_JSON))
            .await
            .unwrap();
        expect_refused(fx.vendor(false).await, "vendor_lockfile_missing");

        // Lock knows only another version of the package.
        let lock = P1_BEFORE_LOCK.replace("1.3.0", "1.4.0");
        let fx = fixture_with(P1_BEFORE_PKG, &lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_not_found");
        assert!(detail.contains("left-pad@1.3.0"), "{detail}");
        assert!(
            !fx.root().join(".socket/vendor").exists(),
            "refusals write nothing"
        );
    }

    /// The unsupported-version remedy must point the right way. The router
    /// sniff is now the ALLOWLIST `sniff_lock_grammar` (5.4 / 6.0 / 9.0 —
    /// the legacy grammars route to their own backend instead of refusing),
    /// so the remedy assertions moved onto it: pre-allowlist locks (pnpm
    /// <= 6's 5.x line) are fixed by upgrading pnpm, but a FUTURE lock
    /// version means pnpm already outgrew this build — "re-lock with
    /// pnpm >= 9" would loop those users back to the lock they have.
    #[test]
    fn lock_version_remedy_is_version_aware() {
        use super::super::pnpm_lock_legacy::{sniff_lock_grammar, PnpmLockGrammar};

        assert!(check_lock_version("lockfileVersion: '9.0'\n").is_ok());
        assert_eq!(
            sniff_lock_grammar("lockfileVersion: '9.0'\n"),
            Ok(PnpmLockGrammar::V9)
        );

        // The legacy grammars are ALLOWLISTED now (pnpm 7's bare-float 5.4,
        // pnpm 8's quoted 6.0): the router routes them to the legacy
        // backend rather than refusing.
        assert_eq!(
            sniff_lock_grammar("lockfileVersion: 5.4\n"),
            Ok(PnpmLockGrammar::V54)
        );
        assert_eq!(
            sniff_lock_grammar("lockfileVersion: '6.0'\n"),
            Ok(PnpmLockGrammar::V60)
        );
        // …while the v9 BACKEND's own guard still holds them out (they can
        // only reach `vendor_pnpm` through a router bug).
        for head in ["lockfileVersion: 5.4\n", "lockfileVersion: '6.0'\n"] {
            assert!(check_lock_version(head).is_err(), "{head}");
        }

        // Too old for the allowlist (pnpm 6's 5.3): upgrade pnpm.
        let err = sniff_lock_grammar("lockfileVersion: 5.3\n").unwrap_err();
        assert!(err.contains("re-lock with pnpm >= 9"), "{err}");

        // Future versions: the fix is an allowlisted-emitting pnpm or a
        // newer build, never "pnpm >= 9" (the user's pnpm already is).
        for head in ["lockfileVersion: '9.1'\n", "lockfileVersion: '10.0'\n"] {
            let err = sniff_lock_grammar(head).unwrap_err();
            assert!(err.contains("update socket-patch"), "{err}");
            assert!(!err.contains("re-lock with pnpm >= 9"), "{err}");
            // The v9 backend's guard agrees on the direction.
            let err = check_lock_version(head).unwrap_err();
            assert!(err.contains("update socket-patch"), "{err}");
        }

        // No version in the head: unrecognizably old — upgrade advice stands.
        let err = sniff_lock_grammar("importers:\n").unwrap_err();
        assert!(err.contains("re-lock with pnpm >= 9"), "{err}");
        assert!(check_lock_version("importers:\n").is_err());
    }

    #[test]
    fn override_key_name_grammar() {
        assert_eq!(override_key_name("left-pad"), "left-pad");
        assert_eq!(override_key_name("left-pad@1.3.0"), "left-pad");
        assert_eq!(override_key_name("left-pad@^1"), "left-pad");
        assert_eq!(override_key_name("@scope/pkg"), "@scope/pkg");
        assert_eq!(override_key_name("@scope/pkg@2"), "@scope/pkg");
        assert_eq!(override_key_name("parent@1>left-pad@2"), "left-pad");
    }

    #[test]
    fn key_line_parser_handles_both_quote_styles_and_file_specs() {
        assert_eq!(
            parse_key_line("  left-pad@1.3.0:", 2),
            Some((
                "left-pad@1.3.0".into(),
                "left-pad@1.3.0".into(),
                String::new()
            ))
        );
        assert_eq!(
            parse_key_line("  left-pad@1.3.0: {}", 2),
            Some((
                "left-pad@1.3.0".into(),
                "left-pad@1.3.0".into(),
                "{}".into()
            ))
        );
        // Keys containing `:` (file: specs) split at the colon+space/EOL.
        assert_eq!(
            parse_key_line("  left-pad@file:x/y.tgz:", 2),
            Some((
                "left-pad@file:x/y.tgz".into(),
                "left-pad@file:x/y.tgz".into(),
                String::new()
            ))
        );
        // pnpm's quoted @-keys (both majors single-quote them).
        assert_eq!(
            parse_key_line("  '@scope/a@1.0.0':", 2),
            Some((
                "@scope/a@1.0.0".into(),
                "'@scope/a@1.0.0'".into(),
                String::new()
            ))
        );
        assert_eq!(
            parse_key_line("  \"@scope/a@1.0.0\": {}", 2),
            Some((
                "@scope/a@1.0.0".into(),
                "\"@scope/a@1.0.0\"".into(),
                "{}".into()
            ))
        );
        // Wrong indent / deeper lines are not keys at this level.
        assert_eq!(parse_key_line("    resolution: {}", 2), None);
        assert_eq!(
            parse_key_line("      - left-pad", 6),
            None,
            "list items are not keys"
        );

        assert_eq!(yaml_key("@scope/a@file:x"), "'@scope/a@file:x'");
        assert_eq!(yaml_key("left-pad@1.3.0"), "left-pad@1.3.0");
        assert_eq!(yaml_key_like("k", "'orig'"), "'k'");
        assert_eq!(yaml_key_like("k", "orig"), "k");
    }

    // ── pnpm-workspace.yaml override surface (pnpm >= 11) ─────────────────

    async fn write_ws(fx: &Fixture, body: &str) {
        tokio::fs::write(fx.root().join(PNPM_WORKSPACE), body)
            .await
            .unwrap();
    }
    async fn ws_exists(fx: &Fixture) -> bool {
        fx.root().join(PNPM_WORKSPACE).exists()
    }

    /// No workspace file: vendor creates the root-only scaffold + our
    /// override; the lock's `overrides:` value equals it (map parity that
    /// pnpm >= 11 hard-checks); revert deletes the file again.
    #[tokio::test]
    async fn workspace_file_is_created_with_root_scaffold_and_revert_deletes_it() {
        let fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        assert!(
            !ws_exists(&fx).await,
            "fixture starts with no workspace file"
        );

        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let spec = format!("file:{}", fx.rel_tgz());
        assert_eq!(
            fx.read(PNPM_WORKSPACE).await,
            ws_scaffold_text("left-pad@1.3.0", &spec),
            "created workspace carries `packages: ['.']` + the override"
        );
        // The three surfaces agree on the same key → value (no config mismatch).
        assert!(fx
            .read(PNPM_WORKSPACE)
            .await
            .contains(&format!("overrides:\n  left-pad@1.3.0: {spec}")));
        assert!(fx
            .read(PNPM_LOCK)
            .await
            .contains(&format!("overrides:\n  left-pad@1.3.0: {spec}")));
        assert!(entry.pnpm.as_ref().unwrap().created_workspace_file);
        assert!(!entry.pnpm.as_ref().unwrap().created_workspace_overrides);

        let outcome = revert_pnpm(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !ws_exists(&fx).await,
            "revert deletes the workspace file it created"
        );
    }

    /// Existing workspace file WITHOUT an `overrides:` section: vendor
    /// appends one, leaving the `packages:` list untouched; revert restores
    /// the file byte-for-byte.
    #[tokio::test]
    async fn workspace_overrides_section_is_appended_and_revert_restores_bytes() {
        let fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        let original = "packages:\n  - 'packages/*'\n";
        write_ws(&fx, original).await;

        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let spec = format!("file:{}", fx.rel_tgz());
        assert_eq!(
            fx.read(PNPM_WORKSPACE).await,
            format!("{original}overrides:\n  left-pad@1.3.0: {spec}\n"),
            "override block appended after the existing packages list"
        );
        assert!(!entry.pnpm.as_ref().unwrap().created_workspace_file);
        assert!(entry.pnpm.as_ref().unwrap().created_workspace_overrides);

        let outcome = revert_pnpm(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            fx.read(PNPM_WORKSPACE).await,
            original,
            "revert removes the appended section byte-for-byte"
        );
    }

    /// Existing workspace file WITH an `overrides:` section: vendor inserts
    /// our key beside the user's, leaving theirs intact; revert removes only
    /// our key.
    #[tokio::test]
    async fn workspace_override_inserted_beside_existing_and_revert_removes_only_ours() {
        let fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        let original = "packages:\n  - 'packages/*'\noverrides:\n  other-pkg: 2.0.0\n";
        write_ws(&fx, original).await;

        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let spec = format!("file:{}", fx.rel_tgz());
        assert_eq!(
            fx.read(PNPM_WORKSPACE).await,
            format!("packages:\n  - 'packages/*'\noverrides:\n  other-pkg: 2.0.0\n  left-pad@1.3.0: {spec}\n"),
        );
        assert!(!entry.pnpm.as_ref().unwrap().created_workspace_file);
        assert!(!entry.pnpm.as_ref().unwrap().created_workspace_overrides);

        let outcome = revert_pnpm(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            fx.read(PNPM_WORKSPACE).await,
            original,
            "revert leaves the user's override intact and drops only ours"
        );
    }

    /// A flow-style/inline `overrides:` mapping the line surgery cannot
    /// splice into is refused before any write.
    #[tokio::test]
    async fn inline_workspace_overrides_mapping_is_refused() {
        let fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        write_ws(&fx, "overrides: {other-pkg: 2.0.0}\n").await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_override_conflict");
        assert!(detail.contains("inline"), "{detail}");
    }

    /// A conflicting same-name override already in the workspace file is a
    /// fail-closed refusal.
    #[tokio::test]
    async fn workspace_conflicting_same_name_override_is_refused() {
        let fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        write_ws(&fx, "overrides:\n  left-pad: 1.4.0\n").await;
        expect_refused(fx.vendor(false).await, "vendor_override_conflict");
    }

    /// The pnpm >= 11 UPGRADE path: a project vendored by the pre-workspace
    /// code (package.json + pnpm-lock.yaml already overridden, NO
    /// pnpm-workspace.yaml) is re-vendored under the current code, which adds
    /// only the workspace mirror. The re-vendor's fresh entry names ONLY the
    /// workspace surface, so replacing the ledger entry wholesale would lose
    /// the package.json + lock originals the first vendoring recorded and
    /// `--revert` could restore only the workspace file. `carry_forward_wiring`
    /// (which `persist_vendor_entry` runs on every re-vendor) reconciles the
    /// two so revert byte-restores ALL THREE surfaces.
    #[tokio::test]
    async fn revendor_upgrade_adds_workspace_and_revert_restores_all_three_surfaces() {
        let fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;

        // 1. First vendoring, then downgrade the recorded state to what the
        //    pre-workspace code would have left: no pnpm-workspace.yaml, and a
        //    ledger entry carrying only the package.json + lock wiring.
        let (_, prev, _) = expect_done(fx.vendor(false).await);
        let mut prev = prev.unwrap();
        tokio::fs::remove_file(fx.root().join(PNPM_WORKSPACE))
            .await
            .unwrap();
        prev.wiring.retain(|r| r.file != PNPM_WORKSPACE);
        if let Some(meta) = prev.pnpm.as_mut() {
            meta.created_workspace_file = false;
            meta.created_workspace_overrides = false;
        }
        // Pre-workspace code created the pnpm/overrides tables (the fixture's
        // package.json had no `pnpm` field), and left both surfaces wired.
        let pnpm_meta = prev.pnpm.clone().unwrap();
        assert!(pnpm_meta.created_pnpm_table && pnpm_meta.created_overrides_table);
        assert!(prev.wiring.iter().any(|r| r.file == PACKAGE_JSON));
        assert!(prev.wiring.iter().any(|r| r.file == PNPM_LOCK));
        assert!(
            !ws_exists(&fx).await,
            "downgraded state has no workspace file"
        );

        // 2. Re-vendor under the current code: package.json + lock are already
        //    in sync, so ONLY the workspace mirror is written and the fresh
        //    entry names ONLY that surface (the bug's precondition).
        let (_, revendored, _) = expect_done(fx.vendor(false).await);
        let mut merged = revendored.unwrap();
        assert!(ws_exists(&fx).await, "re-vendor added the workspace file");
        assert!(
            merged.wiring.iter().all(|r| r.file == PNPM_WORKSPACE),
            "the fresh re-vendor entry names only the workspace surface: {:?}",
            merged.wiring
        );

        // 3. Reconcile with the entry being replaced (as persist_vendor_entry
        //    does), then revert.
        super::super::state::carry_forward_wiring(&prev, &mut merged);
        let outcome = revert_pnpm(&merged, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);

        // All three surfaces byte-restored to their pre-vendor originals.
        assert_eq!(
            fx.read(PACKAGE_JSON).await,
            P1_BEFORE_PKG,
            "package.json byte-restored"
        );
        assert_eq!(
            fx.read(PNPM_LOCK).await,
            P1_BEFORE_LOCK,
            "lock byte-restored"
        );
        assert!(
            !ws_exists(&fx).await,
            "the workspace file the re-vendor created is deleted"
        );
        assert!(!fx
            .root()
            .join(format!(".socket/vendor/npm/{UUID}"))
            .exists());
    }

    /// A re-vendor under a NEW patch uuid (the patch was updated upstream)
    /// finds every surface already present — the FIRST vendoring created the
    /// package.json `pnpm`/`overrides` tables and pnpm-workspace.yaml — so
    /// the fresh entry records all-false creation flags. Those flags are
    /// historical facts independent of the patch generation:
    /// `carry_forward_wiring` must keep them across the uuid change, or
    /// `--revert` leaves the vendor-created pnpm-workspace.yaml behind (a
    /// workspace-defining file the user never wrote) and an empty
    /// `"pnpm": {"overrides": {}}` husk in package.json.
    #[tokio::test]
    async fn new_uuid_revendor_revert_removes_created_workspace_and_tables() {
        let mut fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;

        // First vendoring under uuid A creates all three surfaces.
        let (_, prev, _) = expect_done(fx.vendor(false).await);
        let prev = prev.unwrap();
        let meta = prev.pnpm.as_ref().unwrap();
        assert!(
            meta.created_pnpm_table && meta.created_overrides_table && meta.created_workspace_file,
            "first vendoring created the surfaces: {meta:?}"
        );

        // The patch is updated upstream: same package, new uuid.
        fx.record.uuid = "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d".to_string();
        let (_, revendored, _) = expect_done(fx.vendor(false).await);
        let mut merged = revendored.unwrap();
        assert_ne!(merged.uuid, prev.uuid, "re-vendor is a new generation");

        // Reconcile with the entry being replaced (as persist_vendor_entry
        // does), then revert.
        super::super::state::carry_forward_wiring(&prev, &mut merged);
        let outcome = revert_pnpm(&merged, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);

        assert!(
            !ws_exists(&fx).await,
            "the pnpm-workspace.yaml vendor created must not survive revert"
        );
        assert_eq!(
            fx.read(PACKAGE_JSON).await,
            P1_BEFORE_PKG,
            "package.json byte-restored (no empty pnpm/overrides husk)"
        );
        assert_eq!(
            fx.read(PNPM_LOCK).await,
            P1_BEFORE_LOCK,
            "lock byte-restored"
        );
    }

    /// The packages-block rewrite drops the entry's own 4-indent
    /// `deprecated:`/`version:` FIELDS — but `version` and `deprecated` are
    /// also real npm package names, and a peerDependency on one of them
    /// (optional + uninstalled, so no peer-suffixed snapshot key triggers the
    /// pre-flight refusal) puts the same spellings at 6-space indent inside
    /// `peerDependencies:`/`peerDependenciesMeta:`. Those lines are part of
    /// the "everything else verbatim" contract and must survive the rewrite.
    #[tokio::test]
    async fn packages_rewrite_keeps_peer_deps_named_version_or_deprecated() {
        let pkg = "{\n  \"name\": \"x\",\n  \"dependencies\": { \"left-pad\": \"1.3.0\" }\n}\n";
        let lock = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      left-pad:
        specifier: 1.3.0
        version: 1.3.0

packages:

  left-pad@1.3.0:
    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==}
    deprecated: use String.prototype.padStart()
    peerDependencies:
      deprecated: ^1.0.0
      version: '>=1'
    peerDependenciesMeta:
      deprecated:
        optional: true
      version:
        optional: true

snapshots:

  left-pad@1.3.0: {}
";
        let fx = fixture_with(pkg, lock).await;
        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());

        let healed = fx.read(PNPM_LOCK).await;
        assert!(
            healed.contains("    peerDependencies:\n      deprecated: ^1.0.0\n      version: '>=1'\n"),
            "peer deps named like dropped fields must survive verbatim:\n{healed}"
        );
        assert!(
            healed.contains(
                "    peerDependenciesMeta:\n      deprecated:\n        optional: true\n      version:\n        optional: true"
            ),
            "peerDependenciesMeta keys must survive verbatim:\n{healed}"
        );
        assert!(
            !healed.contains("    deprecated: use String.prototype.padStart()"),
            "the entry's own 4-indent deprecated: field is still dropped:\n{healed}"
        );
        assert!(
            healed.contains("    version: 1.3.0\n"),
            "the canonical version: field is re-inserted:\n{healed}"
        );
    }

    /// An EXISTING pnpm-workspace.yaml that cannot be read (non-UTF-8
    /// encoding — e.g. a UTF-16 save —, permissions, a FIFO) must refuse,
    /// never be mistaken for "no file": the create path would OVERWRITE the
    /// user's workspace definition (their `packages:` globs, catalogs) with
    /// the root-only scaffold.
    #[tokio::test]
    async fn unreadable_workspace_file_refuses_instead_of_scaffold_overwrite() {
        let fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        let junk: &[u8] = b"packages:\n  - 'packages/*'\n\xFF\xFE\n";
        tokio::fs::write(fx.root().join(PNPM_WORKSPACE), junk)
            .await
            .unwrap();

        let detail = expect_refused(fx.vendor(false).await, "vendor_lockfile_missing");
        assert!(detail.contains(PNPM_WORKSPACE), "{detail}");
        assert_eq!(
            tokio::fs::read(fx.root().join(PNPM_WORKSPACE)).await.unwrap(),
            junk,
            "the unreadable workspace file must survive byte-identical"
        );
        assert_eq!(fx.read(PACKAGE_JSON).await, P1_BEFORE_PKG, "pkg untouched");
        assert_eq!(fx.read(PNPM_LOCK).await, P1_BEFORE_LOCK, "lock untouched");
    }

    /// A CRLF pnpm-workspace.yaml (Windows autocrlf checkout) dodges every
    /// structural probe — the conflict checks miss the existing `overrides:`
    /// section and the edit appends a DUPLICATE one, which pnpm rejects as a
    /// duplicated mapping key (bricking every pnpm command). Same fail-closed
    /// posture as the lock's CRLF refusal.
    #[tokio::test]
    async fn crlf_workspace_file_refuses_instead_of_duplicating_overrides() {
        let fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        let crlf_ws = "packages:\r\n  - 'packages/*'\r\noverrides:\r\n  other-pkg: 2.0.0\r\n";
        write_ws(&fx, crlf_ws).await;

        let detail = expect_refused(fx.vendor(false).await, "vendor_lockfile_crlf_unsupported");
        assert!(detail.contains(PNPM_WORKSPACE), "{detail}");
        assert!(detail.contains("CRLF"), "{detail}");
        assert_eq!(fx.read(PNPM_WORKSPACE).await, crlf_ws, "workspace untouched");
        assert_eq!(fx.read(PNPM_LOCK).await, P1_BEFORE_LOCK, "lock untouched");
        assert_eq!(fx.read(PACKAGE_JSON).await, P1_BEFORE_PKG, "pkg untouched");
    }

    /// The revert twin of the CRLF blindness: a workspace file converted to
    /// CRLF since vendoring makes the Added override read as "already
    /// converged" (the section probe misses it), so revert would remove the
    /// artifact while the live override still points at it — pnpm >= 11 then
    /// resolves through a deleted tarball. Must be a drift-keep instead.
    #[tokio::test]
    async fn crlf_workspace_revert_is_a_drift_keep_not_silent_convergence() {
        let fx = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let crlf_ws = fx.read(PNPM_WORKSPACE).await.replace('\n', "\r\n");
        tokio::fs::write(fx.root().join(PNPM_WORKSPACE), &crlf_ws)
            .await
            .unwrap();

        let outcome = revert_pnpm(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted" && w.detail.contains(PNPM_WORKSPACE)),
            "CRLF workspace must surface as drift: {:?}",
            outcome.warnings
        );
        assert!(
            outcome.kept_artifact,
            "the still-referenced artifact must be kept"
        );
        assert!(
            fx.root()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "artifact dir survives the drift-keep"
        );
        assert_eq!(fx.read(PNPM_WORKSPACE).await, crlf_ws, "CRLF file left alone");
    }

    /// A CRLF lock breaks the packages/snapshots section probes, so the
    /// in-use scan finds nothing and would call a still-referenced artifact
    /// "provably orphaned" (`Some(false)`) — letting the unwired-revert
    /// guard delete it out from under the lock. CRLF must be undeterminable
    /// (`None`), which the guard refuses on while the lock exists.
    #[tokio::test]
    async fn crlf_lock_is_undeterminable_for_in_use_and_unwired_revert_refuses() {
        let (fx, entry) = reconstructed_fixture().await;
        let crlf_lock = fx.read(PNPM_LOCK).await.replace('\n', "\r\n");
        tokio::fs::write(fx.root().join(PNPM_LOCK), &crlf_lock)
            .await
            .unwrap();

        assert_eq!(
            pnpm_entry_in_use(&entry, fx.root()).await,
            None,
            "a CRLF lock is undeterminable, never provably orphaned"
        );
        let outcome = revert_pnpm(&entry, fx.root(), false).await;
        assert!(!outcome.success, "unwired revert must refuse: {outcome:?}");
        assert!(
            fx.root().join(fx.rel_tgz()).exists(),
            "the artifact must survive"
        );
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

    /// A FIFO planted as one of the pair files must fail fast instead of
    /// wedging vendor / revert / the in-use probe forever in an `open(2)`
    /// waiting for a writer that never comes. package.json and
    /// pnpm-workspace.yaml are the FIRST opens in the vendor flow (flavor
    /// detection reads only the lock), and revert's lock/package.json reads
    /// are the first opens of theirs. Same `open_regular_file` guard class
    /// as the vendor siblings (npm_lock.rs, npm_flavor.rs, lock_inventory.rs).
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_pair_files_fail_fast_instead_of_wedging_vendor_and_revert() {
        // Vendor half A: package.json is a FIFO.
        let fxa = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        tokio::fs::remove_file(fxa.root().join(PACKAGE_JSON))
            .await
            .unwrap();
        mkfifo(&fxa.root().join(PACKAGE_JSON));

        // Vendor half B: pnpm-workspace.yaml is a FIFO.
        let fxb = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        mkfifo(&fxb.root().join(PNPM_WORKSPACE));

        // Revert halves: vendor normally first, then swap one pair file for
        // a FIFO before reverting (probing the in-use scan on the FIFO lock
        // too).
        let fxc = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        let (_, entry_c, _) = expect_done(fxc.vendor(false).await);
        let entry_c = entry_c.unwrap();
        tokio::fs::remove_file(fxc.root().join(PNPM_LOCK))
            .await
            .unwrap();
        mkfifo(&fxc.root().join(PNPM_LOCK));

        let fxd = fixture_with(P1_BEFORE_PKG, P1_BEFORE_LOCK).await;
        let (_, entry_d, _) = expect_done(fxd.vendor(false).await);
        let entry_d = entry_d.unwrap();
        tokio::fs::remove_file(fxd.root().join(PACKAGE_JSON))
            .await
            .unwrap();
        mkfifo(&fxd.root().join(PACKAGE_JSON));

        let deadline = std::time::Duration::from_secs(5);
        let all = async {
            (
                fxa.vendor(false).await,
                fxb.vendor(false).await,
                pnpm_entry_in_use(&entry_c, fxc.root()).await,
                revert_pnpm(&entry_c, fxc.root(), false).await,
                revert_pnpm(&entry_d, fxd.root(), false).await,
            )
        };
        let Ok((vendored_a, vendored_b, in_use_c, reverted_c, reverted_d)) =
            tokio::time::timeout(deadline, all).await
        else {
            // On timeout the open is wedged in a `spawn_blocking` thread the
            // runtime waits for on shutdown; connect a non-blocking writer to
            // release it so the test can FAIL instead of hanging the suite.
            use std::os::unix::fs::OpenOptionsExt;
            for path in [
                fxa.root().join(PACKAGE_JSON),
                fxb.root().join(PNPM_WORKSPACE),
                fxc.root().join(PNPM_LOCK),
                fxd.root().join(PACKAGE_JSON),
            ] {
                let _ = std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(path);
            }
            panic!("pnpm pair-file reads must fail fast on FIFOs");
        };
        let detail = expect_refused(vendored_a, "vendor_lockfile_missing");
        assert!(detail.contains(PACKAGE_JSON), "{detail}");
        let detail = expect_refused(vendored_b, "vendor_lockfile_missing");
        assert!(detail.contains(PNPM_WORKSPACE), "{detail}");
        assert_eq!(in_use_c, None, "a FIFO lock is undeterminable");
        assert!(
            !reverted_c.success,
            "revert must fail closed on a FIFO lock: {:?}",
            reverted_c.warnings
        );
        assert!(
            fxc.root().join(fxc.rel_tgz()).exists(),
            "the artifact must survive the failed revert"
        );
        assert!(
            !reverted_d.success,
            "revert must fail closed on a FIFO package.json: {:?}",
            reverted_d.warnings
        );
        assert!(
            fxd.root().join(fxd.rel_tgz()).exists(),
            "the artifact must survive the failed revert"
        );
    }
}
