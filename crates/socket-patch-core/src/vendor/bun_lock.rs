//! bun vendor backend: LOCK-ONLY `bun.lock` surgery.
//!
//! Spike BN3 (`spikes/PHASE0-V2-FINDINGS.txt`, fixtures in `spikes/bun/`)
//! proved the lock-only edit is sound on bun 1.3.x: rewriting just the
//! `packages` entry passes `bun install --frozen-lockfile` / `bun ci`, the
//! lock stays byte-stable under plain `bun install`, the entry's integrity
//! (sha512 of the raw tarball bytes) is enforced fail-closed even on plain
//! installs (BN5) — by Bun >= 1.3.10, the release that started verifying
//! the sha512 of URL/local-tarball tuples (registry 4-tuples are verified
//! from >= 1.2.0); every earlier release installs a tampered tarball with
//! exit 0, so on those consumers the integrity we write is a pin they
//! cannot enforce — warm caches never shadow the tarball (BN6), and a
//! fresh checkout installs fully offline (BN7). package.json is left UNTOUCHED —
//! and per-entry edits give exact per-instance targeting that bun's
//! name-only `overrides` cannot (BN4: a name-keyed override collapses EVERY
//! version; a version-scoped override key is a silent no-op).
//!
//! The rewrite (exact arity + spelling pinned by the BN1/BN3 fixtures):
//! every `packages` entry — top-level AND nested `"parent/child"` keys —
//! whose tuple resolves the exact `name@version` moves from the registry
//! 4-tuple `["name@version", "<registry>", {deps}, "sha512-..."]` to the
//! local-tarball 3-tuple `["name@<rel-path>", {deps}, "sha512-<ours>"]`,
//! where `<rel-path>` is the BARE project-relative path
//! (`.socket/vendor/npm/<uuid>/<name>-<version>.tgz` — no `file:`, no `./`;
//! that is the spelling bun itself emits and re-serializes byte-stably) and
//! the integrity is recomputed from the tarball we packed. The `{deps}`
//! object is carried over verbatim (its position shifts from index 2 to 1).
//!
//! `bun.lock` is JSONC (trailing commas), so the surgery is line-oriented —
//! bun emits each packages entry on a single line — under a conservative
//! grammar that fails CLOSED on anything unexpected; the file is never fed
//! to a JSON parser.

use std::path::Path;

use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha512};

use crate::manifest::schema::PatchRecord;
use crate::patch::apply::PatchSources;
use crate::patch::copy_tree::remove_tree;
use crate::utils::fs::{atomic_write_bytes_preserving_mode, read_regular_to_string};
use crate::vendor::bun_lock_text::{
    check_lock_version, decode_json_string, has_workspace_packages, lock_version, packages_bounds,
    parse_entry_line, parse_packages_section, split_name_spec, BunEntry,
};

use super::common::{already_patched_result, refused};
use super::npm_common::{
    done_failure_unstage, guard_coordinates, guard_revert_uuid_dir, stage_patch_pack, tgz_rel_leaf,
};
use super::path::parse_vendor_path;
use super::state::{
    write_marker, VendorArtifact, VendorEntry, VendorMarker, WiringAction, WiringRecord,
};
use super::{RevertOpts, RevertOutcome, VendorOutcome, VendorWarning};

const BUN_LOCK: &str = "bun.lock";

/// The `WiringRecord.kind` this backend owns: key = the `packages` map key,
/// original/new = the verbatim entry LINE.
const KIND_LOCK_PACKAGE: &str = "bun_lock_package";

/// The ONE remedy text for `vendor_bun_lockb_unsupported`, shared by the
/// flavor router ([`super::npm_flavor::detect_npm_lock_flavor`], reached by
/// `vendor` and detached runs) and [`preflight_vendor`] (reached by
/// `get`/`scan --mode vendored` before any download) so the code never
/// carries two different remedies. `bun install --save-text-lockfile` is
/// the actual fix — plain `bun install` on ANY bun (1.2.x and 1.4.x
/// included) keeps an in-sync bun.lockb as-is — and the flag exists only
/// from 1.1.39 (1.1.38 accepts it silently and still writes bun.lockb), so
/// the floor is spelled out too.
pub(crate) const BUN_LOCKB_UNSUPPORTED_DETAIL: &str =
    "bun.lockb is bun's legacy binary lockfile, which vendor cannot rewrite; run `bun install \
     --save-text-lockfile` (Bun >= 1.1.39), commit the resulting bun.lock, and re-run";

/// Workspace gate: a `workspace:` packages entry in a lock whose
/// `lockfileVersion` is below 2 refuses with `vendor_bun_workspace_unsupported`.
///
/// WHY (measured with real binaries, cold caches): Bun 1.2.x–1.3.x resolve
/// a workspace-scoped local-tarball path relative to the workspace MEMBER
/// that declares it — our root-relative `.socket/vendor/npm/…` tuple then
/// ENOENTs on `bun install` — while 1.4.x resolves it relative to the
/// lockfile. The property belongs to the consuming bun binary, which the
/// vendoring machine cannot see; a committed lockfileVersion-2 lock is the
/// only proof that every consumer runs Bun >= 1.4, because 1.3.x cannot
/// parse v2 at all, whereas a v1 lock is readable by both.
///
/// The gate is a DELIBERATE OVER-APPROXIMATION: a package declared only by
/// the workspace root vendors and installs correctly on every v1 release
/// too, but the lock cannot cheaply prove which workspace declares the
/// entry (hoisted entries collapse root and member declarations into one
/// key), so every pre-v2 workspace lock refuses. Hosted mode accepts these
/// locks (a URL tuple has no path to resolve), which the remedy points at.
///
/// Bun never bumps an existing lock's version in place — 1.4.x `install`,
/// `--save-text-lockfile`, `--force`, `add` and `update` all keep a v1 lock
/// at version 1; only deleting bun.lock and re-locking writes 2 — so the
/// remedy says exactly that instead of the non-converging "upgrade and run
/// `bun install`".
///
/// The hosted alternative in the remedy is VERSION-SPECIFIC: hosted mode
/// accepts a version-1 workspace lock (a URL tuple has no path to resolve)
/// but refuses a version-0 one (`redirect_bun_workspace_unsupported`,
/// `redirect/mod.rs`), so pointing a Bun 1.1.39–1.1.45 user at `--mode
/// hosted` as-is would only earn them a second refusal with a different
/// remedy. A v0 lock must be re-locked with Bun >= 1.2 (which writes
/// version 1) before hosted mode can take it — and that means DELETING the
/// lock first: measured on this lock shape, an in-place `bun install` keeps
/// v0 on 1.2.0 and fails to resolve on 1.3.14/1.4.2.
fn check_workspace_compatibility(
    text: &str,
    entries: &[BunEntry],
) -> Result<(), (&'static str, String)> {
    // `check_lock_version` already refused a lock with no integer head, so
    // `None` is unreachable here; 0 (the oldest text grammar) is the
    // fail-closed reading if it ever were.
    let version = lock_version(text).unwrap_or(0);
    if version >= 2 || !has_workspace_packages(entries) {
        return Ok(());
    }
    let hosted_alternative = if version == 0 {
        "or delete bun.lock, re-lock with Bun >= 1.2 (which writes lockfileVersion 1) and use \
         `--mode hosted`"
    } else {
        "or use `--mode hosted`, which accepts version-1 workspace locks"
    };
    Err((
        "vendor_bun_workspace_unsupported",
        format!(
            "Bun releases before 1.4 resolve a workspace-scoped local tarball path relative to \
             the workspace member, and a lockfileVersion-{version} lock may still be installed \
             by such a release; delete bun.lock and re-run `bun install` with Bun >= 1.4 (which \
             writes lockfileVersion 2) before vendoring — an in-place `bun install` keeps the \
             existing lockfileVersion — {hosted_alternative}"
        ),
    ))
}

/// Refuse incompatible Bun projects before downloading records into the
/// manifest. Other package managers are left to their own backends.
///
/// PROJECT-LEVEL: this cannot see per-purl state, so it refuses a pre-v2
/// workspace lock even when the purl in question is already vendored in
/// it. The CLI exempts a purl from this refusal before acting on it when
/// EITHER its vendor ledger already wires the purl at the uuid the run
/// selected (an in-sync re-run) OR [`wired_instances_all_ours`] reports
/// that every lock instance of the purl is already one of our tuples — the
/// same criterion [`vendor_bun`] applies per classified instance, so that
/// in-sync re-runs, superseding-uuid re-vendors and `repair` rebuilds of a
/// project vendored before it grew a workspace member all reach the
/// engine instead of dying here.
pub async fn preflight_vendor(project_root: &Path) -> Result<(), (&'static str, String)> {
    let path = project_root.join(BUN_LOCK);
    let text = match read_regular_to_string(&path).await {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if project_root.join("bun.lockb").exists() {
                return Err((
                    "vendor_bun_lockb_unsupported",
                    BUN_LOCKB_UNSUPPORTED_DETAIL.to_string(),
                ));
            }
            return Ok(());
        }
        Err(error) => return Err(("vendor_lockfile_missing", error.to_string())),
    };
    check_lock_version(&text).map_err(|detail| ("vendor_lockfile_version_unsupported", detail))?;
    let lines = text.split('\n').map(str::to_string).collect::<Vec<_>>();
    let entries = parse_packages_section(&lines)
        .map_err(|detail| ("vendor_lockfile_version_unsupported", detail))?;
    check_workspace_compatibility(&text, &entries)
}

/// Whether `bun.lock` already wires EVERY packages entry resolving the npm
/// `purl`'s `name@version` to one of our `.socket/vendor/npm/` tarballs —
/// any uuid, 3-tuple or the digest-less 2-tuple Bun < 1.3.10 re-saves it
/// as (see [`classify`]). `Ok(false)` when no entry resolves the purl at
/// all (a fresh vendor, or a hosted URL tuple the takeover has yet to
/// revert) or when any resolving instance is still the registry tuple.
///
/// This is the per-purl half of the vendored preflight: [`preflight_vendor`]
/// is project-level and refuses every pre-v2 workspace lock, whereas
/// [`vendor_bun`] skips that gate whenever the instances it would rewrite
/// are already ours — rewriting an `Ours` tuple to another uuid adds no new
/// workspace-relative path, so a superseding patch on a project vendored
/// before it grew a workspace member re-vendors in place, and a `repair`
/// rebuild proceeds. The CLI consults this so its pre-download refusal
/// exempts exactly what the engine would let through, ledger or no ledger
/// (a wiped `state.json` used to turn every such update into a false
/// `vendor_bun_workspace_unsupported`).
///
/// `Err` mirrors [`preflight_vendor`]'s codes (unreadable lock, unsupported
/// version, out-of-grammar packages section); a purl that is not an npm
/// `name@version` yields `Ok(false)` — nothing in the lock can be ours.
pub async fn wired_instances_all_ours(
    project_root: &Path,
    purl: &str,
) -> Result<bool, (&'static str, String)> {
    let Some((name, version)) = super::npm_common::parse_npm_purl(purl) else {
        return Ok(false);
    };
    let text = read_regular_to_string(&project_root.join(BUN_LOCK))
        .await
        .map_err(|error| ("vendor_lockfile_missing", error.to_string()))?;
    check_lock_version(&text).map_err(|detail| ("vendor_lockfile_version_unsupported", detail))?;
    let lines = text.split('\n').map(str::to_string).collect::<Vec<_>>();
    let entries = parse_packages_section(&lines)
        .map_err(|detail| ("vendor_lockfile_version_unsupported", detail))?;
    let target_spec = format!("{name}@{version}");
    let target_leaf = tgz_rel_leaf(&name, &version);
    let mut matched = 0usize;
    for entry in &entries {
        match classify(entry, &target_spec, &name, &target_leaf) {
            Some(TupleShape::Ours { .. }) => matched += 1,
            Some(TupleShape::Registry) => return Ok(false),
            None => {}
        }
    }
    Ok(matched > 0)
}

/// Vendor one installed npm package into a bun project (see the module doc).
/// Same contract as `npm_lock::vendor_npm`: refuse-early / wire-last,
/// `entry` present iff `result.success` and not a dry run, and an in-sync
/// re-run synthesizes AlreadyPatched with no entry.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn vendor_bun(
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

    // ── 2. Read + strictly parse the lock (refuse before any write) ──────
    let lock_text = match read_regular_to_string(&project_root.join(BUN_LOCK)).await {
        Ok(text) => text,
        Err(e) => {
            return refused(
                "vendor_lockfile_missing",
                format!("cannot read {BUN_LOCK}: {e} — run `bun install` first"),
            );
        }
    };
    if let Err(detail) = check_lock_version(&lock_text) {
        return refused("vendor_lockfile_version_unsupported", detail);
    }
    let mut lines: Vec<String> = lock_text.split('\n').map(str::to_string).collect();
    let entries = match parse_packages_section(&lines) {
        Ok(entries) => entries,
        Err(detail) => {
            // SECURITY/fail-closed: never line-splice a lock whose packages
            // section does not match the pinned single-line grammar.
            return refused(
                "vendor_lockfile_version_unsupported",
                format!("{BUN_LOCK} packages section is not in bun's emitted shape: {detail}"),
            );
        }
    };

    // ── 3. Pre-flight: at least one rewritable instance ──────────────────
    let target_spec = format!("{name}@{version}");
    let target_leaf = tgz_rel_leaf(name, version);
    let has_match = entries
        .iter()
        .any(|e| classify(e, &target_spec, name, &target_leaf).is_some());
    if !has_match {
        return refused(
            "vendor_lock_entry_not_found",
            format!(
                "{BUN_LOCK} has no packages entry resolving {name}@{version} — make sure \
                 the package is installed and locked (`bun install`) before vendoring"
            ),
        );
    }
    // Workspace gate, evaluated on the CLASSIFIED target instances rather
    // than the raw lock: it refuses only a run that would WRITE a new
    // local-tarball tuple (a `Registry` instance) into a pre-v2 workspace
    // lock. When every matching instance is already one of ours (`Ours`),
    // the lock carries the local tuple regardless of what this run does —
    // an in-sync re-run must synthesize AlreadyPatched and a `repair`
    // rebuild of a missing/corrupt artifact must proceed (both route here),
    // otherwise a project vendored before it grew a workspace member is
    // refused every maintenance verb and `repair` leaves the lock pointing
    // at a tarball it declined to rebuild. Still ahead of staging, so the
    // refusal precedes every write.
    let writes_new_local_tuple = entries.iter().any(|e| {
        matches!(
            classify(e, &target_spec, name, &target_leaf),
            Some(TupleShape::Registry)
        )
    });
    if writes_new_local_tuple {
        if let Err((code, detail)) = check_workspace_compatibility(&lock_text, &entries) {
            return refused(code, detail);
        }
    }

    // The sha512 of the artifact already sitting at the target path, if
    // any — the one witness a digest-less in-sync tuple (see `classify`)
    // still has of the digest Bun dropped: the lock line was written from
    // these bytes. Read BEFORE staging, which overwrites the file; a
    // missing or non-regular path (a `repair` rebuild after deletion, a
    // FIFO) yields `None`, which the in-sync check below treats as "not
    // provably the same bytes".
    let prior_artifact_integrity: Option<String> = {
        let abs = project_root.join(&coords.uuid_dir_rel).join(&target_leaf);
        match tokio::fs::metadata(&abs).await {
            Ok(meta) if meta.is_file() => tokio::fs::read(&abs).await.ok().map(|bytes| {
                format!(
                    "sha512-{}",
                    base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&bytes))
                )
            }),
            _ => None,
        }
    };

    // ── 4. Stage → patch → pack (shared flavor-agnostic pipeline) ────────
    // A wiring failure past this point must unwind the uuid dir staging is
    // about to create — but never one that already existed (a same-uuid
    // re-vendor's dir may still be referenced by live wiring).
    let uuid_dir_preexisted = tokio::fs::metadata(project_root.join(&coords.uuid_dir_rel))
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
        // Failed patch or dry run: wiring never ran, project byte-untouched.
        return VendorOutcome::Done {
            result,
            entry: None,
            warnings,
        };
    };
    // BN3 spelling: BARE project-relative path, no `file:`/`./` prefix.
    let rel_tgz = staged.rel_tgz;
    let packed = staged.packed;
    if staged.staged_pkg_json.is_some() {
        // The tuple's deps object mirrors the package's own manifest; the
        // spike has no fixture for a manifest-rewriting patch, so it is
        // preserved verbatim rather than recomputed (fail-safe + loud).
        warnings.push(VendorWarning::new(
            "vendor_dep_manifest_stale",
            format!(
                "the patch rewrites {name}@{version}'s package.json; its {BUN_LOCK} tuple's \
                 dependency object was preserved verbatim — if the patch changed dependency \
                 ranges, run `bun install` to re-resolve them"
            ),
        ));
    }

    // ── 5. Rewrite every matching instance (in-memory) ────────────────────
    let mut wiring: Vec<WiringRecord> = Vec::new();
    let mut changed = false;
    // In-sync instances whose digest Bun dropped (see `classify`): re-pinned
    // on disk WITHOUT a wiring record — the ledger already holds this
    // instance's pristine original and `revert_one_record` recognises both
    // spellings — so the run stays an AlreadyPatched no-op for the ledger
    // while ≥ 1.3.10 consumers of the committed lock regain verification.
    let mut healed = false;
    for entry in &entries {
        let Some(shape) = classify(entry, &target_spec, name, &target_leaf) else {
            continue;
        };
        let original_line = lines[entry.line_idx].clone();
        // Lines come from a bare `split('\n')`, so a CRLF lock's lines carry
        // a trailing `\r` (the grammar trims it away when parsing). Re-emit
        // it verbatim: the surgery must never mix line endings.
        let cr = if original_line.ends_with('\r') {
            "\r"
        } else {
            ""
        };
        let local_tuple_line = |deps: &str| {
            format!(
                "{indent}{key}: [\"{name}@{rel_tgz}\", {deps}, \"{integrity}\"]{comma}{cr}",
                indent = entry.indent,
                key = entry.key_raw,
                integrity = packed.integrity,
                comma = if entry.trailing_comma { "," } else { "" },
            )
        };
        let (deps_verbatim, was_ours) = match shape {
            TupleShape::Registry => (entry.elems[2].clone(), false),
            TupleShape::Ours { path } => {
                if path == rel_tgz {
                    match entry.elems.get(2) {
                        // Idempotency: an instance already carrying this exact
                        // path and integrity needs no edit and no wiring record.
                        Some(integrity) if *integrity == format!("\"{}\"", packed.integrity) => {
                            continue;
                        }
                        // Digest-less re-save of THIS wiring (Bun 1.1.39–1.3.9)
                        // over the SAME bytes the lock was written from (the
                        // artifact found at the path before this run re-staged
                        // it equals the staged one): heal the line in place,
                        // record nothing — the ledger's fingerprint still holds.
                        None if prior_artifact_integrity.as_deref()
                            == Some(packed.integrity.as_str()) =>
                        {
                            lines[entry.line_idx] = local_tuple_line(&entry.elems[1]);
                            healed = true;
                            continue;
                        }
                        // Same path, different digest — or a digest-less line
                        // whose artifact was missing or differed before staging
                        // (a `repair` rebuild, a service-prebuilt ↔ local-pack
                        // flip): re-pinned below like any stale tuple of ours,
                        // so the returned entry carries the rebuilt artifact's
                        // fingerprint (`carry_forward_wiring` refills the
                        // pristine original from the entry it replaces).
                        _ => {}
                    }
                }
                (entry.elems[1].clone(), true)
            }
        };
        let new_line = local_tuple_line(&deps_verbatim);
        lines[entry.line_idx] = new_line.clone();
        wiring.push(WiringRecord {
            file: BUN_LOCK.to_string(),
            kind: KIND_LOCK_PACKAGE.to_string(),
            action: WiringAction::Rewritten,
            key: Some(entry.key.clone()),
            // Never record one of our own (stale) edits as the "original" —
            // revert must restore the pre-vendor registry tuple, not a
            // dangling `.socket/vendor/` pointer from an earlier uuid.
            original: if was_ours {
                None
            } else {
                Some(Value::String(original_line))
            },
            new: Some(Value::String(new_line)),
        });
        changed = true;
    }

    if !changed {
        // Every instance already points at this uuid with the packed
        // integrity (or with the digest Bun dropped, now re-pinned): in
        // sync. The tarball re-pack above was byte-identical by
        // determinism; synthesize AlreadyPatched and record nothing. The
        // heal is the one write of an in-sync run, and a failed write
        // leaves the still-installable digest-less lock — reported as the
        // failure it is, like every other lock write below.
        if healed {
            if let Err(e) = atomic_write_bytes_preserving_mode(
                &project_root.join(BUN_LOCK),
                lines.join("\n").as_bytes(),
            )
            .await
            {
                return done_failure_unstage(
                    purl,
                    format!("cannot write {BUN_LOCK}: {e}"),
                    project_root,
                    &coords.uuid_dir_rel,
                    uuid_dir_preexisted,
                )
                .await;
            }
        }
        return VendorOutcome::Done {
            result: already_patched_result(purl, &project_root.join(&rel_tgz), &record.files),
            entry: None,
            warnings,
        };
    }

    if let Err(e) = atomic_write_bytes_preserving_mode(
        &project_root.join(BUN_LOCK),
        lines.join("\n").as_bytes(),
    )
    .await
    {
        return done_failure_unstage(
            purl,
            format!("cannot write {BUN_LOCK}: {e}"),
            project_root,
            &coords.uuid_dir_rel,
            uuid_dir_preexisted,
        )
        .await;
    }

    // ── 6. Marker + ledger entry ──────────────────────────────────────────
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
        flavor: Some("bun".to_string()),
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

/// Undo one bun-vendored package: restore the recorded entry lines and
/// remove the artifact dir. Reverse application order; per-record ownership
/// is re-checked against the live line (drift ⇒ warning, left alone).
/// Test-only shorthand — production routes through [`revert_bun_opts`]
/// (via [`super::npm_flavor::revert_npm_any_opts`]).
#[cfg(test)]
pub(crate) async fn revert_bun(
    entry: &VendorEntry,
    project_root: &Path,
    dry_run: bool,
) -> RevertOutcome {
    revert_bun_opts(entry, project_root, RevertOpts::new(dry_run)).await
}

/// [`revert_bun`] with full [`RevertOpts`]: `keep_artifact` skips the
/// artifact deletion — and the refusals that exist only to protect it —
/// while the wiring restore runs unchanged.
pub(crate) async fn revert_bun_opts(
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
    // only be removed when bun.lock provably no longer resolves through it
    // — otherwise refuse, fail-closed, instead of silently bricking
    // installs. Runs before the dry-run return so a preview never
    // advertises a revert the wet run refuses. Skipped under
    // `keep_artifact`: the refusal exists only to protect the deletion,
    // which a preserve-state revert never performs.
    if !keep_artifact && entry.wiring.is_empty() {
        if let Some(blocked) = super::npm_lock::guard_unwired_textual_revert(
            project_root,
            &entry.uuid,
            &uuid_dir_rel,
            &[BUN_LOCK],
        )
        .await
        {
            return blocked;
        }
    }
    if dry_run {
        return RevertOutcome::ok();
    }
    let mut outcome = RevertOutcome::ok();

    // SECURITY: revert writes are restricted to the one file vendor edits — a
    // poisoned state.json must not be able to point the rewrite at an
    // arbitrary project file. Records naming anything else are skipped with a
    // warning (fail-closed).
    let mut touches_lock = false;
    for rec in &entry.wiring {
        if rec.file != BUN_LOCK {
            outcome.warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "ignoring wiring record for non-allowlisted file `{}`",
                    rec.file
                ),
            ));
            continue;
        }
        touches_lock = true;
    }

    let mut lines: Option<Vec<String>> = None;
    if touches_lock {
        match tokio::fs::read_to_string(project_root.join(BUN_LOCK)).await {
            Ok(text) => lines = Some(text.split('\n').map(str::to_string).collect()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                outcome.warnings.push(VendorWarning::new(
                    "vendor_lockfile_missing",
                    format!("{BUN_LOCK} is missing; lock entries cannot be restored"),
                ));
            }
            Err(e) => return RevertOutcome::failed(format!("cannot read {BUN_LOCK}: {e}")),
        }
    }

    let mut dirty = false;
    if let Some(lines) = lines.as_mut() {
        for rec in entry.wiring.iter().rev().filter(|r| r.file == BUN_LOCK) {
            revert_one_record(lines, rec, &entry.uuid, &mut dirty, &mut outcome.warnings);
        }
        if dirty {
            if let Err(e) = atomic_write_bytes_preserving_mode(
                &project_root.join(BUN_LOCK),
                lines.join("\n").as_bytes(),
            )
            .await
            {
                return RevertOutcome::failed(format!("cannot write {BUN_LOCK}: {e}"));
            }
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

fn revert_one_record(
    lines: &mut [String],
    rec: &WiringRecord,
    entry_uuid: &str,
    dirty: &mut bool,
    warnings: &mut Vec<VendorWarning>,
) {
    let drifted = |detail: String| VendorWarning::new("vendor_lock_entry_drifted", detail);
    if rec.kind != KIND_LOCK_PACKAGE {
        warnings.push(drifted(format!(
            "unknown wiring kind `{}`; left alone",
            rec.kind
        )));
        return;
    }
    let Some(key) = rec.key.as_deref() else {
        warnings.push(drifted("wiring record has no key; left alone".to_string()));
        return;
    };
    // Lenient location scan: unparseable foreign lines are ignored — ours
    // must parse (we wrote it) or compare byte-equal to `rec.new`.
    let Some((start, end)) = packages_bounds(lines) else {
        warnings.push(drifted(format!(
            "{BUN_LOCK} has no packages section; `{key}` not restored"
        )));
        return;
    };
    let located = lines[start + 1..end]
        .iter()
        .enumerate()
        .find_map(|(off, line)| {
            let parsed = parse_entry_line(line).ok()?;
            (parsed.key == key).then_some((start + 1 + off, parsed))
        });
    if let Some((idx, parsed)) = located {
        // ALREADY CONVERGED: the live line equals the recorded pre-vendor
        // original — an earlier partial revert (or the user, by hand)
        // already restored this record. Not drift: stay silent so the
        // drift-skip keep gate can converge instead of re-flagging the
        // restored line forever.
        if rec.original.as_ref().and_then(Value::as_str) == Some(lines[idx].as_str()) {
            return;
        }
        // Ours iff the line is exactly what we wrote, or its tuple still
        // points into OUR uuid dir (a re-serialized but unmoved entry —
        // including the digest-less 2-tuple Bun 1.1.39–1.3.9 re-save our
        // 3-tuple as on any later lock re-save; the path is the claim, the
        // dropped sha512 proves nothing either way).
        let exact = Some(lines[idx].as_str()) == rec.new.as_ref().and_then(Value::as_str);
        let ours_uuid = matches!(parsed.elems.len(), 2 | 3)
            && decode_json_string(&parsed.elems[0])
                .and_then(|spec| split_name_spec(&spec).map(|(_, p)| p.to_string()))
                .and_then(|path| parse_vendor_path(&path))
                .is_some_and(|p| p.eco == "npm" && p.uuid == entry_uuid);
        if !exact && !ours_uuid {
            warnings.push(drifted(format!(
                "lock entry `{key}` was re-resolved since vendoring; left alone"
            )));
            return;
        }
        match rec.original.as_ref().and_then(Value::as_str) {
            Some(original) => {
                lines[idx] = original.to_string();
                *dirty = true;
            }
            None => {
                // The record rewrote one of our own earlier edits, so there
                // is no pre-vendor tuple to restore (by design). Surface it
                // instead of guessing a registry tuple.
                warnings.push(drifted(format!(
                    "lock entry `{key}` has no recorded pre-vendor original; left as-is \
                     (run `bun install` to re-resolve it from the registry)"
                )));
            }
        }
        return;
    }
    warnings.push(drifted(format!(
        "lock entry `{key}` no longer exists; nothing to restore"
    )));
}

// ───────────────────────── vendor-specific classification ─────────────────
// The conservative line grammar (`BunEntry`, `parse_*`, `scan_*`, …) lives in
// `crate::vendor::bun_lock_text`; this module keeps only the vendor tuple
// classification that decides which parsed entries to rewrite.

/// What a matching entry's tuple looks like.
enum TupleShape {
    /// Registry 4-tuple `["name@version", "<registry>", {deps}, "sha512-…"]`.
    Registry,
    /// Our local tuple (any uuid; the caller decides current vs stale): the
    /// 3-tuple we write, or the digest-less 2-tuple Bun 1.1.39–1.3.9 re-save
    /// it as (`elems.len()` tells them apart; only a 3-tuple has `elems[2]`).
    Ours { path: String },
}

/// Classify an entry against the target: `Some(Registry)` for the exact
/// `name@version` registry tuple, `Some(Ours{..})` for one of our own
/// `.socket/vendor/npm/` tuples for the same `name@version` (any uuid),
/// `None` otherwise. The Ours arm matches on the uuid-independent tarball
/// leaf, NOT the name alone: a vendored tuple for ANOTHER version of the
/// same package is someone else's edit (two patched versions can coexist in
/// one lock — nested instances) and must never be cross-clobbered. It
/// accepts the 2-tuple spelling too: Bun 1.1.39–1.3.9 drop a local tarball
/// tuple's `"sha512-…"` on any lock re-save (`bun add`, `bun install` after
/// a manifest change), leaving spec and meta intact — still our wiring, so
/// re-runs stay in sync, `repair` can rebuild and revert can unwind it
/// instead of refusing `vendor_lock_entry_not_found` / `_drifted`.
fn classify(
    entry: &BunEntry,
    target_spec: &str,
    name: &str,
    target_leaf: &str,
) -> Option<TupleShape> {
    let spec = decode_json_string(entry.elems.first()?)?;
    match entry.elems.len() {
        4 if spec == target_spec
            && decode_json_string(&entry.elems[1]).is_some()
            && entry.elems[2].starts_with('{')
            && decode_json_string(&entry.elems[3]).is_some() =>
        {
            Some(TupleShape::Registry)
        }
        2 | 3 => {
            let (entry_name, path) = split_name_spec(&spec)?;
            if entry_name != name || !entry.elems[1].starts_with('{') {
                return None;
            }
            let parts = parse_vendor_path(path)?;
            (parts.eco == "npm" && parts.leaf == target_leaf).then(|| TupleShape::Ours {
                path: path.to_string(),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::PatchFileInfo;
    use crate::patch::apply::{ApplyResult, VerifyStatus};
    use std::collections::HashMap;
    use std::path::PathBuf;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const ORIG_INDEX: &[u8] = b"module.exports = () => 'orig';\n";
    const PATCHED_INDEX: &[u8] = b"module.exports = () => 'patched';\n";

    /// The spike tarball's integrity, as committed in the after-fixtures.
    /// Our pack produces a DIFFERENT (deterministic) tarball, so fixture
    /// comparisons substitute the actual integrity for this token —
    /// everything else must be byte-identical.
    const SPIKE_INTEGRITY: &str =
        "sha512-BeCz4t+xVlVhKgnBa2K5pAR1MKUgHxv3w9G4T/ADxBhxHNY1ByfS0zcyKi6WQYEM+W2MbTE5kpwwVpgkS//6lQ==";

    // ── tool-generated byte-exact oracles ─────────────────────────────────
    // Provenance: spikes/bun/bn3-lock-only/{before,after}/bun.lock — the
    // decisive lock-only pair, bun 1.3.14 (frozen install passes, plain
    // install + `bun ci` keep the after-lock byte-identical).
    const BN3_BEFORE_LOCK: &str = r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "bn3-lockonly",
      "dependencies": {
        "left-pad": "1.3.0",
      },
    },
  },
  "packages": {
    "left-pad": ["left-pad@1.3.0", "", {}, "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA=="],
  }
}
"#;
    const BN3_AFTER_LOCK: &str = r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "bn3-lockonly",
      "dependencies": {
        "left-pad": "1.3.0",
      },
    },
  },
  "packages": {
    "left-pad": ["left-pad@.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz", {}, "sha512-BeCz4t+xVlVhKgnBa2K5pAR1MKUgHxv3w9G4T/ADxBhxHNY1ByfS0zcyKi6WQYEM+W2MbTE5kpwwVpgkS//6lQ=="],
  }
}
"#;
    const BN3_PKG: &str = r#"{
  "name": "bn3-lockonly",
  "version": "1.0.0",
  "dependencies": {
    "left-pad": "1.3.0"
  }
}
"#;

    // Provenance: spikes/bun/bn4c-targeted-nested/{before,after}/bun.lock —
    // per-instance targeting: ONLY the nested "haspad/left-pad" (1.3.0)
    // moves; the root "left-pad" (1.2.0) stays the registry tuple.
    const BN4C_BEFORE_LOCK: &str = r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "bn4c-targeted",
      "dependencies": {
        "haspad": "file:./haspad-1.0.0.tgz",
        "left-pad": "1.2.0",
      },
    },
  },
  "packages": {
    "haspad": ["haspad@./haspad-1.0.0.tgz", { "dependencies": { "left-pad": "^1.3.0" } }, "sha512-Ct3JBgq1p/gbE4bZVj4DH8g6yueYk9gzR70Z0IXrjsI2UxcieFppUx84kdARnyO1wKM1p6dNw0hgTYnokLEtOQ=="],

    "left-pad": ["left-pad@1.2.0", "", {}, "sha512-OQadpCyFCT/VLniZQgym8d3/ofIJtuZyw2ibsVeIUOexKgW/osn8+mMFJbwGMPeDC4GnLzD8q115WPCDx4YRWg=="],

    "haspad/left-pad": ["left-pad@1.3.0", "", {}, "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA=="],
  }
}
"#;
    const BN4C_AFTER_LOCK: &str = r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "bn4c-targeted",
      "dependencies": {
        "haspad": "file:./haspad-1.0.0.tgz",
        "left-pad": "1.2.0",
      },
    },
  },
  "packages": {
    "haspad": ["haspad@./haspad-1.0.0.tgz", { "dependencies": { "left-pad": "^1.3.0" } }, "sha512-Ct3JBgq1p/gbE4bZVj4DH8g6yueYk9gzR70Z0IXrjsI2UxcieFppUx84kdARnyO1wKM1p6dNw0hgTYnokLEtOQ=="],

    "left-pad": ["left-pad@1.2.0", "", {}, "sha512-OQadpCyFCT/VLniZQgym8d3/ofIJtuZyw2ibsVeIUOexKgW/osn8+mMFJbwGMPeDC4GnLzD8q115WPCDx4YRWg=="],

    "haspad/left-pad": ["left-pad@.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz", {}, "sha512-BeCz4t+xVlVhKgnBa2K5pAR1MKUgHxv3w9G4T/ADxBhxHNY1ByfS0zcyKi6WQYEM+W2MbTE5kpwwVpgkS//6lQ=="],
  }
}
"#;

    // Scoped package: the vendored spec embeds an `@` inside the path
    // (`@scope/pkg@.socket/vendor/npm/<uuid>/@scope/pkg-1.0.0.tgz` — the
    // scope stays a real subdirectory in the tarball leaf), so name/path
    // splitting must not key on the LAST `@`.
    const SCOPED_BEFORE_LOCK: &str = r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "scoped-fixture",
      "dependencies": {
        "@scope/pkg": "1.0.0",
      },
    },
  },
  "packages": {
    "@scope/pkg": ["@scope/pkg@1.0.0", "", {}, "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA=="],
  }
}
"#;

    struct Fixture {
        tmp: tempfile::TempDir,
        record: PatchRecord,
        /// Where the patched instance is installed (nested for bn4c).
        installed: PathBuf,
    }

    impl Fixture {
        fn root(&self) -> &Path {
            self.tmp.path()
        }

        fn rel_tgz(&self) -> String {
            format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz")
        }

        async fn read_lock(&self) -> String {
            tokio::fs::read_to_string(self.root().join(BUN_LOCK))
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
            vendor_bun(
                "pkg:npm/left-pad@1.3.0",
                &self.installed,
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

    async fn fixture_with(lock: &str, installed_rel: &str) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        let installed = root.join(installed_rel);
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

        tokio::fs::write(root.join("package.json"), BN3_PKG)
            .await
            .unwrap();
        tokio::fs::write(root.join(BUN_LOCK), lock).await.unwrap();

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
            installed,
        }
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
    async fn bn3_fixture_oracle_transform_is_byte_identical_and_pkg_json_untouched() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("success carries a ledger entry");

        let actual = fx.actual_integrity().await;
        assert_ne!(
            actual, SPIKE_INTEGRITY,
            "different tarballs, different hashes"
        );
        assert_eq!(
            fx.read_lock().await,
            BN3_AFTER_LOCK.replace(SPIKE_INTEGRITY, &actual),
            "the BN3 transform, byte-for-byte (3-tuple arity, bare rel path, no file:/./)"
        );
        // LOCK-ONLY: package.json byte-untouched.
        assert_eq!(
            tokio::fs::read_to_string(fx.root().join("package.json"))
                .await
                .unwrap(),
            BN3_PKG
        );

        // Ledger facts.
        assert_eq!(entry.flavor.as_deref(), Some("bun"));
        assert!(entry.pnpm.is_none());
        assert_eq!(entry.artifact.path, fx.rel_tgz());
        assert_eq!(entry.wiring.len(), 1);
        let rec = &entry.wiring[0];
        assert_eq!(rec.file, BUN_LOCK);
        assert_eq!(rec.kind, KIND_LOCK_PACKAGE);
        assert_eq!(rec.action, WiringAction::Rewritten);
        assert_eq!(rec.key.as_deref(), Some("left-pad"));
        assert_eq!(
            rec.original.as_ref().and_then(Value::as_str).unwrap(),
            "    \"left-pad\": [\"left-pad@1.3.0\", \"\", {}, \"sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==\"],",
            "original = the verbatim pre-vendor entry line"
        );
    }

    #[tokio::test]
    async fn bn4c_nested_key_is_rewritten_and_the_other_version_stays_registry() {
        let fx = fixture_with(
            BN4C_BEFORE_LOCK,
            "node_modules/haspad/node_modules/left-pad",
        )
        .await;
        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();

        let actual = fx.actual_integrity().await;
        assert_eq!(
            fx.read_lock().await,
            BN4C_AFTER_LOCK.replace(SPIKE_INTEGRITY, &actual),
            "only the nested haspad/left-pad instance moves (scoping)"
        );
        assert_eq!(entry.wiring.len(), 1);
        assert_eq!(entry.wiring[0].key.as_deref(), Some("haspad/left-pad"));
    }

    #[tokio::test]
    async fn integrity_is_recomputed_from_the_packed_tarball() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();

        let tgz = tokio::fs::read(fx.root().join(fx.rel_tgz())).await.unwrap();
        let expected = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&tgz))
        );
        let live = fx.read_lock().await;
        assert!(
            live.contains(&format!("\"{expected}\"")),
            "lock must carry the recomputed tarball hash, never an inherited one: {live}"
        );
        assert!(!live.contains("sha512-XI5MPzVN"), "registry integrity gone");
        assert_eq!(
            entry.artifact.sha256,
            hex::encode(sha2::Sha256::digest(&tgz))
        );
        assert_eq!(entry.artifact.size, Some(tgz.len() as u64));
    }

    #[tokio::test]
    async fn deps_object_is_preserved_verbatim_with_a_note_when_manifest_rewritten() {
        // The target's registry tuple carries a deps object; it must move
        // from index 2 (4-tuple) to index 1 (3-tuple) VERBATIM.
        let lock = BN3_BEFORE_LOCK.replace(
            r#""left-pad": ["left-pad@1.3.0", "", {}, "#,
            r#""left-pad": ["left-pad@1.3.0", "", { "dependencies": { "wow": "^1.0.0" } }, "#,
        );
        let mut fx = fixture_with(&lock, "node_modules/left-pad").await;

        // The patch ALSO rewrites the package's own package.json.
        let before = br#"{"name":"left-pad","version":"1.3.0"}"#;
        let after: &[u8] =
            br#"{"name":"left-pad","version":"1.3.0","dependencies":{"wow":"^2.0.0"}}"#;
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
        let live = fx.read_lock().await;
        assert!(
            live.contains(&format!(
                "\"left-pad\": [\"left-pad@{}\", {{ \"dependencies\": {{ \"wow\": \"^1.0.0\" }} }}, \"sha512-",
                fx.rel_tgz()
            )),
            "deps object carried verbatim into the 3-tuple: {live}"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_dep_manifest_stale" && w.detail.contains("bun install")),
            "loud note that the deps mirror was NOT recomputed: {warnings:?}"
        );
    }

    const UUID_B: &str = "aaaaaaaa-1111-4111-8111-111111111111";

    /// Two patched versions of ONE package must vendor independently: the
    /// second pass must never classify the first pass's vendored tuple (same
    /// name, OTHER version) as its own stale edit and cross-clobber it.
    #[tokio::test]
    async fn two_vendored_versions_of_one_package_do_not_cross_clobber() {
        // Nested haspad/left-pad@1.3.0 (fx.record, UUID) + root left-pad@1.2.0
        // (record_b, UUID_B), each installed where its lock entry says.
        let fx = fixture_with(
            BN4C_BEFORE_LOCK,
            "node_modules/haspad/node_modules/left-pad",
        )
        .await;
        let root_installed = fx.root().join("node_modules/left-pad");
        tokio::fs::create_dir_all(&root_installed).await.unwrap();
        tokio::fs::write(
            root_installed.join("package.json"),
            br#"{"name":"left-pad","version":"1.2.0"}"#,
        )
        .await
        .unwrap();
        tokio::fs::write(root_installed.join("index.js"), ORIG_INDEX)
            .await
            .unwrap();
        let mut record_b = fx.record.clone();
        record_b.uuid = UUID_B.to_string();

        let (result_a, entry_a, _) = expect_done(fx.vendor(false).await);
        assert!(result_a.success, "{:?}", result_a.error);
        let entry_a = entry_a.unwrap();

        let blobs = fx.root().join(".socket/blobs");
        let sources = PatchSources::blobs_only(&blobs);
        let (result_b, entry_b, _) = expect_done(
            vendor_bun(
                "pkg:npm/left-pad@1.2.0",
                &root_installed,
                fx.root(),
                &record_b,
                &sources,
                "2026-06-09T00:00:00Z",
                false,
                false,
                None,
            )
            .await,
        );
        assert!(result_b.success, "{:?}", result_b.error);
        let entry_b = entry_b.unwrap();

        // Each instance points at ITS version's tarball under ITS uuid.
        let live = fx.read_lock().await;
        assert!(
            live.contains(&format!(
                "\"haspad/left-pad\": [\"left-pad@.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz\""
            )),
            "the 1.3.0 instance must survive the 1.2.0 pass untouched: {live}"
        );
        assert!(
            live.contains(&format!(
                "\"left-pad\": [\"left-pad@.socket/vendor/npm/{UUID_B}/left-pad-1.2.0.tgz\""
            )),
            "the 1.2.0 instance lands under its own uuid: {live}"
        );
        // The second pass edits exactly ONE entry and keeps its true
        // pre-vendor registry original (revert data).
        assert_eq!(entry_b.wiring.len(), 1, "{:?}", entry_b.wiring);
        assert_eq!(entry_b.wiring[0].key.as_deref(), Some("left-pad"));
        assert!(
            entry_b.wiring[0]
                .original
                .as_ref()
                .and_then(Value::as_str)
                .is_some_and(|o| o.contains("\"left-pad@1.2.0\"")),
            "original = the registry 1.2.0 tuple: {:?}",
            entry_b.wiring[0].original
        );

        // Full revert round-trips the lock byte-exactly, no drift warnings.
        for entry in [&entry_b, &entry_a] {
            let outcome = revert_bun(entry, fx.root(), false).await;
            assert!(outcome.success, "{:?}", outcome.error);
            assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        }
        assert_eq!(fx.read_lock().await, BN4C_BEFORE_LOCK, "lock byte-restored");
        assert!(!fx
            .root()
            .join(format!(".socket/vendor/npm/{UUID}"))
            .exists());
        assert!(!fx
            .root()
            .join(format!(".socket/vendor/npm/{UUID_B}"))
            .exists());
    }

    /// Pre-flight: a lock whose only same-name entries are vendored tuples
    /// for ANOTHER version has nothing rewritable — refuse, never rewrite.
    #[tokio::test]
    async fn preflight_refuses_when_only_other_version_vendored_tuples_exist() {
        // BN3_AFTER_LOCK's only left-pad entry is a vendored 1.3.0 3-tuple;
        // target 1.2.0.
        let fx = fixture_with(BN3_AFTER_LOCK, "node_modules/left-pad").await;
        tokio::fs::write(
            fx.installed.join("package.json"),
            br#"{"name":"left-pad","version":"1.2.0"}"#,
        )
        .await
        .unwrap();
        let mut record = fx.record.clone();
        record.uuid = UUID_B.to_string();
        let blobs = fx.root().join(".socket/blobs");
        let sources = PatchSources::blobs_only(&blobs);
        let outcome = vendor_bun(
            "pkg:npm/left-pad@1.2.0",
            &fx.installed,
            fx.root(),
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            None,
        )
        .await;
        expect_refused(outcome, "vendor_lock_entry_not_found");
        assert_eq!(
            fx.read_lock().await,
            BN3_AFTER_LOCK,
            "the other version's vendored tuple is never touched"
        );
        assert!(!fx
            .root()
            .join(format!(".socket/vendor/npm/{UUID_B}"))
            .exists());
    }

    /// A CRLF lock must stay CRLF: the rewritten entry line re-emits its
    /// trailing `\r`, and revert byte-restores the CRLF original.
    #[tokio::test]
    async fn crlf_lock_keeps_crlf_on_rewritten_lines_and_reverts_byte_exact() {
        let crlf_before = BN3_BEFORE_LOCK.replace('\n', "\r\n");
        let fx = fixture_with(&crlf_before, "node_modules/left-pad").await;
        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();

        let actual = fx.actual_integrity().await;
        assert_eq!(
            fx.read_lock().await,
            BN3_AFTER_LOCK
                .replace(SPIKE_INTEGRITY, &actual)
                .replace('\n', "\r\n"),
            "every line — including the rewritten one — still ends \\r\\n"
        );

        // In-sync re-run stays byte-stable.
        let lock_first = fx.read_lock().await;
        let (result, rerun_entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(rerun_entry.is_none(), "in-sync re-run records nothing");
        assert_eq!(fx.read_lock().await, lock_first);

        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert_eq!(
            fx.read_lock().await,
            crlf_before,
            "CRLF original byte-restored"
        );
    }

    #[tokio::test]
    async fn no_matching_entry_is_refused() {
        // The lock only knows left-pad@1.2.0; the exact 1.3.0 tuple is
        // absent (only the exact version is ever rewritten).
        let lock = BN3_BEFORE_LOCK.replace("left-pad@1.3.0", "left-pad@1.2.0");
        let fx = fixture_with(&lock, "node_modules/left-pad").await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_not_found");
        assert!(
            detail.contains("bun install"),
            "actionable detail: {detail}"
        );
        assert_eq!(fx.read_lock().await, lock, "refusal writes nothing");
        assert!(!fx.root().join(".socket/vendor").exists());
    }

    #[tokio::test]
    async fn unparseable_entry_line_fails_closed_before_any_write() {
        for bad in [
            "    \"left-pad\": [\"left-pad@1.3.0\", \"\", {},", // unterminated
            "    \"left-pad\": {\"not\": \"a tuple\"},",        // not an array
            "    bare-key: [\"x@1\", \"\", {}, \"sha\"],",      // unquoted key
        ] {
            let lock = BN3_BEFORE_LOCK.replace(
                "    \"left-pad\": [\"left-pad@1.3.0\", \"\", {}, \"sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==\"],",
                bad,
            );
            assert_ne!(lock, BN3_BEFORE_LOCK, "replacement must hit");
            let fx = fixture_with(&lock, "node_modules/left-pad").await;
            let detail = expect_refused(
                fx.vendor(false).await,
                "vendor_lockfile_version_unsupported",
            );
            assert!(detail.contains("packages section"), "{detail}");
            assert_eq!(fx.read_lock().await, lock, "fail-closed: lock untouched");
            assert!(
                !fx.root().join(".socket/vendor").exists(),
                "nothing staged/packed"
            );
        }
    }

    #[tokio::test]
    async fn missing_lock_and_unsupported_version_are_refused() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        tokio::fs::remove_file(fx.root().join(BUN_LOCK))
            .await
            .unwrap();
        let detail = expect_refused(fx.vendor(false).await, "vendor_lockfile_missing");
        assert!(detail.contains("bun install"), "{detail}");

        let lock = BN3_BEFORE_LOCK.replace("\"lockfileVersion\": 1,", "\"lockfileVersion\": 3,");
        let fx = fixture_with(&lock, "node_modules/left-pad").await;
        let detail = expect_refused(
            fx.vendor(false).await,
            "vendor_lockfile_version_unsupported",
        );
        assert!(detail.contains('3'), "{detail}");
    }

    /// bun >= 1.4 writes `"lockfileVersion": 2` over the SAME emitted grammar
    /// (the bump gates stricter parse checks, not new entry shapes), so
    /// vendoring must proceed exactly as on a v1 lock, and the version line
    /// must survive verbatim.
    #[tokio::test]
    async fn lock_v2_vendors_like_v1() {
        let lock = BN3_BEFORE_LOCK.replace("\"lockfileVersion\": 1,", "\"lockfileVersion\": 2,");
        assert_ne!(lock, BN3_BEFORE_LOCK, "replacement must hit");
        let fx = fixture_with(&lock, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        assert!(entry.is_some(), "the vendor run must record an entry");
        let rewritten = fx.read_lock().await;
        assert!(
            rewritten.contains("\"lockfileVersion\": 2,"),
            "the version line must be preserved verbatim: {rewritten}"
        );
        assert!(
            rewritten.contains(".socket/vendor/npm/"),
            "the packages entry must point at the vendored tarball: {rewritten}"
        );
    }

    #[tokio::test]
    async fn rerun_is_in_sync_and_byte_stable() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        assert!(entry.is_some());
        let lock_first = fx.read_lock().await;
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
        assert_eq!(fx.read_lock().await, lock_first, "lock byte-stable");
        assert_eq!(
            tokio::fs::read(fx.root().join(fx.rel_tgz())).await.unwrap(),
            tgz_first,
            "tarball byte-identical across re-runs"
        );
    }

    // ── lockfileVersion 0 + workspace locks: real per-version grammar ─────
    //
    // Provenance (real `bun install --save-text-lockfile` output, verified
    // 2026-09-18 on a root + `packages/consumer` workspace project):
    //   bun 1.1.45 (v0): no `configVersion` line; the root's workspace dep
    //     is spelled as a bare path (`"consumer": "packages/consumer"`);
    //     the member's packages entry is a 2-TUPLE carrying its deps object
    //     (`{}` when dep-less).
    //   bun 1.3.14 (v1) / 1.4.2 (v2): `configVersion: 1`; `workspace:*`;
    //     the 1-tuple `["consumer@workspace:packages/consumer"]`.
    // Entries are separated by a blank line. Registry 4-tuples are
    // grammar-identical across 0/1/2.

    /// Re-head a BN3 lock (before or after) as `lockfileVersion`: the
    /// integer, and — on 0 — no `configVersion` line.
    fn as_lock_version(base: &str, version: u64) -> String {
        let lock = base.replace(
            "\"lockfileVersion\": 1,",
            &format!("\"lockfileVersion\": {version},"),
        );
        if version == 0 {
            lock.replace("  \"configVersion\": 1,\n", "")
        } else {
            lock
        }
    }

    /// The `packages` entry bun writes for the `consumer` workspace member
    /// at `lockfileVersion`.
    fn workspace_entry_line(version: u64) -> &'static str {
        if version == 0 {
            "    \"consumer\": [\"consumer@workspace:packages/consumer\", { \"dependencies\": { \"left-pad\": \"1.3.0\" } }],"
        } else {
            "    \"consumer\": [\"consumer@workspace:packages/consumer\"],"
        }
    }

    /// Add the `consumer` workspace member to a BN3-shaped lock the way bun
    /// of that `lockfileVersion` spells it (root dep + first packages entry
    /// + blank-line separator). Works on a pre- or post-vendor lock.
    fn with_workspace_member(base: &str, version: u64) -> String {
        let root_dep = if version == 0 {
            "packages/consumer"
        } else {
            "workspace:*"
        };
        let lock = base
            .replace(
                "        \"left-pad\": \"1.3.0\",",
                &format!("        \"consumer\": \"{root_dep}\",\n        \"left-pad\": \"1.3.0\","),
            )
            .replace(
                "  \"packages\": {\n",
                &format!("  \"packages\": {{\n{}\n\n", workspace_entry_line(version)),
            );
        assert_ne!(lock, base, "the workspace splice must hit");
        lock
    }

    /// A BN3 lock re-spelled as a `lockfileVersion` workspace lock.
    fn as_workspace_lock(base: &str, version: u64) -> String {
        with_workspace_member(&as_lock_version(base, version), version)
    }

    /// The converging remedy: names the lock's version, says to DELETE the
    /// lock (an in-place `bun install` keeps the version), and offers
    /// hosted mode in a VERSION-SPECIFIC tail — hosted accepts a v1
    /// workspace lock as-is but refuses a v0 one, so the v0 tail must say
    /// to re-lock with Bun >= 1.2 first instead of sending the user into a
    /// second refusal.
    fn assert_workspace_remedy(detail: &str, version: u64) {
        assert!(detail.contains("Bun releases before 1.4"), "{detail}");
        assert!(
            detail.contains(&format!("lockfileVersion-{version} lock")),
            "the detail must name the actual version integer: {detail}"
        );
        assert!(detail.contains("delete bun.lock"), "{detail}");
        assert!(
            detail.contains("in-place `bun install` keeps the existing lockfileVersion"),
            "{detail}"
        );
        let tail = if version == 0 {
            "— or delete bun.lock, re-lock with Bun >= 1.2 (which writes lockfileVersion 1) and \
             use `--mode hosted`"
        } else {
            "— or use `--mode hosted`, which accepts version-1 workspace locks"
        };
        assert!(
            detail.ends_with(tail),
            "v{version}: the hosted alternative must be version-specific:\n{detail}"
        );
        if version == 0 {
            assert!(
                !detail.contains("accepts version-1"),
                "a v0 lock must not be told hosted accepts it as-is: {detail}"
            );
        }
        assert!(
            !detail.contains("upgrade to Bun"),
            "the non-converging remedy must be gone: {detail}"
        );
    }

    /// Fresh vendoring on a workspace lock: lockfileVersion 0 and 1 refuse
    /// BEFORE any write (preflight and engine alike) with the converging
    /// remedy; 2 vendors byte-exactly — the workspace line survives — and
    /// reverts byte-exactly.
    #[tokio::test]
    async fn legacy_workspace_tarballs_refuse_before_writes() {
        for version in [0u64, 1, 2] {
            let lock = as_workspace_lock(BN3_BEFORE_LOCK, version);
            let fx = fixture_with(&lock, "node_modules/left-pad").await;
            if version < 2 {
                let (code, detail) = preflight_vendor(fx.root()).await.unwrap_err();
                assert_eq!(code, "vendor_bun_workspace_unsupported", "v{version}");
                assert_workspace_remedy(&detail, version);
                let detail =
                    expect_refused(fx.vendor(false).await, "vendor_bun_workspace_unsupported");
                assert_workspace_remedy(&detail, version);
                assert_eq!(
                    fx.read_lock().await,
                    lock,
                    "v{version}: refusal writes nothing"
                );
                assert!(!fx.root().join(".socket/vendor").exists(), "v{version}");
            } else {
                assert!(preflight_vendor(fx.root()).await.is_ok());
                let (result, entry, _) = expect_done(fx.vendor(false).await);
                assert!(result.success, "{:?}", result.error);
                let entry = entry.expect("success carries a ledger entry");
                assert_eq!(
                    fx.read_lock().await,
                    as_workspace_lock(BN3_AFTER_LOCK, version)
                        .replace(SPIKE_INTEGRITY, &fx.actual_integrity().await),
                    "the BN3 transform byte-for-byte, workspace line intact"
                );
                let outcome = revert_bun(&entry, fx.root(), false).await;
                assert!(outcome.success, "{:?}", outcome.error);
                assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
                assert_eq!(
                    fx.read_lock().await,
                    lock,
                    "revert byte-restores the workspace lock"
                );
            }
        }
    }

    /// Fresh vendor on a v0/v1 workspace lock — a `Registry` target instance,
    /// so the run WOULD write a new local-tarball tuple — still refuses,
    /// even when a stale uuid dir already sits under `.socket/vendor/`
    /// (classification is by lock tuple, never by artifact presence).
    #[tokio::test]
    async fn fresh_vendor_on_v1_workspace_lock_still_refuses() {
        for version in [0u64, 1] {
            let lock = as_workspace_lock(BN3_BEFORE_LOCK, version);
            let fx = fixture_with(&lock, "node_modules/left-pad").await;
            let stale_dir = fx.root().join(format!(".socket/vendor/npm/{UUID}"));
            tokio::fs::create_dir_all(&stale_dir).await.unwrap();
            let detail = expect_refused(fx.vendor(false).await, "vendor_bun_workspace_unsupported");
            assert_workspace_remedy(&detail, version);
            assert_eq!(
                fx.read_lock().await,
                lock,
                "v{version}: refusal writes nothing"
            );
            assert!(
                !fx.root().join(fx.rel_tgz()).exists(),
                "v{version}: nothing staged or packed"
            );
        }
    }

    /// The upgrade shape the gate must not regress: a plain v0/v1 lock
    /// vendored (as every earlier release did), then the user adds a
    /// workspace member and runs `bun install` in place — bun keeps the
    /// version and leaves the vendored tuple byte-identical (verified with
    /// bun 1.3.14). Returns the fixture, its ledger entry and the resulting
    /// workspace lock text.
    async fn vendored_then_workspace_added(version: u64) -> (Fixture, VendorEntry, String) {
        let fx = fixture_with(
            &as_lock_version(BN3_BEFORE_LOCK, version),
            "node_modules/left-pad",
        )
        .await;
        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "v{version}: {:?}", result.error);
        let entry = entry.expect("fresh vendor records an entry");
        let lock = with_workspace_member(&fx.read_lock().await, version);
        tokio::fs::write(fx.root().join(BUN_LOCK), &lock)
            .await
            .unwrap();
        (fx, entry, lock)
    }

    /// Every matching instance is already ours: the in-sync re-run must
    /// synthesize AlreadyPatched (exit-0 `already_vendored` upstream), not
    /// refuse — the lock already carries the local tuple whatever this run
    /// does. The project-level preflight still refuses (it cannot see
    /// per-purl state; the CLI exempts already-vendored purls before it).
    #[tokio::test]
    async fn in_sync_rerun_on_v1_workspace_lock_is_already_patched_not_refused() {
        for version in [0u64, 1] {
            let (fx, _entry, lock) = vendored_then_workspace_added(version).await;
            assert_eq!(
                preflight_vendor(fx.root()).await.unwrap_err().0,
                "vendor_bun_workspace_unsupported",
                "v{version}: the project-level gate stays blanket"
            );
            let (result, entry, _) = expect_done(fx.vendor(false).await);
            assert!(result.success, "v{version}: {:?}", result.error);
            assert!(
                entry.is_none(),
                "v{version}: in-sync re-run records nothing"
            );
            assert!(
                result
                    .files_verified
                    .iter()
                    .all(|v| v.status == VerifyStatus::AlreadyPatched),
                "v{version}: {:?}",
                result.files_verified
            );
            assert_eq!(fx.read_lock().await, lock, "v{version}: lock byte-stable");
        }
    }

    /// `repair` on a missing artifact drives this exact call: the target
    /// instance is `Ours`, so the gate is skipped, the artifact is re-packed
    /// byte-identically and the lock is left alone — instead of refusing and
    /// leaving the lock pointing at a tarball nobody rebuilt.
    #[tokio::test]
    async fn rebuild_on_missing_tarball_on_v1_workspace_lock_succeeds() {
        for version in [0u64, 1] {
            let (fx, _entry, lock) = vendored_then_workspace_added(version).await;
            let tgz_path = fx.root().join(fx.rel_tgz());
            let tgz_bytes = tokio::fs::read(&tgz_path).await.unwrap();
            remove_tree(&fx.root().join(format!(".socket/vendor/npm/{UUID}")))
                .await
                .unwrap();
            assert!(!tgz_path.exists(), "v{version}: setup deletes the artifact");

            let (result, entry, _) = expect_done(fx.vendor(false).await);
            assert!(result.success, "v{version}: {:?}", result.error);
            assert!(entry.is_none(), "v{version}: the lock needed no edit");
            assert_eq!(
                tokio::fs::read(&tgz_path).await.unwrap(),
                tgz_bytes,
                "v{version}: deterministic rebuild reproduces the recorded bytes"
            );
            assert_eq!(fx.read_lock().await, lock, "v{version}: lock byte-stable");
        }
    }

    /// The CLI's lock-derived exemption mirrors the engine's gate: on the
    /// upgrade shape (vendored, then a workspace member added) every
    /// instance is ours — at the recorded uuid, at a superseding uuid the
    /// ledger has never seen, and in the digest-less 2-tuple spelling — so
    /// the project-level refusal still fires but the purl is exempt; a
    /// fresh registry instance and a purl the lock does not resolve are not.
    #[tokio::test]
    async fn wired_instances_all_ours_mirrors_the_engine_gate() {
        const PURL: &str = "pkg:npm/left-pad@1.3.0";
        for version in [0u64, 1] {
            let (fx, entry, lock) = vendored_then_workspace_added(version).await;
            assert_eq!(
                preflight_vendor(fx.root()).await.unwrap_err().0,
                "vendor_bun_workspace_unsupported",
                "v{version}: the project-level gate stays blanket"
            );
            assert_eq!(
                wired_instances_all_ours(fx.root(), PURL).await,
                Ok(true),
                "v{version}: the vendored tuple is ours"
            );
            // Another version of the same package is someone else's edit.
            assert_eq!(
                wired_instances_all_ours(fx.root(), "pkg:npm/left-pad@1.2.0").await,
                Ok(false),
                "v{version}: an unresolved purl is not exempt"
            );
            assert_eq!(
                wired_instances_all_ours(fx.root(), "pkg:pypi/left-pad@1.3.0").await,
                Ok(false),
                "v{version}: a non-npm purl can never be ours"
            );
            // The digest-less re-save (Bun < 1.3.10) is still our wiring.
            let (_, digestless) = digestless_lock(&lock, &entry);
            tokio::fs::write(fx.root().join(BUN_LOCK), &digestless)
                .await
                .unwrap();
            assert_eq!(
                wired_instances_all_ours(fx.root(), PURL).await,
                Ok(true),
                "v{version}: the digest-less 2-tuple is ours"
            );
            // A superseding uuid: the ledger would not match, the lock does.
            let other_uuid = "0a1b2c3d-4e5f-4a7b-8c9d-0e1f2a3b4c5d";
            tokio::fs::write(fx.root().join(BUN_LOCK), lock.replace(UUID, other_uuid))
                .await
                .unwrap();
            assert_eq!(
                wired_instances_all_ours(fx.root(), PURL).await,
                Ok(true),
                "v{version}: any uuid of ours counts"
            );

            // A fresh registry instance is exactly what the gate refuses.
            let fresh = fixture_with(
                &as_workspace_lock(BN3_BEFORE_LOCK, version),
                "node_modules/left-pad",
            )
            .await;
            assert_eq!(
                wired_instances_all_ours(fresh.root(), PURL).await,
                Ok(false),
                "v{version}: a registry tuple would be rewritten"
            );
        }

        // Unreadable or unsupported locks mirror `preflight_vendor`'s codes.
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            wired_instances_all_ours(root.path(), PURL)
                .await
                .unwrap_err()
                .0,
            "vendor_lockfile_missing"
        );
        tokio::fs::write(root.path().join(BUN_LOCK), "{}")
            .await
            .unwrap();
        assert_eq!(
            wired_instances_all_ours(root.path(), PURL)
                .await
                .unwrap_err()
                .0,
            "vendor_lockfile_version_unsupported"
        );
    }

    /// A version-0 head (real bun 1.1.45 shape: no `configVersion`) vendors
    /// with the exact BN3 transform and reverts byte-exactly.
    #[tokio::test]
    async fn lock_v0_vendor_and_revert_preserve_bytes() {
        let lock = as_lock_version(BN3_BEFORE_LOCK, 0);
        let fx = fixture_with(&lock, "node_modules/left-pad").await;
        assert!(preflight_vendor(fx.root()).await.is_ok());
        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert_eq!(
            fx.read_lock().await,
            as_lock_version(BN3_AFTER_LOCK, 0)
                .replace(SPIKE_INTEGRITY, &fx.actual_integrity().await),
            "the BN3 transform byte-for-byte under a version-0 head"
        );
        let entry = entry.expect("success carries a ledger entry");
        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert_eq!(fx.read_lock().await, lock, "lock byte-restored");
    }

    #[tokio::test]
    async fn download_preflight_refuses_binary_and_malformed_bun_locks() {
        let root = tempfile::tempdir().unwrap();
        assert!(preflight_vendor(root.path()).await.is_ok());
        tokio::fs::write(root.path().join("bun.lockb"), b"binary")
            .await
            .unwrap();
        let (code, detail) = preflight_vendor(root.path()).await.unwrap_err();
        assert_eq!(code, "vendor_bun_lockb_unsupported");
        // The contract's remedy, from the ONE shared text (the router emits
        // the same string for the same code).
        assert_eq!(detail, BUN_LOCKB_UNSUPPORTED_DETAIL);
        assert!(
            detail.contains("bun install --save-text-lockfile") && detail.contains("1.1.39"),
            "remedy + version floor: {detail}"
        );
        assert!(!detail.contains("upgrade Bun"), "{detail}");
        tokio::fs::write(root.path().join(BUN_LOCK), BN3_BEFORE_LOCK)
            .await
            .unwrap();
        assert!(preflight_vendor(root.path()).await.is_ok());
        tokio::fs::write(root.path().join(BUN_LOCK), "{}")
            .await
            .unwrap();
        assert_eq!(
            preflight_vendor(root.path()).await.unwrap_err().0,
            "vendor_lockfile_version_unsupported"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn download_preflight_refuses_fifo_without_blocking() {
        let root = tempfile::tempdir().unwrap();
        assert!(std::process::Command::new("mkfifo")
            .arg(root.path().join(BUN_LOCK))
            .status()
            .unwrap()
            .success());
        let refusal = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            preflight_vendor(root.path()),
        )
        .await
        .expect("Bun preflight must not block on a FIFO")
        .unwrap_err();
        assert_eq!(refusal.0, "vendor_lockfile_missing");
    }

    /// Build a scoped-package fixture and vendor it once (not dry).
    async fn scoped_fixture() -> Fixture {
        let fx = fixture_with(SCOPED_BEFORE_LOCK, "node_modules/@scope/pkg").await;
        tokio::fs::write(
            fx.installed.join("package.json"),
            br#"{"name":"@scope/pkg","version":"1.0.0"}"#,
        )
        .await
        .unwrap();
        fx
    }

    async fn vendor_scoped(fx: &Fixture) -> VendorOutcome {
        let blobs = fx.root().join(".socket/blobs");
        let sources = PatchSources::blobs_only(&blobs);
        vendor_bun(
            "pkg:npm/@scope/pkg@1.0.0",
            &fx.installed,
            fx.root(),
            &fx.record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            None,
        )
        .await
    }

    #[tokio::test]
    async fn scoped_package_rerun_is_in_sync_not_refused() {
        let fx = scoped_fixture().await;
        let (result, entry, _) = expect_done(vendor_scoped(&fx).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());
        let lock_first = fx.read_lock().await;
        assert!(
            lock_first.contains(&format!(
                "\"@scope/pkg@.socket/vendor/npm/{UUID}/@scope/pkg-1.0.0.tgz\""
            )),
            "vendored spec keeps the scope dir in the leaf: {lock_first}"
        );

        // The in-sync re-run must synthesize AlreadyPatched, not refuse.
        let (result, entry, _) = expect_done(vendor_scoped(&fx).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_none(), "in-sync re-run records nothing");
        assert!(
            result
                .files_verified
                .iter()
                .all(|v| v.status == VerifyStatus::AlreadyPatched),
            "{:?}",
            result.files_verified
        );
        assert_eq!(fx.read_lock().await, lock_first, "lock byte-stable");
    }

    #[tokio::test]
    async fn scoped_reserialized_entry_is_still_ours_on_revert() {
        let fx = scoped_fixture().await;
        let (_, entry, _) = expect_done(vendor_scoped(&fx).await);
        let entry = entry.unwrap();

        // Simulate bun re-serializing the line without moving the entry:
        // same key, same tuple, trailing comma dropped. The uuid-ownership
        // fallback (not the byte-exact compare) must still claim it.
        let live = fx.read_lock().await;
        let new_line = entry.wiring[0]
            .new
            .as_ref()
            .and_then(Value::as_str)
            .unwrap();
        let reserialized = new_line.strip_suffix(',').unwrap();
        tokio::fs::write(
            fx.root().join(BUN_LOCK),
            live.replacen(new_line, reserialized, 1),
        )
        .await
        .unwrap();

        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome.warnings.is_empty(),
            "an unmoved entry is ours, not drift: {:?}",
            outcome.warnings
        );
        assert_eq!(
            fx.read_lock().await,
            SCOPED_BEFORE_LOCK,
            "registry tuple byte-restored"
        );
        assert!(!fx
            .root()
            .join(format!(".socket/vendor/npm/{UUID}"))
            .exists());
    }

    #[tokio::test]
    async fn dry_run_writes_nothing() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (result, entry, _) = expect_done(fx.vendor(true).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_none());
        assert!(result.files_patched.is_empty());

        assert_eq!(fx.read_lock().await, BN3_BEFORE_LOCK);
        assert!(!fx.root().join(".socket/vendor").exists());
        assert_eq!(
            tokio::fs::read(fx.installed.join("index.js"))
                .await
                .unwrap(),
            ORIG_INDEX,
            "vendor never patches in place"
        );
    }

    #[tokio::test]
    async fn revert_round_trips_the_lock_and_removes_the_artifact() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let tgz_path = fx.root().join(fx.rel_tgz());
        assert!(tgz_path.exists());

        // Dry-run revert touches nothing.
        let outcome = revert_bun(&entry, fx.root(), true).await;
        assert!(outcome.success);
        assert!(tgz_path.exists());
        assert_ne!(fx.read_lock().await, BN3_BEFORE_LOCK);

        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert_eq!(fx.read_lock().await, BN3_BEFORE_LOCK, "lock byte-restored");
        assert!(!tgz_path.exists());
        assert!(!fx
            .root()
            .join(format!(".socket/vendor/npm/{UUID}"))
            .exists());
    }

    /// bun.lock is a user-owned file we merely edit: the vendor rewrite and
    /// the revert restore must keep its permission bits (a 0600 private lock
    /// must not silently become umask-default 0644).
    #[cfg(unix)]
    #[tokio::test]
    async fn lock_writes_preserve_file_mode() {
        use std::os::unix::fs::PermissionsExt;
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let lock_path = fx.root().join(BUN_LOCK);
        tokio::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600))
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
            mode(lock_path.clone()).await,
            0o600,
            "vendor must preserve bun.lock's mode"
        );

        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            mode(lock_path).await,
            0o600,
            "revert must preserve bun.lock's mode"
        );
    }

    #[tokio::test]
    async fn revert_allowlist_is_fail_closed() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let mut entry = entry.unwrap();
        // A poisoned ledger names a file outside the allowlist.
        tokio::fs::write(fx.root().join("package.json.bak"), b"precious")
            .await
            .unwrap();
        entry.wiring.push(WiringRecord {
            file: "package.json.bak".to_string(),
            kind: KIND_LOCK_PACKAGE.to_string(),
            action: WiringAction::Rewritten,
            key: Some("left-pad".to_string()),
            original: Some(Value::String("overwritten!".to_string())),
            new: Some(Value::String("x".to_string())),
        });

        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"
                    && w.detail.contains("package.json.bak")),
            "{:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read(fx.root().join("package.json.bak"))
                .await
                .unwrap(),
            b"precious",
            "non-allowlisted file never touched"
        );
        assert_eq!(
            fx.read_lock().await,
            BN3_BEFORE_LOCK,
            "real record still restored"
        );
    }

    #[tokio::test]
    async fn revert_leaves_drifted_entries_alone_with_warning() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();

        // The user re-resolved the entry behind our back (`bun update`).
        let drifted_line = "    \"left-pad\": [\"left-pad@1.3.1\", \"\", {}, \"sha512-other==\"],";
        let live = fx.read_lock().await;
        let new_line = entry.wiring[0]
            .new
            .as_ref()
            .and_then(Value::as_str)
            .unwrap();
        let drifted_lock = live.replace(new_line, drifted_line);
        assert_ne!(
            drifted_lock, live,
            "test setup must actually drift the entry"
        );
        tokio::fs::write(fx.root().join(BUN_LOCK), &drifted_lock)
            .await
            .unwrap();

        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted" && w.detail.contains("left-pad")),
            "{:?}",
            outcome.warnings
        );
        assert!(
            fx.read_lock().await.contains(drifted_line),
            "drifted entry left alone"
        );
        // Residual #131: a drift-skip keeps the artifact dir (the drifted
        // entry's recorded original may still be needed later) and says so.
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

        // KEEP-GATE LIVENESS: undo the drift (repoint the entry back at the
        // vendored tuple) — the same revert must then complete fully
        // instead of ratcheting the keep forever.
        let healed = fx.read_lock().await.replace(drifted_line, new_line);
        tokio::fs::write(fx.root().join(BUN_LOCK), &healed)
            .await
            .unwrap();

        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome.warnings.is_empty(),
            "no drift left after the undo: {:?}",
            outcome.warnings
        );
        assert!(!outcome.kept_artifact);
        assert_eq!(fx.read_lock().await, BN3_BEFORE_LOCK, "lock byte-restored");
        assert!(
            !fx.root()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "artifact pruned once the revert converges"
        );
    }

    // ── empty-wiring (reconstructed) revert guard ──────────────────────────

    /// Reshape a vendored entry into what `repair`'s no-ledger
    /// reconstruction persists: same uuid/artifact, EMPTY wiring. With
    /// nothing to replay, revert must refuse (fail-closed) while bun.lock
    /// still resolves through the artifact — dry-run preview included —
    /// still remove a genuinely orphaned artifact, fail closed on an
    /// unreadable lock, and proceed when no lock exists at all.
    #[tokio::test]
    async fn empty_wiring_revert_guards_against_bricking_installs() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let mut entry = entry.unwrap();
        entry.wiring.clear();
        let tgz_path = fx.root().join(fx.rel_tgz());
        let lock_vendored = fx.read_lock().await;

        // Still referenced: refuse, artifact and lock untouched.
        for dry_run in [true, false] {
            let outcome = revert_bun(&entry, fx.root(), dry_run).await;
            assert!(!outcome.success, "dry_run={dry_run}: must refuse");
            assert!(
                outcome
                    .warnings
                    .iter()
                    .any(|w| w.code == "vendor_wiring_unknown_revert_blocked"),
                "{:?}",
                outcome.warnings
            );
            assert!(tgz_path.exists(), "artifact survives the refusal");
            assert_eq!(fx.read_lock().await, lock_vendored, "lock untouched");
        }

        // Unreadable lock (not UTF-8): undeterminable, fail closed.
        tokio::fs::write(fx.root().join(BUN_LOCK), [0xff, 0xfe, b'x'])
            .await
            .unwrap();
        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(!outcome.success, "unreadable-lock revert must refuse");
        assert!(tgz_path.exists());

        // Re-locked away from the artifact (provably orphaned): removal
        // proceeds, replaying nothing.
        tokio::fs::write(fx.root().join(BUN_LOCK), BN3_BEFORE_LOCK)
            .await
            .unwrap();
        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(!tgz_path.exists(), "orphaned artifact removed");
        assert_eq!(
            fx.read_lock().await,
            BN3_BEFORE_LOCK,
            "empty wiring replays nothing"
        );

        // No lock at all: nothing can reference the artifact — proceed.
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let mut entry = entry.unwrap();
        entry.wiring.clear();
        tokio::fs::remove_file(fx.root().join(BUN_LOCK))
            .await
            .unwrap();
        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !fx.root().join(fx.rel_tgz()).exists(),
            "no lock, no reference"
        );
    }

    /// `--preserve-state` (`keep_artifact`) with empty wiring: the
    /// deletion-protecting refusal above must be SKIPPED (the fn doc and
    /// composer's reference implementation both promise it — a
    /// preserve-state revert deletes nothing), so the revert completes as
    /// a successful no-op with lock and artifact intact. Dry-run preview
    /// included: it must never advertise a refusal the wet preserve-state
    /// run does not hit.
    #[tokio::test]
    async fn empty_wiring_preserve_state_revert_skips_the_deletion_refusal() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let mut entry = entry.unwrap();
        entry.wiring.clear();
        let tgz_path = fx.root().join(fx.rel_tgz());
        let lock_vendored = fx.read_lock().await;

        for dry_run in [true, false] {
            let outcome = revert_bun_opts(
                &entry,
                fx.root(),
                RevertOpts {
                    dry_run,
                    keep_artifact: true,
                },
            )
            .await;
            assert!(
                outcome.success,
                "dry_run={dry_run}: preserve-state deletes nothing, so the \
                 deletion guard must not fire: {:?}",
                outcome.error
            );
            assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
            assert!(!outcome.kept_artifact, "preserve-state is not a drift-keep");
            assert!(tgz_path.exists(), "artifact kept");
            assert_eq!(
                fx.read_lock().await,
                lock_vendored,
                "empty wiring replays nothing"
            );
        }
    }

    #[tokio::test]
    async fn revert_refuses_tampered_uuid_fail_closed() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let mut entry = entry.unwrap();
        entry.uuid = "../../x".to_string();
        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(!outcome.success, "tampered uuid must fail closed");
    }

    // ── refusal glue: shared npm_common guards bubble through vendor_bun ──

    #[tokio::test]
    async fn unsafe_purl_coordinates_are_refused_before_any_write() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let blobs = fx.root().join(".socket/blobs");
        let sources = PatchSources::blobs_only(&blobs);
        // `..` fails is_safe_single_segment: a hostile version segment must
        // never reach the lock rewrite or name a path inside the project.
        let outcome = vendor_bun(
            "pkg:npm/left-pad@..",
            &fx.installed,
            fx.root(),
            &fx.record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            None,
        )
        .await;
        expect_refused(outcome, "unsafe_coordinates");
        assert_eq!(
            fx.read_lock().await,
            BN3_BEFORE_LOCK,
            "refusal writes nothing"
        );
        assert!(!fx.root().join(".socket/vendor").exists());
    }

    #[tokio::test]
    async fn bundled_deps_package_is_refused_before_pack() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        // Bundled deps ship INSIDE the tarball; repacking after the staged
        // node_modules prune would produce a tarball bun cannot satisfy
        // them from — the shared pipeline refuses before patching.
        tokio::fs::write(
            fx.installed.join("package.json"),
            br#"{"name":"left-pad","version":"1.3.0","bundleDependencies":true}"#,
        )
        .await
        .unwrap();
        let detail = expect_refused(fx.vendor(false).await, "vendor_bundled_deps_unsupported");
        assert!(detail.contains("bundleDependencies"), "{detail}");
        assert_eq!(
            fx.read_lock().await,
            BN3_BEFORE_LOCK,
            "refusal precedes the pack"
        );
        assert!(
            !fx.root().join(".socket/vendor").exists(),
            "nothing staged/packed inside the project"
        );
    }

    #[tokio::test]
    async fn marker_write_failure_is_a_warning_not_a_failure() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        // A rogue DIRECTORY squatting on the marker path: prepare_tgz_dest
        // uses create_dir_all (the uuid dir is never wiped), so the pack
        // and the lock rewrite succeed and only write_marker's
        // rename-over-a-directory fails.
        tokio::fs::create_dir_all(fx.root().join(format!(
            ".socket/vendor/npm/{UUID}/{}",
            crate::vendor::state::VENDOR_MARKER_FILE
        )))
        .await
        .unwrap();

        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(
            entry.is_some(),
            "the marker is informational; vendoring completes"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_marker_write_failed"),
            "{warnings:?}"
        );
        assert_eq!(
            fx.read_lock().await,
            BN3_AFTER_LOCK.replace(SPIKE_INTEGRITY, &fx.actual_integrity().await),
            "the lock rewrite is unaffected by the marker failure"
        );
    }

    // ── revert lock-read arms (non-empty wiring) ──────────────────────────

    #[tokio::test]
    async fn revert_missing_lock_warns_and_still_removes_the_artifact() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        tokio::fs::remove_file(fx.root().join(BUN_LOCK))
            .await
            .unwrap();

        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lockfile_missing"
                    && w.detail.contains("cannot be restored")),
            "{:?}",
            outcome.warnings
        );
        assert!(!outcome.kept_artifact, "a missing lock is not a drift-keep");
        assert!(
            !fx.root()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "no lock ⇒ nothing references the artifact ⇒ deletion proceeds"
        );
    }

    #[tokio::test]
    async fn revert_unreadable_lock_fails_closed_with_wiring_to_replay() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        // Not UTF-8: read_to_string fails with a non-NotFound error.
        tokio::fs::write(fx.root().join(BUN_LOCK), [0xff, 0xfe, b'x'])
            .await
            .unwrap();

        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(!outcome.success, "an unreadable lock must fail the revert");
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or("")
                .contains("cannot read bun.lock"),
            "{:?}",
            outcome.error
        );
        assert!(
            fx.root().join(fx.rel_tgz()).exists(),
            "artifact untouched on failure"
        );
    }

    /// `--preserve-state` with real wiring: the lock restore runs, the
    /// artifact dir stays, and `kept_artifact` stays false (reserved for
    /// drift-keeps per the `RevertOpts` doc). A later plain revert finds the
    /// lock already converged (silent no-op) and finishes the cleanup.
    #[tokio::test]
    async fn preserve_state_revert_restores_wiring_and_keeps_artifact() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let tgz_path = fx.root().join(fx.rel_tgz());

        let outcome = revert_bun_opts(
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
        assert!(!outcome.kept_artifact, "preserve-state is not a drift-keep");
        assert_eq!(fx.read_lock().await, BN3_BEFORE_LOCK, "wiring restored");
        assert!(tgz_path.exists(), "artifact deliberately kept");

        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome.warnings.is_empty(),
            "converged records are silent: {:?}",
            outcome.warnings
        );
        assert!(!tgz_path.exists());
        assert!(!fx
            .root()
            .join(format!(".socket/vendor/npm/{UUID}"))
            .exists());
    }

    // ── revert_one_record fail-closed drift arms ──────────────────────────

    /// A poisoned record (unknown kind, or no key) is left alone with the
    /// stable drift code — a wrong code here would delete the artifact out
    /// from under a lock the revert just refused to touch.
    #[tokio::test]
    async fn poisoned_record_unknown_kind_or_missing_key_drift_keeps() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let lock_vendored = fx.read_lock().await;

        let mut unknown_kind = entry.clone();
        unknown_kind.wiring[0].kind = "bogus".to_string();
        let mut missing_key = entry.clone();
        missing_key.wiring[0].key = None;

        for (poisoned, want) in [
            (unknown_kind, "unknown wiring kind"),
            (missing_key, "has no key"),
        ] {
            let outcome = revert_bun(&poisoned, fx.root(), false).await;
            assert!(outcome.success, "{want}: {:?}", outcome.error);
            assert!(
                outcome
                    .warnings
                    .iter()
                    .any(|w| w.code == "vendor_lock_entry_drifted" && w.detail.contains(want)),
                "{want}: {:?}",
                outcome.warnings
            );
            assert!(outcome.kept_artifact, "{want}: fail-closed keep");
            assert!(
                outcome
                    .warnings
                    .iter()
                    .any(|w| w.code == "vendor_artifact_kept"),
                "{want}: the keep must be surfaced: {:?}",
                outcome.warnings
            );
            assert_eq!(
                fx.read_lock().await,
                lock_vendored,
                "{want}: lock untouched (still vendored)"
            );
            assert!(
                fx.root().join(fx.rel_tgz()).exists(),
                "{want}: artifact kept"
            );
        }
    }

    #[tokio::test]
    async fn vanished_packages_section_drift_keeps() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        // The user replaced the lock wholesale; no packages section remains.
        let gutted = "{\n  \"lockfileVersion\": 1,\n}\n";
        tokio::fs::write(fx.root().join(BUN_LOCK), gutted)
            .await
            .unwrap();

        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"
                    && w.detail.contains("no packages section")
                    && w.detail.contains("left-pad")),
            "{:?}",
            outcome.warnings
        );
        assert!(outcome.kept_artifact, "drift-skip keeps the artifact");
        assert_eq!(fx.read_lock().await, gutted, "gutted lock left alone");
        assert!(fx.root().join(fx.rel_tgz()).exists(), "artifact kept");
    }

    #[tokio::test]
    async fn vanished_entry_key_drift_keeps() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        // Delete only the vendored entry line; the packages braces stay.
        let new_line = entry.wiring[0]
            .new
            .as_ref()
            .and_then(Value::as_str)
            .unwrap();
        let live = fx.read_lock().await;
        let without_entry = live.replace(&format!("{new_line}\n"), "");
        assert_ne!(without_entry, live, "the entry line must actually go");
        tokio::fs::write(fx.root().join(BUN_LOCK), &without_entry)
            .await
            .unwrap();

        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"
                    && w.detail.contains("no longer exists; nothing to restore")),
            "{:?}",
            outcome.warnings
        );
        assert!(outcome.kept_artifact, "drift-skip keeps the artifact");
        assert_eq!(fx.read_lock().await, without_entry, "nothing rewritten");
        assert!(fx.root().join(fx.rel_tgz()).exists(), "artifact kept");
    }

    /// KEEP-GATE LIVENESS (the `drift_skipped` contract in mod.rs): a record
    /// whose live line already equals its recorded pre-vendor original — the
    /// user restored it by hand — is a silent no-op, never drift, so the
    /// revert still finishes the artifact cleanup instead of re-flagging the
    /// restored line (and ratcheting the keep) forever.
    #[tokio::test]
    async fn hand_restored_original_line_is_silent_and_cleanup_completes() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let new_line = entry.wiring[0]
            .new
            .as_ref()
            .and_then(Value::as_str)
            .unwrap();
        let original_line = entry.wiring[0]
            .original
            .as_ref()
            .and_then(Value::as_str)
            .unwrap();
        let hand_restored = fx.read_lock().await.replace(new_line, original_line);
        assert_eq!(
            hand_restored, BN3_BEFORE_LOCK,
            "hand-restore = the pre-vendor lock"
        );
        tokio::fs::write(fx.root().join(BUN_LOCK), &hand_restored)
            .await
            .unwrap();

        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome.warnings.is_empty(),
            "already-converged is silent: {:?}",
            outcome.warnings
        );
        assert!(!outcome.kept_artifact);
        assert_eq!(fx.read_lock().await, BN3_BEFORE_LOCK);
        assert!(
            !fx.root()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "cleanup completes"
        );
    }

    // ── digest-less re-saves (Bun 1.1.39–1.3.9, every text-lock release below 1.3.10) ─────────────────────────
    // Those releases re-save our local-tarball 3-tuple WITHOUT its sha512
    // on any later lock re-save (`bun add`, `bun install` after a manifest
    // change) — verified on real 1.2.23 and 1.3.9; 1.3.10+ keep it. The
    // 2-tuple `["name@.socket/vendor/npm/<uuid>/leaf", {meta}]` is still
    // our wiring: re-runs stay in sync (and heal the digest back, recording
    // nothing), `repair` rebuilds through it, and revert unwinds it.

    /// Strip the trailing integrity element of a 3-tuple line the way Bun
    /// < 1.3.10 re-saves it (any `\r` kept).
    fn drop_digest(line: &str) -> String {
        let cut = line
            .rfind(", \"sha512-")
            .unwrap_or_else(|| panic!("no sha512 element in {line}"));
        let tail = if line.trim_end_matches('\r').ends_with("],") {
            "],"
        } else {
            "]"
        };
        let cr = if line.ends_with('\r') { "\r" } else { "" };
        format!("{}{tail}{cr}", &line[..cut])
    }

    /// The wired line of `entry` and the lock with that line's digest dropped.
    fn digestless_lock(wired: &str, entry: &VendorEntry) -> (String, String) {
        let new_line = entry.wiring[0]
            .new
            .as_ref()
            .and_then(Value::as_str)
            .unwrap()
            .to_string();
        let digestless = drop_digest(&new_line);
        assert!(!digestless.contains("sha512-"), "{digestless}");
        assert!(wired.contains(&new_line), "{wired}");
        (new_line.clone(), wired.replacen(&new_line, &digestless, 1))
    }

    #[tokio::test]
    async fn digestless_rerun_is_already_patched_and_heals_the_digest_without_a_record() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let wired = fx.read_lock().await;
        let (_, digestless) = digestless_lock(&wired, &entry);
        tokio::fs::write(fx.root().join(BUN_LOCK), &digestless)
            .await
            .unwrap();

        // Re-run: in sync (AlreadyPatched, no entry), NOT
        // `vendor_lock_entry_not_found`; the digest is healed on disk and the
        // lock is byte-identical to the post-vendor lock again.
        let (result, rerun_entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(rerun_entry.is_none(), "an in-sync re-run records nothing");
        assert!(
            result
                .files_verified
                .iter()
                .all(|v| v.status == VerifyStatus::AlreadyPatched),
            "{:?}",
            result.files_verified
        );
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(
            fx.read_lock().await,
            wired,
            "digest healed back to the 3-tuple"
        );

        // The healed lock reverts through the ORIGINAL entry byte-exactly.
        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert_eq!(fx.read_lock().await, BN3_BEFORE_LOCK);
        assert!(!fx
            .root()
            .join(format!(".socket/vendor/npm/{UUID}"))
            .exists());
    }

    /// Revert straight over the digest-less line (no re-run in between —
    /// `rollback` right after a `bun add`): the path claims the line, the
    /// registry original comes back, the artifact goes, no drift warning.
    #[tokio::test]
    async fn digestless_tuple_revert_restores_the_registry_line() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let (_, digestless) = digestless_lock(&fx.read_lock().await, &entry);
        tokio::fs::write(fx.root().join(BUN_LOCK), &digestless)
            .await
            .unwrap();

        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome.warnings.is_empty(),
            "a digest-less spelling of our own tuple is not drift: {:?}",
            outcome.warnings
        );
        assert!(!outcome.kept_artifact);
        assert_eq!(fx.read_lock().await, BN3_BEFORE_LOCK);
        assert!(!fx
            .root()
            .join(format!(".socket/vendor/npm/{UUID}"))
            .exists());
    }

    /// CRLF lock: the digest-less re-save keeps `\r`; the heal keeps every
    /// line's `\r\n` and revert lands byte-exact on the CRLF original.
    #[tokio::test]
    async fn digestless_crlf_lock_heals_and_reverts_byte_exact() {
        let crlf_before = BN3_BEFORE_LOCK.replace('\n', "\r\n");
        let fx = fixture_with(&crlf_before, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let wired = fx.read_lock().await;
        let (new_line, digestless) = digestless_lock(&wired, &entry);
        assert!(
            new_line.ends_with('\r'),
            "wired line carries its \\r: {new_line:?}"
        );
        tokio::fs::write(fx.root().join(BUN_LOCK), &digestless)
            .await
            .unwrap();

        let (result, rerun_entry, _) = expect_done(fx.vendor(false).await);
        assert!(
            result.success && rerun_entry.is_none(),
            "{:?}",
            result.error
        );
        let healed = fx.read_lock().await;
        assert_eq!(healed, wired, "CRLF heal is byte-exact");
        assert_eq!(healed.matches('\n').count(), healed.matches("\r\n").count());

        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(
            outcome.success && outcome.warnings.is_empty(),
            "{outcome:?}"
        );
        assert_eq!(fx.read_lock().await, crlf_before);
    }

    /// The upgraded-workspace case (the matrix's `already-vendored-workspace`
    /// shape on Bun 1.1.39–1.3.9): vendored, then a member added and `bun
    /// install` re-saved the lock digest-less. The in-sync re-run must stay
    /// AlreadyPatched (the v1 workspace gate fires only on a run that would
    /// WRITE a new local tuple) and heal the digest; revert restores the
    /// grown lock with the registry line back.
    #[tokio::test]
    async fn digestless_rerun_on_v1_workspace_lock_is_already_patched_and_heals() {
        for version in [0u64, 1] {
            let (fx, entry, lock) = vendored_then_workspace_added(version).await;
            let (_, digestless) = digestless_lock(&lock, &entry);
            tokio::fs::write(fx.root().join(BUN_LOCK), &digestless)
                .await
                .unwrap();
            let (result, rerun_entry, _) = expect_done(fx.vendor(false).await);
            assert!(result.success, "v{version}: {:?}", result.error);
            assert!(
                rerun_entry.is_none(),
                "v{version}: in-sync re-run records nothing"
            );
            assert!(
                result
                    .files_verified
                    .iter()
                    .all(|v| v.status == VerifyStatus::AlreadyPatched),
                "v{version}: {:?}",
                result.files_verified
            );
            assert_eq!(fx.read_lock().await, lock, "v{version}: digest healed");

            let outcome = revert_bun(&entry, fx.root(), false).await;
            assert!(
                outcome.success && outcome.warnings.is_empty(),
                "v{version}: {outcome:?}"
            );
            let original_line = entry.wiring[0]
                .original
                .as_ref()
                .and_then(Value::as_str)
                .unwrap();
            let new_line = entry.wiring[0]
                .new
                .as_ref()
                .and_then(Value::as_str)
                .unwrap();
            assert_eq!(
                fx.read_lock().await,
                lock.replacen(new_line, original_line, 1),
                "v{version}: the grown lock with the registry line put back"
            );
        }
    }

    /// `repair` on a digest-less lock: the artifact is gone, the lock still
    /// points at it (2-tuple). The rebuild routes through `vendor_bun`, must
    /// pass the has-match preflight (the 2-tuple IS our instance), rebuild
    /// the tarball and heal the digest — never refuse
    /// `vendor_lock_entry_not_found` and leave the lock pointing at ENOENT.
    #[tokio::test]
    async fn rebuild_on_missing_tarball_through_a_digestless_lock_succeeds() {
        for version in [0u64, 1, 2] {
            let (fx, entry, lock) = vendored_then_workspace_added(version).await;
            let (_, digestless) = digestless_lock(&lock, &entry);
            tokio::fs::write(fx.root().join(BUN_LOCK), &digestless)
                .await
                .unwrap();
            let tgz = fx.root().join(fx.rel_tgz());
            tokio::fs::remove_file(&tgz).await.unwrap();

            let (result, rebuilt_entry, _) = expect_done(fx.vendor(false).await);
            assert!(result.success, "v{version}: {:?}", result.error);
            assert!(tgz.is_file(), "v{version}: the tarball must be rebuilt");
            assert_eq!(
                fx.read_lock().await,
                lock,
                "v{version}: the rebuilt digest is re-pinned into the healed 3-tuple"
            );
            // No artifact stood witness for the dropped digest, so this is
            // a re-pin, not a silent heal: a fresh entry carries the rebuilt
            // fingerprint for the ledger (its `original` is refilled from
            // the replaced entry by `carry_forward_wiring`).
            let rebuilt_entry =
                rebuilt_entry.expect("a rebuild through a digest-less line returns an entry");
            assert_eq!(rebuilt_entry.artifact.path, fx.rel_tgz());
            assert!(rebuilt_entry.wiring[0].original.is_none(), "v{version}");
        }
    }

    /// The digest-less line's artifact is PRESENT but no longer the bytes
    /// the lock was written from (a service-prebuilt tarball replaced by a
    /// local pack, or vice versa). The tuple cannot say which digest it
    /// pinned, so this is a re-pin with a fresh entry — never a silent heal
    /// that would leave the ledger's fingerprint pointing at other bytes
    /// (`repair`'s post-verify then rejects the rebuild and deletes it).
    #[tokio::test]
    async fn digestless_tuple_over_different_artifact_bytes_is_repinned_with_a_fresh_entry() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let wired = fx.read_lock().await;
        let (_, digestless) = digestless_lock(&wired, &entry);
        tokio::fs::write(fx.root().join(BUN_LOCK), &digestless)
            .await
            .unwrap();
        // Different artifact bytes at the same path.
        tokio::fs::write(fx.root().join(fx.rel_tgz()), b"not the packed tarball")
            .await
            .unwrap();

        let (result, repinned, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        let repinned = repinned.expect("differing bytes force a re-pin with a fresh entry");
        assert_eq!(
            fx.read_lock().await,
            wired,
            "the line is re-pinned to the freshly packed digest"
        );
        assert_eq!(
            repinned.artifact.sha256, entry.artifact.sha256,
            "the fresh entry fingerprints the re-staged (deterministic) pack"
        );
        assert!(repinned.wiring[0].original.is_none());
        assert_eq!(
            repinned.wiring[0].new.as_ref().and_then(Value::as_str),
            entry.wiring[0].new.as_ref().and_then(Value::as_str)
        );
    }

    /// A digest-less 2-tuple pointing at ANOTHER uuid for the same leaf is
    /// not this entry's wiring on revert: drift-kept with the warning, the
    /// lock and artifact left alone (mirrors the 3-tuple stale-uuid rule).
    #[tokio::test]
    async fn digestless_tuple_of_another_uuid_is_drift_on_revert() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let (_, digestless) = digestless_lock(&fx.read_lock().await, &entry);
        let foreign = digestless.replace(UUID, UUID_B);
        assert_ne!(foreign, digestless);
        tokio::fs::write(fx.root().join(BUN_LOCK), &foreign)
            .await
            .unwrap();

        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted" && w.detail.contains("left-pad")),
            "{:?}",
            outcome.warnings
        );
        assert!(outcome.kept_artifact, "drift keeps the artifact");
        assert_eq!(fx.read_lock().await, foreign, "lock untouched");
    }

    /// A re-vendor under a NEW uuid rewrites our own earlier tuple, so its
    /// record carries `original: None` by design (never record a stale
    /// `.socket/vendor/` pointer as the "original"). Reverting that record
    /// has no pre-vendor tuple to restore: it must surface the gap loudly
    /// (pointing at `bun install`) and drift-keep — never guess a registry
    /// tuple.
    #[tokio::test]
    async fn revendored_entry_with_no_recorded_original_drift_keeps() {
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (result_a, _, _) = expect_done(fx.vendor(false).await);
        assert!(result_a.success, "{:?}", result_a.error);

        // Second vendor of the SAME name@version under UUID_B: classify
        // sees our UUID tuple (TupleShape::Ours), so the rewrite records no
        // original.
        let mut record_b = fx.record.clone();
        record_b.uuid = UUID_B.to_string();
        let blobs = fx.root().join(".socket/blobs");
        let sources = PatchSources::blobs_only(&blobs);
        let (result_b, entry_b, _) = expect_done(
            vendor_bun(
                "pkg:npm/left-pad@1.3.0",
                &fx.installed,
                fx.root(),
                &record_b,
                &sources,
                "2026-06-09T00:00:00Z",
                false,
                false,
                None,
            )
            .await,
        );
        assert!(result_b.success, "{:?}", result_b.error);
        let entry_b = entry_b.unwrap();
        assert!(
            entry_b.wiring[0].original.is_none(),
            "rewriting our own stale tuple records no original: {:?}",
            entry_b.wiring[0].original
        );
        let uuid_b_line =
            format!("\"left-pad\": [\"left-pad@.socket/vendor/npm/{UUID_B}/left-pad-1.3.0.tgz\"");
        assert!(fx.read_lock().await.contains(&uuid_b_line));

        let outcome = revert_bun(&entry_b, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"
                    && w.detail.contains("no recorded pre-vendor original")
                    && w.detail.contains("bun install")),
            "{:?}",
            outcome.warnings
        );
        assert!(outcome.kept_artifact);
        assert!(
            fx.read_lock().await.contains(&uuid_b_line),
            "the live tuple is left as-is, never guessed at"
        );
        assert!(
            fx.root()
                .join(format!(".socket/vendor/npm/{UUID_B}/left-pad-1.3.0.tgz"))
                .exists(),
            "artifact kept while the lock still points at it"
        );

        // SUSPECTED BUG 3 (documented, not endorsed): after the advertised
        // remediation — `bun install` re-resolves the entry from the
        // registry — the revert STILL drift-keeps ("re-resolved since
        // vendoring"), so an original:None record's keep can never
        // converge. Pinned as current behavior; flip these asserts when the
        // ratchet is fixed.
        tokio::fs::write(fx.root().join(BUN_LOCK), BN3_BEFORE_LOCK)
            .await
            .unwrap();
        let outcome = revert_bun(&entry_b, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"
                    && w.detail.contains("re-resolved since vendoring")),
            "{:?}",
            outcome.warnings
        );
        assert!(
            outcome.kept_artifact,
            "the ratchet: still kept after the advertised remediation"
        );
    }

    // ── unix error injection: lock-write / restore-write / removal ────────

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

    /// Write failures fail closed on unix: a read-only project root makes
    /// the vendor's bun.lock commit and the revert's restore write fail, and
    /// a read-only `.socket/vendor/npm` makes the artifact removal fail —
    /// and a re-run converges once the permission is fixed.
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_write_failures_fail_closed() {
        if unsafe { libc::geteuid() } == 0 {
            return; // chmod is advisory for root — the failures never fire
        }

        // Vendor: the tarball is already packed (.socket stays writable)
        // when the lock write fails — the atomic write stages its temp file
        // in the read-only root.
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let guard = ModeGuard::set(fx.root(), 0o555);
        let (result, entry, _) = expect_done(fx.vendor(false).await);
        drop(guard);
        assert!(!result.success, "a read-only root must fail the lock write");
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or("")
                .contains("cannot write bun.lock"),
            "{:?}",
            result.error
        );
        assert!(entry.is_none(), "no ledger entry for a failed wiring");
        assert_eq!(fx.read_lock().await, BN3_BEFORE_LOCK, "lock untouched");
        // The freshly packed uuid dir is unwound on this failure path
        // (done_failure_unstage, matching yarn at the same phase) — no
        // ledger entry ever points at it, so leaving it behind would be an
        // untracked husk `--revert` could never clean.
        assert!(
            !fx.root()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "no orphaned artifact husk may remain (nothing tracks it)"
        );

        // Revert: the restore write fails, deletion is never reached.
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let lock_vendored = fx.read_lock().await;
        let guard = ModeGuard::set(fx.root(), 0o555);
        let outcome = revert_bun(&entry, fx.root(), false).await;
        drop(guard);
        assert!(!outcome.success, "read-only root must fail the restore");
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or("")
                .contains("cannot write bun.lock"),
            "{:?}",
            outcome.error
        );
        assert_eq!(fx.read_lock().await, lock_vendored, "lock untouched");
        assert!(
            fx.root().join(fx.rel_tgz()).exists(),
            "artifact survives the failed restore (deletion never reached)"
        );

        // Revert: the lock restore lands, the uuid-dir removal fails — and
        // a re-run converges once the permission is fixed.
        let fx = fixture_with(BN3_BEFORE_LOCK, "node_modules/left-pad").await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let guard = ModeGuard::set(&fx.root().join(".socket/vendor/npm"), 0o555);
        let outcome = revert_bun(&entry, fx.root(), false).await;
        drop(guard);
        assert!(!outcome.success, "a read-only parent must fail the removal");
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or("")
                .contains("cannot remove .socket/vendor/npm/"),
            "{:?}",
            outcome.error
        );
        assert_eq!(
            fx.read_lock().await,
            BN3_BEFORE_LOCK,
            "the lock restore ran before the failed removal"
        );
        let outcome = revert_bun(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome.warnings.is_empty(),
            "the converged re-run is silent: {:?}",
            outcome.warnings
        );
        assert!(
            !fx.root()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "the re-run converges and removes the uuid dir"
        );
    }
}
