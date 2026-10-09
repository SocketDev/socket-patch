//! yarn classic (v1 lockfile) vendor backend: lock-only block surgery.
//!
//! Vendoring under yarn classic = pack the patched tree into the
//! deterministic tarball under `.socket/vendor/npm/<uuid>/` (shared npm
//! pipeline) and rewrite every matching `yarn.lock` block's
//! `resolved "file:./<rel-tgz>#<sha1>"` + `integrity <sha512 SRI>`.
//! `package.json` is untouched — the block's range keys still match.
//! Spike-proven (Y2/Y5/Y6): the rewrite passes `--frozen-lockfile`,
//! installs offline from a fresh checkout, and round-trips yarn's own
//! serializer byte-for-byte.
//!
//! Two spellings are LOAD-BEARING:
//! * `resolved` must keep a `file:./` (or `./`) prefix — a bare path is
//!   treated as registry-relative and 404s against registry.yarnpkg.com;
//! * the `#<sha1>` fragment carries the tgz sha1 and the `integrity` line
//!   the tgz sha512 — yarn enforces BOTH on every install (even when the
//!   integrity line was absent before, adding it turns the check on), so the
//!   hashes are always the recomputed ones of OUR tarball, never inherited.
//!
//! The edit is line-oriented and splice-based: every byte outside the edited
//! blocks (comments, blank lines, other blocks, CRLF line endings) is
//! preserved verbatim, so yarn's re-serialization produces no churn.

use std::path::Path;
use std::sync::Arc;

use serde_json::Value;

use crate::constants::SOCKET_DIR;
use crate::formats::yarn::blocks::{
    block_eol, body_field_line, classic_field, repin_classic_block, replace_block, scan_blocks,
    LockBlock,
};
use crate::formats::yarn::patterns::{classic_key_real_name, split_key_patterns};
use crate::formats::yarn::source::{classic_copy_source, CopySource};
use crate::manifest::schema::PatchRecord;
use crate::patch::apply::PatchSources;
use crate::utils::fs::{atomic_write_bytes_preserving_mode, read_regular_to_string};
use crate::utils::socket_dir::remove_tree_and_prune;

use super::common::{detect_eol, refused};
use super::npm_common::{
    guard_revert_uuid_dir, vendor_npm_family, NpmCommit, NpmCoords, NpmLockBackend, NpmStagedPack,
    NpmVendorRequest, WireCx,
};
use super::parse_memo::ParseMemo;
use super::path::parse_vendor_path;
use super::source::PackageSource;
use super::state::{VendorEntry, WiringAction, WiringRecord};
use super::{RevertOpts, RevertOutcome, VendorOutcome, VendorWarning};

const YARN_LOCK: &str = "yarn.lock";

/// The `WiringRecord.kind` this backend owns: one rewritten lock block,
/// `original`/`new` = verbatim block line arrays (key line included).
const KIND_LOCK_BLOCK: &str = "yarn_lock_block";

/// Vendor one installed npm package into a yarn-classic project.
///
/// Same contract as [`super::npm_lock::vendor_npm`]: refuse-early, wire-last
/// (every refusal fires before any write inside the project; the lock edit is
/// the final mutation), `entry` is `None` for dry runs and the in-sync
/// re-run. The flow is [`vendor_npm_family`]'s; [`YarnClassicBackend`] is
/// the v1 lock grammar.
#[allow(clippy::too_many_arguments)]
pub async fn vendor_yarn_classic<'a>(
    purl: &str,
    installed_dir: impl Into<PackageSource<'a>>,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
    service: Option<&super::VendorServiceConfig>,
) -> VendorOutcome {
    vendor_npm_family(
        &YarnClassicBackend,
        NpmVendorRequest {
            purl,
            installed_dir: installed_dir.into(),
            project_root,
            record,
            sources,
            vendored_at,
            dry_run,
            force,
            service,
        },
    )
    .await
}

/// The yarn-classic half of [`vendor_yarn_classic`].
struct YarnClassicBackend;

/// [`YarnClassicBackend`]'s pre-flight product: the lock text and the keys
/// of the blocks to rewrite.
struct YarnClassicPlan {
    text: String,
    candidate_keys: Vec<String>,
}

impl NpmLockBackend for YarnClassicBackend {
    type Plan = YarnClassicPlan;

    fn flavor(&self) -> Option<&'static str> {
        Some("yarn-classic")
    }

    async fn preflight(
        &self,
        project_root: &Path,
        coords: &NpmCoords,
        warnings: &mut Vec<VendorWarning>,
    ) -> Result<YarnClassicPlan, Box<VendorOutcome>> {
        // ── 2. Lockfile ───────────────────────────────────────────────────
        let text = read_yarn_lock(project_root).await?;
        refuse_berry_lock(&text)?;

        // ── 3. Find the rewritable blocks (pre-flight, BEFORE staging) ────
        let blocks = scan_blocks_shared(&text);
        let other_name =
            other_name_copy_warnings(project_root, &blocks, &coords.name, &coords.version).await;
        let (candidate_keys, skipped) =
            rewritable_candidates(&blocks, &coords.name, &coords.version).map_err(|o| {
                only_other_name_copies(o, &coords.name, &coords.version, &other_name)
            })?;
        warnings.extend(skipped);
        warnings.extend(other_name);
        Ok(YarnClassicPlan {
            text,
            candidate_keys,
        })
    }

    async fn wire(
        &self,
        plan: YarnClassicPlan,
        cx: &WireCx<'_>,
        staged: &mut NpmStagedPack,
        _warnings: &mut Vec<VendorWarning>,
    ) -> Result<Option<NpmCommit>, String> {
        let YarnClassicPlan {
            text,
            candidate_keys,
        } = plan;
        // SECURITY/CORRECTNESS: the `file:./` prefix is load-bearing — a
        // bare path is registry-relative to yarn classic (spike Y2: 404).
        let resolved_value = format!("file:./{}#{}", staged.rel_tgz, staged.packed.sha1_hex);

        // ── 8. Lock rewrite: splice each candidate block, byte-preserving ─
        let eol = detect_eol(&text);
        let mut new_text = text;
        let mut wiring: Vec<WiringRecord> = Vec::new();
        for key in &candidate_keys {
            let edit = {
                // While nothing has been spliced yet, `new_text` is still the
                // text scanned above and every candidate hits that scan — the
                // whole idempotent re-run takes this arm. Once a splice has
                // rewritten it, each key sees text no later read can ask for
                // again, so scan it without paying the memo's copy of it.
                let blocks = if wiring.is_empty() {
                    scan_blocks_shared(&new_text)
                } else {
                    Arc::new(scan_blocks(&new_text))
                };
                let Some(block) = blocks.iter().find(|b| &b.key == key) else {
                    return Err(format!("lock block `{key}` vanished mid-rewrite"));
                };
                let new_lines = rewrite_classic_block(
                    &block.lines,
                    &resolved_value,
                    &staged.packed.integrity,
                    staged.staged_pkg_json.as_ref(),
                );
                if new_lines == block.lines {
                    // Idempotency: already carrying our exact spec — no edit,
                    // no wiring record.
                    None
                } else {
                    // Never record one of our own (stale) edits as the
                    // "original" — revert must restore the pre-vendor
                    // registry fragment, not a dangling `.socket/vendor/`
                    // pointer.
                    let was_vendored = block_points_into_vendor(&block.lines);
                    let rec = WiringRecord {
                        file: YARN_LOCK.to_string(),
                        kind: KIND_LOCK_BLOCK.to_string(),
                        action: WiringAction::Rewritten,
                        key: Some(key.clone()),
                        original: if was_vendored {
                            None
                        } else {
                            Some(lines_to_json(&block.lines))
                        },
                        new: Some(lines_to_json(&new_lines)),
                    };
                    Some((replace_block(&new_text, block, &new_lines, eol), rec))
                }
            };
            if let Some((replaced, rec)) = edit {
                new_text = replaced;
                wiring.push(rec);
            }
        }

        if wiring.is_empty() {
            // Every block already points at this uuid with the packed
            // hashes (`#sha1` and `integrity`): in sync.
            return Ok(None);
        }

        forget_block_scans();
        atomic_write_bytes_preserving_mode(&cx.project_root.join(YARN_LOCK), new_text.as_bytes())
            .await
            .map_err(|e| format!("cannot write {YARN_LOCK}: {e}"))?;
        Ok(Some(NpmCommit {
            wiring,
            ..NpmCommit::default()
        }))
    }

    fn manifest_warning(&self, name: &str, version: &str) -> VendorWarning {
        VendorWarning::new(
            "vendor_dep_manifest_rewritten",
            format!(
                "the patch rewrites {name}@{version}'s package.json; its lock blocks' \
                 dependencies/optionalDependencies sub-maps were recomputed from the patched \
                 manifest"
            ),
        )
    }
}

/// [`vendor_yarn_classic`]'s defensive re-sniff: the flavor router already
/// separates classic from berry, but rewriting a berry lock with classic
/// grammar would corrupt it — never proceed past a `__metadata:` key.
fn refuse_berry_lock(text: &str) -> Result<(), Box<VendorOutcome>> {
    if crate::formats::yarn::is_berry_lock(text) {
        return Err(Box::new(refused(
            "vendor_lockfile_version_unsupported",
            "yarn.lock is a yarn berry (v2+) lockfile (top-level `__metadata:` key); the \
             yarn-classic backend cannot rewrite it"
                .to_string(),
        )));
    }
    Ok(())
}

/// [`vendor_yarn_classic`]'s step 3: classify every block of
/// `name@version` and return the rewritable keys plus a named warning for
/// each copy that can't be rewired (link, `file:` directory, git, a
/// non-registry tarball). Refused
/// when nothing is rewritable — as `vendor_lock_entry_not_rewritable`,
/// naming the skipped copies, when the package IS locked but only through
/// such copies (#857: `yarn install` can't help there) — or when a key sits
/// on more than one block. Nothing here reads the package's source or asks
/// the service, so the vendor loop's download plan evaluates it ahead of
/// the loop ([`preflight_packages`]).
fn rewritable_candidates(
    blocks: &[LockBlock],
    name: &str,
    version: &str,
) -> Result<(Vec<String>, Vec<VendorWarning>), Box<VendorOutcome>> {
    let mut candidate_keys: Vec<String> = Vec::new();
    let mut skipped: Vec<VendorWarning> = Vec::new();
    // The skipped blocks that are real installed copies no re-lock changes.
    let mut unrewritable: Vec<String> = Vec::new();
    for block in blocks {
        match classify_classic_block(block, name, version) {
            BlockClass::Candidate => candidate_keys.push(block.key.clone()),
            BlockClass::LinkSkip(detail) => {
                unrewritable.push(detail.clone());
                skipped.push(VendorWarning::new("vendor_link_entry_skipped", detail));
            }
            BlockClass::GitSkip(detail) => {
                unrewritable.push(detail.clone());
                skipped.push(VendorWarning::new(
                    "vendor_yarn_classic_git_entry_skipped",
                    detail,
                ));
            }
            BlockClass::UnresolvedSkip(detail) => {
                skipped.push(VendorWarning::new("vendor_link_entry_skipped", detail));
            }
            BlockClass::RemoteSkip(detail) => {
                unrewritable.push(detail.clone());
                skipped.push(VendorWarning::new(
                    "vendor_yarn_classic_non_registry_entry_skipped",
                    detail,
                ));
            }
            BlockClass::LegacyWired(detail) => {
                candidate_keys.push(block.key.clone());
                skipped.push(VendorWarning::new(
                    "vendor_yarn_classic_non_registry_legacy_wiring",
                    detail,
                ));
            }
            BlockClass::NoMatch => {}
        }
    }
    if candidate_keys.is_empty() && !unrewritable.is_empty() {
        let details: Vec<&str> = unrewritable.iter().map(String::as_str).collect();
        return Err(Box::new(refused(
            "vendor_lock_entry_not_rewritable",
            format!(
                "every {YARN_LOCK} block for {name}@{version} installs from git, a link, a \
                 file: directory or a non-registry tarball, which vendoring can't rewire — \
                 those copies stay UNPATCHED and `yarn install` will not help: {}",
                details.join("; ")
            ),
        )));
    }
    if candidate_keys.is_empty() {
        return Err(Box::new(refused(
            "vendor_lock_entry_not_found",
            format!(
                "{YARN_LOCK} has no rewritable block for {name}@{version} — make sure the \
                 package is installed and locked (`yarn install`) before vendoring"
            ),
        )));
    }
    // A candidate key on more than one block (a mangled merge — yarn itself
    // parses duplicates last-wins) makes the by-key rewrite ambiguous: it
    // would splice the first same-key block, even a version-mismatched one
    // classification never selected, and leave yarn's winner resolving to
    // the registry — success reported, package unpatched. Refuse-early.
    for key in &candidate_keys {
        if blocks.iter().filter(|b| &b.key == key).count() > 1 {
            return Err(Box::new(refused(
                "vendor_lock_entry_ambiguous",
                format!(
                    "{YARN_LOCK} has more than one block with the key `{key}` (most likely a \
                     mangled merge; yarn keeps only the last) — run `yarn install` to re-lock, \
                     then re-run the vendor"
                ),
            )));
        }
    }
    Ok((candidate_keys, skipped))
}

/// A named warning for each block that installs `name@version` under
/// ANOTHER dependency name (#1236): yarn 1 keys a `file:` directory or url
/// copy by the name the depender gave it (`"lp2@file:./lpdir"`), so which
/// package it is comes from the copy itself (the directory's
/// `package.json`, the registry url's path). No re-lock of `name` reaches
/// that copy, so it stays unpatched; the registry blocks are still wired.
async fn other_name_copy_warnings(
    project_root: &Path,
    blocks: &[LockBlock],
    name: &str,
    version: &str,
) -> Vec<VendorWarning> {
    let mut out = Vec::new();
    for block in blocks {
        let patterns = split_key_patterns(&block.key);
        if classic_key_real_name(&patterns) == Some(name)
            || classic_field(&block.lines, "version") != Some(version)
        {
            continue;
        }
        let manifest = crate::formats::yarn::source::classic_file_directory(&patterns).map(|dir| {
            if dir.is_empty() {
                "package.json".to_string()
            } else {
                format!("{dir}/package.json")
            }
        });
        let text = match manifest {
            Some(rel) => read_regular_to_string(&project_root.join(&rel)).await.ok(),
            None => None,
        };
        let copy = crate::formats::yarn::source::classic_copy_real_name(
            &patterns,
            classic_field(&block.lines, "resolved"),
            version,
            |_| text.clone(),
        );
        let Some((_, source)) = copy.filter(|(n, _)| n == name) else {
            continue;
        };
        let (code, from) = match source {
            CopySource::Directory => (
                "vendor_link_entry_skipped",
                "a file: directory, which yarn copies into node_modules",
            ),
            _ => (
                "vendor_yarn_classic_non_registry_entry_skipped",
                "a URL tarball",
            ),
        };
        out.push(VendorWarning::new(
            code,
            format!(
                "lock entry `{}` installs {name}@{version} under another dependency name, \
                 from {from}; vendoring can't rewire it, so this copy stays UNPATCHED",
                block.key
            ),
        ));
    }
    out
}

/// A `vendor_lock_entry_not_found` refusal of a package whose only copies
/// are locked under ANOTHER dependency name ([`other_name_copy_warnings`])
/// becomes `vendor_lock_entry_not_rewritable` naming them: the package IS
/// installed, and `yarn install` can't re-lock those copies to it (#1236).
/// Any other refusal passes through.
fn only_other_name_copies(
    refusal: Box<VendorOutcome>,
    name: &str,
    version: &str,
    other_name: &[VendorWarning],
) -> Box<VendorOutcome> {
    if other_name.is_empty()
        || super::npm_common::refusal_code(&refusal) != "vendor_lock_entry_not_found"
    {
        return refusal;
    }
    let details: Vec<&str> = other_name.iter().map(|w| w.detail.as_str()).collect();
    Box::new(refused(
        "vendor_lock_entry_not_rewritable",
        format!(
            "every {YARN_LOCK} block for {name}@{version} is a copy locked under another \
             dependency name, which vendoring can't rewire — those copies stay UNPATCHED and \
             `yarn install` will not help: {}",
            details.join("; ")
        ),
    ))
}

/// The lock as [`vendor_yarn_classic`]'s step 2 leaves it: read, re-sniffed
/// and scanned into blocks. Read once for the vendor loop's download plan
/// ([`preflight_packages`]); the loop itself runs the same steps inline,
/// per package.
pub(super) struct ClassicProject {
    blocks: Arc<Vec<LockBlock>>,
}

/// Read the lock as [`vendor_yarn_classic`]'s step 2 does — read,
/// re-sniffed against a berry lock, scanned into blocks — once, for the
/// download plan; refuses with the loop's codes.
pub(super) async fn read_project(project_root: &Path) -> Result<ClassicProject, &'static str> {
    let text = read_yarn_lock(project_root)
        .await
        .map_err(|o| super::npm_common::refusal_code(&o))?;
    refuse_berry_lock(&text).map_err(|o| super::npm_common::refusal_code(&o))?;
    Ok(ClassicProject {
        blocks: scan_blocks_shared(&text),
    })
}

/// Which of `packages` [`vendor_yarn_classic`] would refuse before its
/// first service call, from one read of the lock; see
/// [`super::npm_flavor::preflight_packages`]. The classification fold is
/// the loop's step 3 over the same blocks; its skip advisories are the
/// loop's to report and are dropped here.
pub(crate) async fn preflight_packages(
    project_root: &Path,
    packages: &[(&str, &PatchRecord)],
) -> Vec<Result<(), &'static str>> {
    let project = read_project(project_root).await;
    let blocks = project.as_ref().ok().map(|p| Arc::clone(&p.blocks));
    let mut gated = super::npm_common::gate_packages(project, packages, |project, coords| {
        let (name, version) = (coords.name.as_str(), coords.version.as_str());
        rewritable_candidates(&project.blocks, name, version)
            .map(drop)
            .map_err(|o| super::npm_common::refusal_code(&o))
    });
    // The loop's step 3 turns "not found" into "not rewritable" when the
    // package's only copies are locked under another name; so does the plan.
    if let Some(blocks) = blocks {
        for ((purl, record), gate) in packages.iter().zip(gated.iter_mut()) {
            if *gate != Err("vendor_lock_entry_not_found") {
                continue;
            }
            let Ok(coords) = super::npm_common::guard_coordinates(purl, record) else {
                continue;
            };
            if !other_name_copy_warnings(project_root, &blocks, &coords.name, &coords.version)
                .await
                .is_empty()
            {
                *gate = Err("vendor_lock_entry_not_rewritable");
            }
        }
    }
    gated
}

/// Undo one yarn-classic vendored package: restore the recorded lock blocks
/// and remove the artifact dir.
/// Test-only shorthand — production routes through
/// [`revert_yarn_classic_opts`] (via
/// [`super::npm_flavor::revert_npm_any_opts`]).
#[cfg(test)]
pub async fn revert_yarn_classic(
    entry: &VendorEntry,
    project_root: &Path,
    dry_run: bool,
) -> RevertOutcome {
    revert_yarn_classic_opts(entry, project_root, RevertOpts::new(dry_run)).await
}

/// [`revert_yarn_classic`] with full [`RevertOpts`]: `keep_artifact` skips
/// the artifact deletion — and the refusals that exist only to protect it —
/// while the wiring restore runs unchanged.
pub async fn revert_yarn_classic_opts(
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
    // only be removed when yarn.lock provably no longer resolves through it
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
            &[YARN_LOCK],
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

    // SECURITY: per-flavor FILE ALLOWLIST — this backend only ever wrote
    // yarn.lock, so a poisoned state.json must not be able to point the
    // restore at any other project file. Violations are skipped fail-closed
    // with a warning, before any read or write of the named path.
    let mut records: Vec<&WiringRecord> = Vec::new();
    for rec in entry.wiring.iter().rev() {
        if rec.file == YARN_LOCK {
            records.push(rec);
        } else {
            outcome.warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "ignoring wiring record for file `{}` outside the yarn-classic \
                     allowlist [\"{YARN_LOCK}\"]",
                    rec.file
                ),
            ));
        }
    }

    let lock_path = project_root.join(YARN_LOCK);
    // Guarded read (`open_regular_file`): a FIFO planted as yarn.lock fails
    // fast into the error arm instead of wedging the revert forever in an
    // `open(2)` waiting for a writer.
    let text = match read_regular_to_string(&lock_path).await {
        Ok(t) => Some(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            outcome.warnings.push(VendorWarning::new(
                "vendor_lockfile_missing",
                format!("{YARN_LOCK} is missing; lock blocks cannot be restored"),
            ));
            None
        }
        Err(e) => return RevertOutcome::failed(format!("cannot read {YARN_LOCK}: {e}")),
    };

    if let Some(mut text) = text {
        let mut changed = false;
        for rec in records {
            changed |= revert_recorded_block(
                &mut text,
                rec,
                &entry.uuid,
                KIND_LOCK_BLOCK,
                "lock block",
                |lines| classic_field(lines, "resolved"),
                &mut outcome.warnings,
            );
        }
        if changed {
            forget_block_scans();
            if let Err(e) = atomic_write_bytes_preserving_mode(&lock_path, text.as_bytes()).await {
                return RevertOutcome::failed(format!("cannot write {YARN_LOCK}: {e}"));
            }
        }
    }

    // LOSSINESS GUARD: when any wiring record was left alone ("drifted;
    // left alone"), the uuid dir may hold the only copy of what the lock —
    // or the redirect ledger's recorded originals — still points at. Keep
    // it (and let the CLI keep the ledger entry) instead of deleting evidence
    // out from under a lock we just refused to touch.
    if outcome.drift_skipped() {
        outcome.keep_artifact(&uuid_dir_rel);
        return outcome;
    }

    // `--preserve-state` (`keep_artifact`): the wiring restore above already
    // ran; the artifact dir stays behind (and the caller keeps the ledger
    // entry), so the deletion — and the still-wired probe that exists only
    // to protect it — are skipped.
    if keep_artifact {
        return outcome;
    }

    if super::npm_flavor::keep_artifact_while_lock_references_it(
        &mut outcome,
        project_root,
        &[YARN_LOCK],
        &entry.uuid,
        &uuid_dir_rel,
    )
    .await
    {
        return outcome;
    }

    // FAIL-CLOSED (same brick class as the unwired guard above, twin of
    // npm_lock's and yarn_berry's post-restore probes): the restore only
    // rewrites the blocks the wiring recorded, but yarn can still resolve
    // through the artifact via a block the wiring never named (hand-copied
    // or re-keyed since vendoring). Deleting the uuid dir then fails every
    // subsequent install on the missing tarball, silently. Mentioned ⇒
    // refuse; absent or unprovable keeps the wired revert's existing
    // missing-lock tolerance.
    if super::npm_flavor::lock_text_mentions_uuid(project_root, &[YARN_LOCK], &entry.uuid).await
        == Some(true)
    {
        let detail = format!(
            "refusing to remove {uuid_dir_rel}: after restoring the recorded lock blocks, \
             {YARN_LOCK} still resolves through it (was the entry re-keyed or hand-copied \
             since vendoring?) — deleting the artifact would make every subsequent install \
             fail; restore the pre-vendor {YARN_LOCK} (or remove the dependency and re-lock) \
             and re-run `vendor --revert`"
        );
        outcome.success = false;
        outcome.error = Some(detail.clone());
        outcome.warnings.push(VendorWarning::new(
            "vendor_lock_still_wired_revert_blocked",
            detail,
        ));
        return outcome;
    }

    // The last npm-family entry leaves `.socket/vendor/npm/` (and
    // `.socket/vendor/`) empty: the shared helper prunes them so a reverted
    // project carries no vendor residue (non-recursive: siblings keep them).
    let uuid_dir = project_root.join(&uuid_dir_rel);
    if let Err(e) = remove_tree_and_prune(&uuid_dir, &project_root.join(SOCKET_DIR)).await {
        return RevertOutcome::failed(format!("cannot remove {uuid_dir_rel}: {e}"));
    }

    outcome
}

/// Apply one wiring record in reverse: restore `original` iff the live block
/// is still ours (drift = a third party re-resolved it; leave theirs alone,
/// with a warning). Returns true when the block was restored.
///
/// Shared by the classic and berry lock reverts, which differ only in the
/// wiring `kind` they own, the noun their warnings use (`lock block` vs
/// `lock entry`), and the field carrying the vendor path — `vendor_field`
/// reads it (classic `resolved` / berry `resolution`).
pub(super) fn revert_recorded_block(
    text: &mut String,
    rec: &WiringRecord,
    entry_uuid: &str,
    expected_kind: &str,
    noun: &str,
    vendor_field: fn(&[String]) -> Option<&str>,
    warnings: &mut Vec<VendorWarning>,
) -> bool {
    let Some(key) = rec.key.as_deref() else {
        warnings.push(VendorWarning::new(
            "vendor_lock_entry_drifted",
            format!("wiring record in {} has no key; left alone", rec.file),
        ));
        return false;
    };
    if rec.kind != expected_kind {
        // Forward compatibility: an unknown kind from a newer binary
        // degrades to a warning (see state.rs schema docs).
        warnings.push(VendorWarning::new(
            "vendor_lock_entry_drifted",
            format!("unknown wiring kind `{}` for `{key}`; left alone", rec.kind),
        ));
        return false;
    }
    // The recorded pre-vendor block (key line first), used both for the
    // restore and for the ALREADY-CONVERGED checks below.
    let orig_lines = rec.original.as_ref().and_then(json_to_lines);
    let edit = {
        let blocks = scan_blocks(text);
        let Some(block) = blocks.iter().find(|b| b.key == key) else {
            // ALREADY CONVERGED: an earlier partial revert restored this
            // record, and the restore rekeyed the block (berry's `file:`
            // locator key reverts to the pre-vendor descriptor), so the
            // recorded key no longer matches while the original block is
            // live verbatim. Not drift: stay silent so the drift-skip keep
            // gate can converge instead of keeping the artifacts forever.
            if let Some(orig) = orig_lines.as_ref() {
                if blocks.iter().any(|b| &b.lines == orig) {
                    return false;
                }
            }
            // REMOVED, not drifted (#665): the user dropped the dependency.
            // The caller keeps the artifact only while the lock still
            // resolves through it.
            warnings.push(VendorWarning::new(
                super::LOCK_ENTRY_REMOVED_CODE,
                format!("{noun} `{key}` no longer exists; nothing to restore"),
            ));
            return false;
        };
        // ALREADY CONVERGED: the live block equals the recorded pre-vendor
        // original — an earlier partial revert (or the user, by hand)
        // already restored it in place. Not drift.
        if orig_lines.as_ref() == Some(&block.lines) {
            return false;
        }
        // Ownership gate: the live block's vendor field must still point
        // into OUR uuid dir — anything else means a third party re-resolved
        // it.
        let ours = vendor_field(&block.lines)
            .and_then(parse_vendor_path)
            .is_some_and(|p| p.eco == "npm" && p.uuid == entry_uuid);
        if !ours {
            warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!("{noun} `{key}` was re-resolved since vendoring; left alone"),
            ));
            return false;
        }
        let Some(original) = orig_lines else {
            // The record rewrote one of our own earlier edits, so there is
            // no pre-vendor fragment to restore (by design). Surface it
            // instead of guessing a registry URL.
            warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "{noun} `{key}` has no recorded pre-vendor original; left as-is \
                     (re-run `yarn install` to re-resolve it from the registry)"
                ),
            ));
            return false;
        };
        // The recorded lines carry no terminators: the restored block takes
        // the one the live block is written in, so a lock whose endings
        // were mixed since vendoring keeps every other line as it is.
        replace_block(text, block, &original, block_eol(text, block))
    };
    *text = edit;
    true
}

// ─────────────────────────── block classification ───────────────────────────

enum BlockClass {
    /// Rewritable instance of the target package.
    Candidate,
    /// Matches the target but cannot be rewired; carries the warning detail.
    LinkSkip(String),
    /// Matches the target but yarn fetches it with git (#363); carries the
    /// warning detail.
    GitSkip(String),
    /// Matches the target but has no `resolved` (a stale lock `yarn install`
    /// re-locks); carries the warning detail.
    UnresolvedSkip(String),
    /// Matches the target but installs a non-registry tarball (B16);
    /// carries the warning detail.
    RemoteSkip(String),
    /// A non-registry copy an older release already wired into
    /// `.socket/vendor/` (B16 upgrade state): kept as a candidate so an
    /// in-sync re-run stays a no-op, but named; carries the warning detail.
    LegacyWired(String),
    NoMatch,
}

/// Does this block stand for `name@version`, and can it be rewired?
fn classify_classic_block(block: &LockBlock, name: &str, version: &str) -> BlockClass {
    let patterns = split_key_patterns(&block.key);
    // Every key pattern must resolve to the target package's real name (an
    // `alias@npm:left-pad@^1.3.0` pattern carries the real name inside the
    // range — spike Y5's alias block).
    if classic_key_real_name(&patterns) != Some(name) {
        return BlockClass::NoMatch;
    }
    if classic_field(&block.lines, "version") != Some(version) {
        return BlockClass::NoMatch;
    }
    // link: and file:-DIRECTORY ranges resolve from the working tree, not a
    // tarball — rewriting their resolved would not change what installs.
    let resolved = classic_field(&block.lines, "resolved");
    match classic_copy_source(&patterns, resolved) {
        CopySource::Registry => BlockClass::Candidate,
        // The vendored tarball is the patch service's build of the REGISTRY
        // package (B16): wiring a fork, local build or hosted-git copy to it
        // would swap the user's code for registry bytes.
        // Checked before the copy-source refusal: a block whose `resolved`
        // is already ours installs the vendored build, not the user's own
        // artifact, and its original is in the ledger for `vendor --revert`.
        CopySource::RemoteTarball if block_points_into_vendor(&block.lines) => {
            BlockClass::LegacyWired(format!(
                "lock block `{}` is a file: tarball, URL or hosted-git dependency that an \
                 older release wired to the vendored registry build of {name}@{version}, so \
                 it installs that build rather than your own; `socket-patch vendor --revert` \
                 restores its original source",
                block.key
            ))
        }
        CopySource::RemoteTarball => BlockClass::RemoteSkip(format!(
            "lock block `{}` installs from a tarball that is not the registry's (a \
             file: tarball, URL or hosted-git dependency), and the vendored artifact is \
             built from the registry package; skipped, so that copy stays unpatched",
            block.key
        )),
        CopySource::Link => BlockClass::LinkSkip(format!(
            "lock block `{}` is a link: dependency; skipped",
            block.key
        )),
        CopySource::Directory => BlockClass::LinkSkip(format!(
            "lock block `{}` is a file: directory dependency; skipped, so that copy \
             stays unpatched",
            block.key
        )),
        CopySource::Unresolved => BlockClass::UnresolvedSkip(format!(
            "lock block `{}` has no resolved tarball; skipped",
            block.key
        )),
        // yarn fetches a git pattern with git, from `resolved` (#363): a
        // vendored tarball there makes every install fail, and the copy is
        // the git bytes.
        CopySource::Git => BlockClass::GitSkip(format!(
            "lock block `{}` installs from git, which yarn fetches from the git \
             source rather than a tarball; skipped, so that copy stays unpatched",
            block.key
        )),
    }
}

/// Rebuild a block's lines with the vendored `resolved`/`integrity`
/// ([`repin_classic_block`], the pin every classic writer shares) and,
/// when the patch rewrote the package's own manifest, the recomputed
/// dependency sub-maps.
fn rewrite_classic_block(
    lines: &[String],
    resolved_value: &str,
    integrity_value: &str,
    staged_pkg: Option<&Value>,
) -> Vec<String> {
    let pinned = repin_classic_block(lines, resolved_value, integrity_value);
    let Some(pkg) = staged_pkg else {
        return pinned;
    };
    let mut out = Vec::with_capacity(pinned.len());
    let mut i = 0;
    while i < pinned.len() {
        if i > 0
            && body_field_line(&pinned[i])
                .is_some_and(|r| r == "dependencies:" || r == "optionalDependencies:")
        {
            // Drop the stale sub-map (header + 4-space entries); the
            // recomputed ones are appended below in yarn's order.
            i += 1;
            while i < pinned.len() && body_field_line(&pinned[i]).is_none() {
                i += 1;
            }
            continue;
        }
        out.push(pinned[i].clone());
        i += 1;
    }
    for field in ["dependencies", "optionalDependencies"] {
        let Some(map) = pkg.get(field).and_then(Value::as_object) else {
            continue;
        };
        if map.is_empty() {
            continue;
        }
        out.push(format!("  {field}:"));
        let mut keys: Vec<&String> = map.keys().collect();
        keys.sort_unstable();
        for k in keys {
            if let Some(range) = map.get(k).and_then(Value::as_str) {
                out.push(format!("    {} \"{range}\"", quote_yarn_key(k)));
            }
        }
    }
    out
}

/// Does this block's `resolved` already point into `.socket/vendor/npm/`
/// (ours — current or stale uuid)?
pub(super) fn block_points_into_vendor(lines: &[String]) -> bool {
    classic_field(lines, "resolved")
        .and_then(parse_vendor_path)
        .is_some_and(|p| p.eco == "npm")
}

// ─────────────────── shared yarn-lock text helpers ───────────────────
// (pub(super): the berry backend reuses the same block grammar — key line at
// column 0 ending `:`, indented body, blank-line separated)

/// Read the project's `yarn.lock` for a vendor run, refusing fail-closed
/// when it is missing or unreadable (vendoring rewires the lockfile, so one
/// must exist). Shared verbatim by the classic and berry backends.
pub(super) async fn read_yarn_lock(project_root: &Path) -> Result<String, Box<VendorOutcome>> {
    match read_regular_to_string(&project_root.join(YARN_LOCK)).await {
        Ok(t) => Ok(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Box::new(refused(
            "vendor_lockfile_missing",
            format!(
                "no {YARN_LOCK} at {} — vendoring rewires the lockfile, so one must \
                 exist (run `yarn install` first)",
                project_root.display()
            ),
        ))),
        Err(e) => Err(Box::new(refused(
            "vendor_lockfile_missing",
            format!("cannot read {YARN_LOCK}: {e}"),
        ))),
    }
}

/// The run's yarn-lock block scans. `scan_blocks` walks every line of the
/// lock and copies each one into the block it belongs to, and BOTH yarn
/// backends re-scan the whole lock for every patched package — plus once
/// per candidate key while splicing. One slot: a project has one yarn.lock,
/// and the splice loop leaves the memo alone once it has rewritten the text
/// (nothing can ask for a half-spliced lock again). An idempotent re-run
/// writes nothing, so every scan after the first hits; see [`ParseMemo`].
static BLOCK_MEMO: ParseMemo<Vec<LockBlock>> = ParseMemo::new();

/// [`scan_blocks`], shared and memoized on the lock text — for the callers
/// that only read the blocks.
pub(crate) fn scan_blocks_shared(text: &str) -> Arc<Vec<LockBlock>> {
    BLOCK_MEMO.parse_infallible(text.as_bytes(), || scan_blocks(text))
}

/// Drop the memoized scans, for the writers on both yarn backends. Never
/// needed for correctness (a scan is keyed on the text it came from) — it
/// is how a write stops the memo holding a scan nothing will hit again.
pub(super) fn forget_block_scans() {
    BLOCK_MEMO.invalidate();
}

/// yarn v1's lockfile key quoting (stringify.js `shouldWrapKey`): wrap when
/// the key would not parse bare.
fn quote_yarn_key(key: &str) -> String {
    let needs = key.is_empty()
        || key.starts_with("true")
        || key.starts_with("false")
        || !key.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        || key
            .chars()
            .any(|c| matches!(c, ':' | ' ' | '\n' | '\t' | '\\' | '"' | ',' | '[' | ']'));
    if needs {
        format!("\"{key}\"")
    } else {
        key.to_string()
    }
}

pub(super) fn lines_to_json(lines: &[String]) -> Value {
    Value::Array(lines.iter().map(|l| Value::String(l.clone())).collect())
}

pub(super) fn json_to_lines(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|v| v.as_str().map(str::to_string))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::yarn::patterns::pattern_real_name;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::PatchFileInfo;
    use crate::patch::apply::{ApplyResult, VerifyStatus};
    use base64::Engine as _;
    use serde_json::json;
    use sha1::Digest as _;
    use std::collections::HashMap;
    use std::path::PathBuf;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const ORIG_INDEX: &[u8] = b"module.exports = () => 'orig';\n";
    const PATCHED_INDEX: &[u8] = b"module.exports = () => 'patched';\n";

    /// The hash constants of the SPIKE's tarball inside the after-lock
    /// fixtures; the tests substitute the recomputed hashes of the tarball
    /// this build packs (everything else must match byte-for-byte).
    const SPIKE_SHA1: &str = "fa4cc6e38a9a5bc17a402e910ac6270a16a0e2b6";
    const SPIKE_SRI: &str =
        "sha512-AhUdVqx1bsqgzQOo7owaHwAHqwHbpwHo4Y1U27ucyBdZn2KxEEzoT9kYGApl8gO3eu5oY2TceRVcmbgLXXRmPw==";

    /// Verbatim spike Y2 before-lock (yarn 1.22.22-generated).
    const Y2_BEFORE: &str = r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


left-pad@^1.3.0:
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e"
  integrity sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==
"#;

    /// Verbatim spike Y2 after-lock — yarn itself round-tripped this
    /// byte-for-byte (spike Y2's re-serialization oracle), so it IS yarn's
    /// own output shape.
    const Y2_AFTER: &str = r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


left-pad@^1.3.0:
  version "1.3.0"
  resolved "file:./.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz#fa4cc6e38a9a5bc17a402e910ac6270a16a0e2b6"
  integrity sha512-AhUdVqx1bsqgzQOo7owaHwAHqwHbpwHo4Y1U27ucyBdZn2KxEEzoT9kYGApl8gO3eu5oY2TceRVcmbgLXXRmPw==
"#;

    /// Verbatim spike Y5 before-lock: a merged two-pattern block, a
    /// separate alias block, and a folder dep.
    const Y5_BEFORE: &str = r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"alias@npm:left-pad@^1.3.0":
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e"
  integrity sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==

"dep-a@file:./dep-a":
  version "1.0.0"
  dependencies:
    left-pad "~1.3.0"

left-pad@^1.3.0, left-pad@~1.3.0:
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e"
  integrity sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==
"#;

    /// Verbatim spike Y5 after-lock.
    const Y5_AFTER: &str = r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"alias@npm:left-pad@^1.3.0":
  version "1.3.0"
  resolved "file:./.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz#fa4cc6e38a9a5bc17a402e910ac6270a16a0e2b6"
  integrity sha512-AhUdVqx1bsqgzQOo7owaHwAHqwHbpwHo4Y1U27ucyBdZn2KxEEzoT9kYGApl8gO3eu5oY2TceRVcmbgLXXRmPw==

"dep-a@file:./dep-a":
  version "1.0.0"
  dependencies:
    left-pad "~1.3.0"

left-pad@^1.3.0, left-pad@~1.3.0:
  version "1.3.0"
  resolved "file:./.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz#fa4cc6e38a9a5bc17a402e910ac6270a16a0e2b6"
  integrity sha512-AhUdVqx1bsqgzQOo7owaHwAHqwHbpwHo4Y1U27ucyBdZn2KxEEzoT9kYGApl8gO3eu5oY2TceRVcmbgLXXRmPw==
"#;

    /// Substitute the spike tarball's hashes with this build's recomputed
    /// ones (the only legal difference vs the fixture).
    fn spike_after(template: &str, sha1: &str, sri: &str) -> String {
        template.replace(SPIKE_SHA1, sha1).replace(SPIKE_SRI, sri)
    }

    struct Fixture {
        tmp: tempfile::TempDir,
        record: PatchRecord,
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

        fn tgz_path(&self) -> PathBuf {
            self.root()
                .join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"))
        }

        async fn lock_text(&self) -> String {
            tokio::fs::read_to_string(self.lock_path()).await.unwrap()
        }

        /// (sha1 hex, sha512 SRI) of the packed tarball on disk.
        async fn packed_hashes(&self) -> (String, String) {
            let tgz = tokio::fs::read(self.tgz_path()).await.unwrap();
            let sha1 = hex::encode(sha1::Sha1::digest(&tgz));
            let sri = format!(
                "sha512-{}",
                base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(&tgz))
            );
            (sha1, sri)
        }

        async fn vendor(&self, dry_run: bool) -> VendorOutcome {
            let blobs = self.root().join(".socket/blobs");
            let sources = PatchSources::blobs_only(&blobs);
            crate::vendor::test_support::vendor_yarn_classic(
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

    // ── source-flip / outage idempotence (vendor::test_support::npm_flip_suite) ──

    impl crate::vendor::test_support::FlipFixture for Fixture {
        fn flip_root(&self) -> &Path {
            self.root()
        }
        fn flip_key(&self) -> String {
            "pkg:npm/left-pad@1.3.0".to_string()
        }
        fn flip_uuid(&self) -> String {
            self.record.uuid.clone()
        }
        fn flip_artifact_rel(&self) -> String {
            format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz")
        }
        fn flip_files(&self) -> Vec<String> {
            vec![YARN_LOCK.to_string(), "package.json".to_string()]
        }
    }

    async fn flip_run(
        fx: &Fixture,
        cfg: Option<&crate::vendor::VendorServiceConfig>,
    ) -> VendorOutcome {
        let blobs = fx.root().join(".socket/blobs");
        crate::vendor::test_support::vendor_yarn_classic(
            "pkg:npm/left-pad@1.3.0",
            &fx.installed(),
            fx.root(),
            &fx.record,
            &PatchSources::blobs_only(&blobs),
            "2026-06-09T00:00:00Z",
            false,
            false,
            cfg,
        )
        .await
    }

    async fn flip_fixture() -> Fixture {
        fixture_with_lock(Y2_BEFORE).await
    }

    crate::vendor::test_support::npm_flip_suite!(flip_suite, Fixture, flip_fixture, flip_run);

    /// Build a project tempdir: installed left-pad, patched blob, the given
    /// yarn.lock bytes, and the PatchRecord.
    async fn fixture_with_lock(lock_text: &str) -> Fixture {
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

        tokio::fs::write(root.join(YARN_LOCK), lock_text.as_bytes())
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
            lock_bytes: lock_text.as_bytes().to_vec(),
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
    async fn y2_fixture_oracle_rewrite_is_byte_exact() {
        let fx = fixture_with_lock(Y2_BEFORE).await;
        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(
            warnings
                .iter()
                .all(|w| w.code == "vendor_prebuilt_downloaded"),
            "{warnings:?}"
        );
        let entry = entry.expect("success carries a ledger entry");

        // Byte-for-byte the spike's after-lock, modulo the recomputed hashes.
        let (sha1, sri) = fx.packed_hashes().await;
        assert_eq!(fx.lock_text().await, spike_after(Y2_AFTER, &sha1, &sri));

        // Ledger shape: flavor, artifact facts, one Rewritten block record
        // with verbatim line arrays.
        assert_eq!(entry.flavor.as_deref(), Some("yarn-classic"));
        assert_eq!(
            entry.artifact.path,
            format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz")
        );
        let tgz = tokio::fs::read(fx.tgz_path()).await.unwrap();
        assert_eq!(entry.artifact.size, Some(tgz.len() as u64));
        assert_eq!(
            entry.artifact.sha256,
            hex::encode(sha2::Sha256::digest(&tgz))
        );
        assert_eq!(entry.wiring.len(), 1);
        let rec = &entry.wiring[0];
        assert_eq!(rec.file, YARN_LOCK);
        assert_eq!(rec.kind, KIND_LOCK_BLOCK);
        assert_eq!(rec.action, WiringAction::Rewritten);
        assert_eq!(rec.key.as_deref(), Some("left-pad@^1.3.0"));
        assert_eq!(
            rec.original.as_ref().unwrap(),
            &json!([
                "left-pad@^1.3.0:",
                "  version \"1.3.0\"",
                "  resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e\"",
                "  integrity sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA=="
            ]),
            "original must be the verbatim pre-vendor block"
        );
        let new_lines = rec.new.as_ref().unwrap().as_array().unwrap();
        assert!(new_lines[2]
            .as_str()
            .unwrap()
            .contains("file:./.socket/vendor/npm/"));

        // The marker sits next to the artifact.
        let marker = tokio::fs::read_to_string(fx.root().join(format!(
            ".socket/vendor/npm/{UUID}/socket-patch.vendor.json"
        )))
        .await
        .unwrap();
        assert!(marker.contains("pkg:npm/left-pad@1.3.0"));
    }

    #[tokio::test]
    async fn y5_merged_keys_and_alias_block_both_rewritten() {
        let fx = fixture_with_lock(Y5_BEFORE).await;
        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        // The folder dep `dep-a@file:./dep-a` is name-mismatched, not a
        // candidate — no skip warning either.
        assert!(
            warnings
                .iter()
                .all(|w| w.code == "vendor_prebuilt_downloaded"),
            "{warnings:?}"
        );
        let entry = entry.unwrap();

        let (sha1, sri) = fx.packed_hashes().await;
        assert_eq!(fx.lock_text().await, spike_after(Y5_AFTER, &sha1, &sri));

        // One record per block: the alias block AND the merged block.
        let mut keys: Vec<&str> = entry
            .wiring
            .iter()
            .map(|r| r.key.as_deref().unwrap())
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "\"alias@npm:left-pad@^1.3.0\"",
                "left-pad@^1.3.0, left-pad@~1.3.0"
            ],
            "verbatim key lines (no colon), quotes preserved"
        );
    }

    #[tokio::test]
    async fn missing_integrity_line_is_added_after_resolved() {
        // A y1-shaped entry (native file: deps get no integrity from yarn);
        // the rewrite must ADD the line so both hash checks are enforced.
        let lock = r#"# yarn lockfile v1

left-pad@^1.3.0:
  version "1.3.0"
  resolved "file:./elsewhere/left-pad-1.3.0.tgz#0123456789abcdef0123456789abcdef01234567"
"#;
        let fx = fixture_with_lock(lock).await;
        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);

        let (sha1, sri) = fx.packed_hashes().await;
        let text = fx.lock_text().await;
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[4],
            format!("  resolved \"file:./.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz#{sha1}\"")
        );
        assert_eq!(
            lines[5],
            format!("  integrity {sri}"),
            "integrity line gained"
        );

        // The record's original is the 3-line block, new is the 4-line one.
        let rec = &entry.unwrap().wiring[0];
        assert_eq!(rec.original.as_ref().unwrap().as_array().unwrap().len(), 3);
        assert_eq!(rec.new.as_ref().unwrap().as_array().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn patched_package_json_recomputes_dep_submaps() {
        let lock = r#"# yarn lockfile v1

left-pad@^1.3.0:
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e"
  integrity sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==
  dependencies:
    old-dep "^1.0.0"
"#;
        let mut fx = fixture_with_lock(lock).await;

        // The patch rewrites package.json: new dependency + an optional one.
        let before: &[u8] = br#"{"name":"left-pad","version":"1.3.0"}"#;
        let after: &[u8] = br#"{"name":"left-pad","version":"1.3.0","dependencies":{"wow":"^1.0.0"},"optionalDependencies":{"@scope/opt":"^2.0.0"}}"#;
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
                .any(|w| w.code == "vendor_dep_manifest_rewritten"),
            "{warnings:?}"
        );

        let text = fx.lock_text().await;
        assert!(!text.contains("old-dep"), "stale sub-map dropped: {text}");
        let want = "  dependencies:\n    wow \"^1.0.0\"\n  optionalDependencies:\n    \"@scope/opt\" \"^2.0.0\"\n";
        assert!(
            text.contains(want),
            "recomputed sub-maps (scoped key quoted): {text}"
        );
    }

    /// #920: the `package.json` advisory is emitted once, by the run that
    /// wires — an in-sync re-run of a manifest-rewriting patch is a quiet
    /// AlreadyPatched.
    #[tokio::test]
    async fn manifest_rewriting_rerun_is_in_sync_without_the_manifest_warning() {
        let mut fx = fixture_with_lock(Y2_BEFORE).await;
        let before: &[u8] = br#"{"name":"left-pad","version":"1.3.0"}"#;
        let after: &[u8] =
            br#"{"name":"left-pad","version":"1.3.0","dependencies":{"wow":"^1.0.0"}}"#;
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
        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success && entry.is_some(), "{:?}", result.error);
        let manifest_warnings = |w: &[VendorWarning]| {
            w.iter()
                .filter(|w| w.code.starts_with("vendor_dep_manifest"))
                .count()
        };
        assert_eq!(manifest_warnings(&warnings), 1, "{warnings:?}");

        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success && entry.is_none(), "{:?}", result.error);
        assert_eq!(manifest_warnings(&warnings), 0, "{warnings:?}");
    }

    /// Twin of npm_lock's relock re-pin test: a relock back to the registry
    /// block, re-pinned from the REUSED tarball (no request under the
    /// outage), recomputes the dependency sub-maps from the reused bytes'
    /// patched package.json.
    #[tokio::test]
    async fn relock_with_pkg_json_patch_recomputes_submaps_from_reused_bytes() {
        use crate::vendor::test_support as ts;
        let lock = r#"# yarn lockfile v1

left-pad@^1.3.0:
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e"
  integrity sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==
  dependencies:
    old-dep "^1.0.0"
"#;
        let mut fx = fixture_with_lock(lock).await;
        let before: &[u8] = br#"{"name":"left-pad","version":"1.3.0"}"#;
        let after: &[u8] =
            br#"{"name":"left-pad","version":"1.3.0","dependencies":{"wow":"^1.0.0"}}"#;
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
        let (r, e, _) = expect_done(flip_run(&fx, None).await);
        assert!(r.success, "{:?}", r.error);
        ts::persist(fx.root(), "pkg:npm/left-pad@1.3.0", e.unwrap()).await;
        let lock1 = fx.lock_text().await;
        let tgz1 = tokio::fs::read(fx.tgz_path()).await.unwrap();
        // The relock.
        tokio::fs::write(fx.lock_path(), &fx.lock_bytes)
            .await
            .unwrap();
        let server = wiremock::MockServer::start().await;
        ts::mount_503(&server).await;
        let cfg = ts::service_cfg(&server.uri(), crate::vendor::VendorSource::Service, false);
        let (r, e, w) = expect_done(flip_run(&fx, Some(&cfg)).await);
        assert!(r.success, "{:?}", r.error);
        assert!(e.is_some(), "the relocked block is re-wired");
        assert!(
            !ts::has_warning(&w, "vendor_prebuilt_unavailable"),
            "reused: {w:?}"
        );
        assert_eq!(ts::request_count(&server).await, 0);
        let text = fx.lock_text().await;
        assert!(!text.contains("old-dep"), "{text}");
        assert!(
            text.contains("  dependencies:\n    wow \"^1.0.0\"\n"),
            "{text}"
        );
        assert_eq!(text, lock1);
        assert_eq!(tokio::fs::read(fx.tgz_path()).await.unwrap(), tgz1);
    }

    #[tokio::test]
    async fn rerun_is_in_sync_and_byte_stable() {
        let fx = fixture_with_lock(Y2_BEFORE).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        assert!(entry.is_some());
        let lock_after_first = tokio::fs::read(fx.lock_path()).await.unwrap();
        let tgz_first = tokio::fs::read(fx.tgz_path()).await.unwrap();

        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success);
        assert!(
            entry.is_none(),
            "in-sync re-run must not produce a new ledger entry"
        );
        assert!(
            warnings
                .iter()
                .all(|w| w.code == "vendor_prebuilt_downloaded"),
            "{warnings:?}"
        );
        assert!(
            result
                .files_verified
                .iter()
                .all(|v| v.status == VerifyStatus::AlreadyPatched),
            "{:?}",
            result.files_verified
        );
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            lock_after_first,
            "lock byte-stable across re-runs"
        );
        assert_eq!(
            tokio::fs::read(fx.tgz_path()).await.unwrap(),
            tgz_first,
            "tarball byte-identical across re-runs"
        );
    }

    /// B16 upgrade state: an older release wired a URL-keyed fork block
    /// into `.socket/vendor/`. That block is ours, so an in-sync re-run
    /// stays a byte-stable no-op (not `vendor_lock_entry_not_rewritable`,
    /// and never "stays UNPATCHED"), and the legacy wiring is named with
    /// the way back.
    #[tokio::test]
    async fn legacy_wired_non_registry_copy_rerun_is_in_sync_and_named() {
        let fx = fixture_with_lock(Y2_BEFORE).await;
        expect_done(fx.vendor(false).await);
        let wired = fx.lock_text().await;
        let legacy = wired.replacen(
            "left-pad@^1.3.0:",
            "\"left-pad@https://host.test/fork/left-pad-1.3.0.tgz\":",
            1,
        );
        assert_ne!(legacy, wired, "fixture re-keys the wired block");
        tokio::fs::write(fx.lock_path(), &legacy).await.unwrap();

        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_none(), "in sync: no new ledger entry");
        let codes: Vec<&str> = warnings
            .iter()
            .map(|w| w.code)
            .filter(|&c| c != "vendor_prebuilt_downloaded")
            .collect();
        assert_eq!(codes, ["vendor_yarn_classic_non_registry_legacy_wiring"]);
        let detail = &warnings
            .iter()
            .find(|w| w.code == codes[0])
            .unwrap()
            .detail;
        assert!(
            detail.contains("host.test/fork")
                && detail.contains("vendor --revert")
                && !detail.contains("UNPATCHED"),
            "{detail}"
        );
        assert_eq!(fx.lock_text().await, legacy, "lock byte-stable");
    }

    #[tokio::test]
    async fn dry_run_writes_nothing() {
        let fx = fixture_with_lock(Y2_BEFORE).await;
        let (result, entry, _) = expect_done(fx.vendor(true).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_none());
        assert!(result.files_patched.is_empty());

        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes
        );
        assert!(!fx.root().join(".socket/vendor").exists());
        assert_eq!(
            tokio::fs::read(fx.installed().join("index.js"))
                .await
                .unwrap(),
            ORIG_INDEX,
            "vendor never patches the installed copy in place"
        );
    }

    #[tokio::test]
    async fn link_and_file_directory_blocks_are_skipped_with_warnings() {
        let extra = r#"
"left-pad@link:../somewhere":
  version "1.3.0"

"left-pad@file:./local-left-pad":
  version "1.3.0"
"#;
        let lock = format!("{Y2_BEFORE}{extra}");
        let fx = fixture_with_lock(&lock).await;
        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert_eq!(
            entry.unwrap().wiring.len(),
            1,
            "only the registry block rewritten"
        );

        let link_warnings: Vec<&VendorWarning> = warnings
            .iter()
            .filter(|w| w.code == "vendor_link_entry_skipped")
            .collect();
        assert_eq!(link_warnings.len(), 2, "{warnings:?}");

        // Skipped blocks byte-untouched.
        let text = fx.lock_text().await;
        assert!(text.contains("\"left-pad@link:../somewhere\":\n  version \"1.3.0\""));
        assert!(text.contains("\"left-pad@file:./local-left-pad\":\n  version \"1.3.0\""));
    }

    /// #1236: yarn 1 locks a `file:` directory or url copy under the
    /// DEPENDENCY name, so a copy of left-pad@1.3.0 declared as `lp2` is
    /// read from the copy itself and named; the registry block is still
    /// wired and the copy stays byte-untouched. Control: a directory
    /// holding another package is not named.
    #[tokio::test]
    async fn issue_1236_other_name_copies_are_named() {
        let extra = r#"
"lp2@file:./lpdir":
  version "1.3.0"

"lp3@https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz":
  version "1.3.0"
  resolved "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz#bbbb"
"#;
        let lock = format!("{Y2_BEFORE}{extra}");
        for (fork, named) in [("left-pad", true), ("other-pkg", false)] {
            let fx = fixture_with_lock(&lock).await;
            tokio::fs::create_dir_all(fx.root().join("lpdir"))
                .await
                .unwrap();
            tokio::fs::write(
                fx.root().join("lpdir/package.json"),
                format!(r#"{{"name":"{fork}","version":"1.3.0"}}"#),
            )
            .await
            .unwrap();
            let (result, entry, warnings) = expect_done(fx.vendor(false).await);
            assert!(result.success, "{:?}", result.error);
            assert_eq!(entry.unwrap().wiring.len(), 1, "the registry block");
            let dir: Vec<&VendorWarning> = warnings
                .iter()
                .filter(|w| w.code == "vendor_link_entry_skipped" && w.detail.contains("lp2@"))
                .collect();
            assert_eq!(dir.len(), usize::from(named), "{fork}: {warnings:?}");
            let url: Vec<&VendorWarning> = warnings
                .iter()
                .filter(|w| {
                    w.code == "vendor_yarn_classic_non_registry_entry_skipped"
                        && w.detail.contains("lp3@")
                })
                .collect();
            assert_eq!(url.len(), 1, "{fork}: {warnings:?}");
            let text = fx.lock_text().await;
            assert!(text.contains("\"lp2@file:./lpdir\":\n  version \"1.3.0\""));
        }
    }

    /// #1236 (review): when left-pad@1.3.0 is locked ONLY under another
    /// dependency name, vendoring refuses `vendor_lock_entry_not_rewritable`
    /// naming that copy, in the loop and in the download plan alike, not
    /// `vendor_lock_entry_not_found` with a `yarn install` remedy that
    /// can't help. Control: a directory holding another package is still
    /// "not found".
    #[tokio::test]
    async fn issue_1236_only_other_name_copies_are_refused_as_not_rewritable() {
        let lock = "# yarn lockfile v1\n\n\n\"lp2@file:./lpdir\":\n  version \"1.3.0\"\n";
        for (fork, code) in [
            ("left-pad", "vendor_lock_entry_not_rewritable"),
            ("other-pkg", "vendor_lock_entry_not_found"),
        ] {
            let fx = fixture_with_lock(lock).await;
            tokio::fs::create_dir_all(fx.root().join("lpdir"))
                .await
                .unwrap();
            tokio::fs::write(
                fx.root().join("lpdir/package.json"),
                format!(r#"{{"name":"{fork}","version":"1.3.0"}}"#),
            )
            .await
            .unwrap();
            let detail = expect_refused(fx.vendor(false).await, code);
            if fork == "left-pad" {
                assert!(detail.contains("lp2@file:./lpdir"), "{detail}");
                assert!(detail.contains("yarn install` will not help"), "{detail}");
            }
            assert_eq!(fx.lock_text().await, lock);
            let pre =
                preflight_packages(fx.root(), &[("pkg:npm/left-pad@1.3.0", &fx.record)]).await;
            assert_eq!(pre, vec![Err(code)], "{fork}");
        }
    }

    #[tokio::test]
    async fn no_matching_block_is_refused_before_any_write() {
        // The lock only knows a different version.
        let lock = Y2_BEFORE.replace("1.3.0", "1.2.0");
        let fx = fixture_with_lock(&lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_not_found");
        assert!(
            detail.contains("yarn install"),
            "actionable detail: {detail}"
        );
        assert!(
            !fx.root().join(".socket/vendor").exists(),
            "refusal writes nothing"
        );
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes
        );
    }

    /// A key that appears on more than one block (a mangled merge — yarn
    /// itself parses duplicates last-wins) must be refused before any write:
    /// the rewrite loop looks blocks up BY KEY, so it would splice the first
    /// same-key block — even a version-mismatched one classification never
    /// selected — and leave the real candidate resolving to the registry,
    /// i.e. report success while the unpatched tarball still installs.
    #[tokio::test]
    async fn duplicate_key_blocks_are_refused_before_any_write() {
        // (a) The duplicate carries a DIFFERENT version: the by-key lookup
        // would corrupt the 1.2.0 block instead of the 1.3.0 candidate.
        let wrong_version_dup = r#"# yarn lockfile v1

left-pad@^1.3.0:
  version "1.2.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.2.0.tgz#d30a73c67b8c4a4b494cb3c7d4cfad4bb1a30b8a"
  integrity sha512-1WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWA==

left-pad@^1.3.0:
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e"
  integrity sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==
"#;
        // (b) Both duplicates are candidates: only the first would be
        // rewritten; the second (yarn's last-wins winner) would stay on the
        // registry.
        let both_candidates_dup = r#"# yarn lockfile v1

left-pad@^1.3.0:
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e"
  integrity sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==

left-pad@^1.3.0:
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e"
  integrity sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==
"#;
        for lock in [wrong_version_dup, both_candidates_dup] {
            let fx = fixture_with_lock(lock).await;
            let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_ambiguous");
            assert!(
                detail.contains("left-pad@^1.3.0"),
                "names the key: {detail}"
            );
            assert!(
                detail.contains("yarn install"),
                "actionable detail: {detail}"
            );
            assert_eq!(
                tokio::fs::read(fx.lock_path()).await.unwrap(),
                fx.lock_bytes,
                "refusal writes nothing"
            );
            assert!(!fx.root().join(".socket/vendor").exists());
        }
    }

    /// A lock-write failure AFTER the tarball is packed must unwind the
    /// freshly created uuid dir — no ledger entry exists for it, so
    /// `--revert` could never clean it up and the user would commit an
    /// unwired artifact (contract: a failure leaves the project
    /// byte-untouched).
    #[cfg(unix)]
    #[tokio::test]
    async fn lock_write_failure_unwinds_the_staged_artifact() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return; // chmod is advisory for root — the failure never fires
        }
        let fx = fixture_with_lock(Y2_BEFORE).await;
        // Pre-create the eco level so staging only creates the uuid dir.
        tokio::fs::create_dir_all(fx.root().join(".socket/vendor/npm"))
            .await
            .unwrap();
        // A read-only project root: yarn.lock still reads and the tarball
        // still packs (into the writable .socket/ subtree), but the atomic
        // lock write (temp file in the root) fails.
        let orig_mode = tokio::fs::metadata(fx.root()).await.unwrap().permissions();
        tokio::fs::set_permissions(fx.root(), std::fs::Permissions::from_mode(0o555))
            .await
            .unwrap();
        let outcome = fx.vendor(false).await;
        tokio::fs::set_permissions(fx.root(), orig_mode)
            .await
            .unwrap();

        let (result, entry, _) = expect_done(outcome);
        assert!(!result.success, "the lock write must fail");
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or("")
                .contains("cannot write yarn.lock"),
            "{:?}",
            result.error
        );
        assert!(entry.is_none());
        assert!(
            !fx.root().join(".socket/vendor").exists(),
            "the staged uuid dir (and its empty parents) must be unwound"
        );
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes
        );
    }

    #[tokio::test]
    async fn berry_lock_and_missing_lock_are_refused() {
        let fx = fixture_with_lock("__metadata:\n  version: 8\n  cacheKey: 10c0\n").await;
        expect_refused(
            fx.vendor(false).await,
            "vendor_lockfile_version_unsupported",
        );

        let fx = fixture_with_lock(Y2_BEFORE).await;
        tokio::fs::remove_file(fx.lock_path()).await.unwrap();
        let detail = expect_refused(fx.vendor(false).await, "vendor_lockfile_missing");
        assert!(detail.contains("yarn install"), "{detail}");
    }

    #[tokio::test]
    async fn revert_round_trips_the_lock_and_removes_the_artifact() {
        let fx = fixture_with_lock(Y5_BEFORE).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        assert!(fx.tgz_path().exists());

        // Dry-run revert: success, nothing restored or removed.
        let outcome = revert_yarn_classic(&entry, fx.root(), true).await;
        assert!(outcome.success);
        assert!(fx.tgz_path().exists());
        assert_ne!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes
        );

        let outcome = revert_yarn_classic(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes,
            "lock restored byte-for-byte"
        );
        assert!(!fx
            .root()
            .join(format!(".socket/vendor/npm/{UUID}"))
            .exists());
    }

    #[tokio::test]
    async fn revert_leaves_drifted_blocks_alone_with_warning() {
        let fx = fixture_with_lock(Y5_BEFORE).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();

        // The user re-resolved the ALIAS block (first occurrence of our
        // resolved line) behind our back.
        let (sha1, _) = fx.packed_hashes().await;
        let ours =
            format!("  resolved \"file:./.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz#{sha1}\"");
        let theirs = "  resolved \"https://example.com/their-fork.tgz#0000000000000000000000000000000000000000\"";
        let text = fx.lock_text().await.replacen(&ours, theirs, 1);
        tokio::fs::write(fx.lock_path(), text).await.unwrap();

        let outcome = revert_yarn_classic(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "{:?}",
            outcome.warnings
        );

        let after = fx.lock_text().await;
        assert!(after.contains("their-fork.tgz"), "drifted block left alone");
        assert!(
            after.contains("left-pad@^1.3.0, left-pad@~1.3.0:\n  version \"1.3.0\"\n  resolved \"https://registry.yarnpkg.com/"),
            "non-drifted block restored: {after}"
        );
        // A drift-skip keeps the artifact dir (the drifted block's recorded
        // original may still be needed later) and says so.
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

        // KEEP-GATE LIVENESS: undo ONLY the drift (repoint the alias block
        // back at the vendored tarball). The block the first revert already
        // restored must now read as CONVERGED, not drifted — otherwise
        // every later revert would re-classify it as drift and keep the
        // artifacts + ledger entry forever.
        let healed = after.replace(theirs, &ours);
        assert_ne!(healed, after, "the undo edit must hit");
        tokio::fs::write(fx.lock_path(), healed).await.unwrap();

        let outcome = revert_yarn_classic(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome.warnings.is_empty(),
            "the already-restored block is converged, not drifted: {:?}",
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
    }

    /// #665: `yarn remove left-pad` deleted the vendored block, so nothing
    /// in yarn.lock resolves through the artifact any more. A vanished
    /// block is not a re-resolution to protect: the revert must succeed and
    /// remove the artifact (letting rollback / `remove` / `scan --prune`
    /// drop the ledger entry), instead of drift-keeping it forever.
    #[tokio::test]
    async fn revert_after_yarn_remove_drops_the_unreferenced_artifact() {
        let fx = fixture_with_lock(Y2_BEFORE).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();

        // What `yarn remove left-pad` leaves behind: the other dependency's
        // block only.
        let removed = "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
                       # yarn lockfile v1\n\n\n\
                       is-number@7.0.0:\n  version \"7.0.0\"\n  \
                       resolved \"https://registry.yarnpkg.com/is-number/-/is-number-7.0.0.tgz\"\n";
        tokio::fs::write(fx.lock_path(), removed).await.unwrap();

        for _ in 0..2 {
            let outcome = revert_yarn_classic(&entry, fx.root(), false).await;
            assert!(outcome.success, "{:?}", outcome.error);
            assert!(!outcome.drift_skipped(), "{:?}", outcome.warnings);
            assert!(!outcome.kept_artifact, "{:?}", outcome.warnings);
            assert!(
                !fx.root()
                    .join(format!(".socket/vendor/npm/{UUID}"))
                    .exists(),
                "nothing resolves through the artifact, so it is removed"
            );
            assert_eq!(
                fx.lock_text().await,
                removed,
                "the user's lock is untouched"
            );
        }
        let outcome = revert_yarn_classic(&entry, fx.root(), false).await;
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_removed"),
            "the vanished block is surfaced: {:?}",
            outcome.warnings
        );
    }

    /// #665 guard: the recorded block vanished, but another (hand-copied or
    /// re-keyed) block still resolves through the artifact. Deleting it
    /// would break that install, so the artifact is kept, as for drift.
    #[tokio::test]
    async fn revert_keeps_artifact_when_a_vanished_block_was_rekeyed() {
        let fx = fixture_with_lock(Y2_BEFORE).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();

        let text = fx
            .lock_text()
            .await
            .replace("left-pad@^1.3.0:", "left-pad@1.3.0:");
        tokio::fs::write(fx.lock_path(), &text).await.unwrap();

        let outcome = revert_yarn_classic(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.kept_artifact, "{:?}", outcome.warnings);
        assert!(fx.tgz_path().exists(), "the re-keyed block still needs it");
        assert_eq!(fx.lock_text().await, text);
    }

    #[tokio::test]
    async fn revert_allowlist_fails_closed_on_foreign_files() {
        let fx = fixture_with_lock(Y2_BEFORE).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let mut entry = entry.unwrap();
        // A poisoned ledger names files outside the yarn.lock allowlist.
        for evil in ["../x", "package.json"] {
            entry.wiring.push(WiringRecord {
                file: evil.to_string(),
                kind: KIND_LOCK_BLOCK.to_string(),
                action: WiringAction::Rewritten,
                key: Some("whatever".to_string()),
                original: Some(json!(["pwned:"])),
                new: Some(json!(["pwned:"])),
            });
        }

        let outcome = revert_yarn_classic(&entry, fx.root(), false).await;
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
        // The legitimate record still restored the lock; nothing was written
        // to (or read from) the foreign paths.
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes
        );
        assert!(!fx.root().join("package.json").exists());
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
        let fx = fixture_with_lock(Y2_BEFORE).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let mut entry = entry.unwrap();
        entry.wiring.clear();
        let lock_vendored = tokio::fs::read(fx.lock_path()).await.unwrap();

        // Still referenced: refuse, artifact and lock untouched.
        for dry_run in [true, false] {
            let outcome = revert_yarn_classic(&entry, fx.root(), dry_run).await;
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
        let outcome = revert_yarn_classic(&entry, fx.root(), false).await;
        assert!(!outcome.success, "unreadable-lock revert must refuse");
        assert!(fx.tgz_path().exists());

        // Re-locked away from the artifact (provably orphaned): removal
        // proceeds, replaying nothing.
        tokio::fs::write(fx.lock_path(), &fx.lock_bytes)
            .await
            .unwrap();
        let outcome = revert_yarn_classic(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(!fx.tgz_path().exists(), "orphaned artifact removed");
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes,
            "empty wiring replays nothing"
        );

        // No lock at all: nothing can reference the artifact — proceed.
        let fx = fixture_with_lock(Y2_BEFORE).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let mut entry = entry.unwrap();
        entry.wiring.clear();
        tokio::fs::remove_file(fx.lock_path()).await.unwrap();
        let outcome = revert_yarn_classic(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(!fx.tgz_path().exists(), "no lock, no reference");
    }

    #[tokio::test]
    async fn revert_refuses_tampered_uuid_fail_closed() {
        let fx = fixture_with_lock(Y2_BEFORE).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let mut entry = entry.unwrap();
        entry.uuid = "../../escape".to_string();
        let outcome = revert_yarn_classic(&entry, fx.root(), false).await;
        assert!(!outcome.success, "tampered uuid must fail closed");
    }

    /// After replaying the recorded blocks, yarn can still resolve through
    /// the artifact via a block the wiring never named (hand-copied or
    /// re-keyed since vendoring). Removing the uuid dir would then fail
    /// every subsequent install on the missing tarball — refuse instead,
    /// fail-closed (twin of npm_lock's and yarn_berry's post-restore
    /// probes).
    #[tokio::test]
    async fn revert_refuses_when_an_unrecorded_lock_entry_still_resolves_through_the_artifact() {
        let fx = fixture_with_lock(Y2_BEFORE).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();

        // Hand-copy the vendored block under a key the wiring never named.
        let (sha1, sri) = fx.packed_hashes().await;
        let extra = format!(
            "\nleft-pad@^1.2.0:\n  version \"1.3.0\"\n  resolved \
             \"file:./.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz#{sha1}\"\n  \
             integrity {sri}\n"
        );
        let text = format!("{}{extra}", fx.lock_text().await);
        tokio::fs::write(fx.lock_path(), text).await.unwrap();

        let outcome = revert_yarn_classic(&entry, fx.root(), false).await;
        assert!(!outcome.success, "must refuse while still referenced");
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_still_wired_revert_blocked"),
            "{:?}",
            outcome.warnings
        );
        assert!(fx.tgz_path().exists(), "artifact survives the refusal");
        // The recorded block was still restored — only the removal is
        // blocked — so undoing the hand-copy lets a re-run converge.
        let after = fx.lock_text().await;
        assert!(
            after.contains("resolved \"https://registry.yarnpkg.com/left-pad/"),
            "recorded block restored: {after}"
        );
        let healed = after.replace(&extra, "");
        assert_ne!(healed, after, "the undo edit must hit");
        tokio::fs::write(fx.lock_path(), healed).await.unwrap();

        let outcome = revert_yarn_classic(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(!fx
            .root()
            .join(format!(".socket/vendor/npm/{UUID}"))
            .exists());
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes,
            "lock restored byte-for-byte once the extra reference is gone"
        );
    }

    /// A FIFO planted as yarn.lock must fail the revert fast instead of
    /// wedging it forever in an `open(2)` waiting for a writer (the vendor
    /// half already reads through `read_regular_to_string`).
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_lock_fails_fast_instead_of_wedging_revert() {
        let fx = fixture_with_lock(Y2_BEFORE).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        tokio::fs::remove_file(fx.lock_path()).await.unwrap();
        mkfifo(&fx.lock_path());

        let deadline = std::time::Duration::from_secs(5);
        let revert = revert_yarn_classic(&entry, fx.root(), false);
        let Ok(outcome) = tokio::time::timeout(deadline, revert).await else {
            // On timeout the open is wedged in a `spawn_blocking` thread the
            // runtime waits for on shutdown; connect a non-blocking writer
            // to release it so the test can FAIL instead of hanging the
            // suite.
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(fx.lock_path());
            panic!("the revert lock read must fail fast on a FIFO");
        };
        assert!(!outcome.success, "a non-regular lock must fail the revert");
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or("")
                .contains("cannot read yarn.lock"),
            "{:?}",
            outcome.error
        );
        assert!(fx.tgz_path().exists(), "artifact survives the failure");
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

    /// The lockfile is a user-owned file we merely edit: both the vendor
    /// rewrite and the revert restore must keep its permission bits (a 0600
    /// private lock must not silently become umask-default 0644).
    #[cfg(unix)]
    #[tokio::test]
    async fn lock_writes_preserve_file_mode() {
        use std::os::unix::fs::PermissionsExt;
        let fx = fixture_with_lock(Y2_BEFORE).await;
        tokio::fs::set_permissions(fx.lock_path(), std::fs::Permissions::from_mode(0o600))
            .await
            .unwrap();

        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();
        let mode = tokio::fs::metadata(fx.lock_path())
            .await
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o600, "vendor must preserve the lockfile's mode");

        let outcome = revert_yarn_classic(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        let mode = tokio::fs::metadata(fx.lock_path())
            .await
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o600, "revert must preserve the lockfile's mode");
    }

    #[tokio::test]
    async fn crlf_lock_is_preserved_and_round_trips() {
        let crlf_before = Y2_BEFORE.replace('\n', "\r\n");
        let fx = fixture_with_lock(&crlf_before).await;
        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);

        let (sha1, sri) = fx.packed_hashes().await;
        let expected = spike_after(Y2_AFTER, &sha1, &sri).replace('\n', "\r\n");
        let text = fx.lock_text().await;
        assert_eq!(
            text, expected,
            "every line (edited and untouched) stays CRLF"
        );
        assert_eq!(
            text.matches('\n').count(),
            text.matches("\r\n").count(),
            "no bare LF introduced"
        );

        let outcome = revert_yarn_classic(&entry.unwrap(), fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            crlf_before.as_bytes(),
            "CRLF lock restored byte-for-byte"
        );
    }

    #[test]
    fn pattern_and_key_helpers() {
        // Key splitting honors quotes and commas.
        assert_eq!(
            split_key_patterns("left-pad@^1.3.0, left-pad@~1.3.0"),
            vec!["left-pad@^1.3.0", "left-pad@~1.3.0"]
        );
        assert_eq!(
            split_key_patterns("\"alias@npm:left-pad@^1.3.0\""),
            vec!["alias@npm:left-pad@^1.3.0"]
        );
        assert_eq!(
            split_key_patterns("\"@scope/pkg@^1.0.0\", \"@scope/pkg@~1.0.0\""),
            vec!["@scope/pkg@^1.0.0", "@scope/pkg@~1.0.0"]
        );

        // Real-name extraction, incl. the alias-range and scoped forms.
        assert_eq!(pattern_real_name("left-pad@^1.3.0"), Some("left-pad"));
        assert_eq!(pattern_real_name("@scope/pkg@^1.0.0"), Some("@scope/pkg"));
        assert_eq!(
            pattern_real_name("alias@npm:left-pad@^1.3.0"),
            Some("left-pad")
        );
        assert_eq!(
            pattern_real_name("alias@npm:@scope/pkg@^1.0.0"),
            Some("@scope/pkg")
        );
        assert_eq!(pattern_real_name("alias@npm:left-pad"), Some("left-pad"));
        assert_eq!(pattern_real_name("no-at-sign"), None);

        // yarn's key quoting rule.
        assert_eq!(quote_yarn_key("left-pad"), "left-pad");
        assert_eq!(quote_yarn_key("@scope/x"), "\"@scope/x\"");
        assert_eq!(quote_yarn_key("3d-lib"), "\"3d-lib\"");
        assert_eq!(quote_yarn_key("true-lib"), "\"true-lib\"");
    }

    #[test]
    fn scan_blocks_grammar() {
        let blocks = scan_blocks(Y5_BEFORE);
        let keys: Vec<&str> = blocks.iter().map(|b| b.key.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "\"alias@npm:left-pad@^1.3.0\"",
                "\"dep-a@file:./dep-a\"",
                "left-pad@^1.3.0, left-pad@~1.3.0"
            ]
        );
        // The folder-dep block captured its 4-space sub-map lines.
        assert_eq!(
            blocks[1].lines,
            vec![
                "\"dep-a@file:./dep-a\":",
                "  version \"1.0.0\"",
                "  dependencies:",
                "    left-pad \"~1.3.0\""
            ]
        );
        // Byte ranges reproduce the source via splice with identical lines.
        for b in &blocks {
            assert_eq!(replace_block(Y5_BEFORE, b, &b.lines, "\n"), Y5_BEFORE);
        }
        // Field reads.
        assert_eq!(classic_field(&blocks[0].lines, "version"), Some("1.3.0"));
        assert!(classic_field(&blocks[1].lines, "resolved").is_none());
    }

    /// A leading BOM is not key text: a header-less lock still yields its
    /// first key (without the BOM), and a splice of that first block keeps
    /// the BOM in place. Each block reports its own terminator, so a
    /// restore into a lock mixed after the fact keeps the block's style.
    #[test]
    fn scan_blocks_skip_a_bom_and_report_each_block_terminator() {
        let text = "\u{feff}__metadata:\r\n  version: 8\r\n\r\n\"a@npm:1\":\n  version: 1\n";
        let blocks = scan_blocks(text);
        let keys: Vec<&str> = blocks.iter().map(|b| b.key.as_str()).collect();
        assert_eq!(keys, vec!["__metadata", "\"a@npm:1\""]);
        assert_eq!(blocks[0].lines[0], "__metadata:");
        for b in &blocks {
            assert_eq!(
                replace_block(text, b, &b.lines, block_eol(text, b)),
                text,
                "{}",
                b.key
            );
        }
        assert_eq!(block_eol(text, &blocks[0]), "\r\n");
        assert_eq!(block_eol(text, &blocks[1]), "\n");
        // An unterminated one-line block falls back to the file's ending.
        let last = "x:\r\n  v: 1\r\n\r\ny:";
        let blocks = scan_blocks(last);
        assert_eq!(block_eol(last, &blocks[1]), "\r\n");
    }

    /// A second canonical uuid, distinct from [`UUID`], for re-vendor tests.
    const UUID_B: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";

    /// The mainline production shape: the vendored package HAS a
    /// dependencies sub-map and the patch does NOT rewrite package.json
    /// (`staged_pkg_json` is `None`). The rewrite must pass the
    /// `dependencies:` header and its 4-space entries through verbatim —
    /// dropping (or recomputing) them would change what installs — and the
    /// revert must round-trip byte-for-byte.
    #[tokio::test]
    async fn deps_submap_preserved_verbatim_without_manifest_patch() {
        let submap = "  dependencies:\n    wow \"^1.0.0\"\n";
        let lock = format!("{Y2_BEFORE}{submap}");
        let fx = fixture_with_lock(&lock).await;
        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(
            !warnings
                .iter()
                .any(|w| w.code == "vendor_dep_manifest_rewritten"),
            "no manifest patch, no recompute warning: {warnings:?}"
        );

        // Byte-exact: the spike after-lock with the sub-map still attached
        // to the block, untouched (resolved repointed, integrity swapped).
        let (sha1, sri) = fx.packed_hashes().await;
        assert_eq!(
            fx.lock_text().await,
            format!("{}{submap}", spike_after(Y2_AFTER, &sha1, &sri)),
            "sub-map lines must survive byte-for-byte"
        );

        let outcome = revert_yarn_classic(&entry.unwrap(), fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes,
            "lock (sub-map included) restored byte-for-byte"
        );
    }

    /// B16: a `file:`-TARBALL range is the user's own artifact, not the
    /// registry package the vendored tarball is built from, so it is never
    /// wired to it: as the only copy it is refused as not rewritable, the
    /// lock untouched. (It used to be rewired to the registry build.)
    #[tokio::test]
    async fn file_tarball_range_only_copy_is_refused_untouched() {
        let lock = r#"# yarn lockfile v1

"left-pad@file:./old/left-pad-1.3.0.tgz":
  version "1.3.0"
  resolved "file:./old/left-pad-1.3.0.tgz#0123456789abcdef0123456789abcdef01234567"
"#;
        let fx = fixture_with_lock(lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_not_rewritable");
        assert!(
            detail.contains("left-pad@file:./old/left-pad-1.3.0.tgz")
                && detail.contains("not the registry's"),
            "{detail}"
        );
        assert_eq!(fx.lock_text().await, lock);
    }

    /// `--preserve-state` (`keep_artifact`): the wiring restore runs
    /// unchanged, the artifact dir stays behind, and `kept_artifact` stays
    /// false (reserved for drift-keeps).
    #[tokio::test]
    async fn preserve_state_revert_keeps_artifact_and_restores_wiring() {
        let fx = fixture_with_lock(Y2_BEFORE).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();

        let outcome = revert_yarn_classic_opts(
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
        assert!(
            !outcome.kept_artifact,
            "kept_artifact stays reserved for drift-keeps"
        );
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes,
            "wiring restored byte-for-byte"
        );
        assert!(
            fx.tgz_path().exists(),
            "the artifact dir must survive a preserve-state revert"
        );
    }

    /// Under `keep_artifact` the deletion is skipped, so the still-wired
    /// probe that exists only to protect it must be skipped too: an
    /// unrecorded hand-copied block that still resolves through the artifact
    /// must NOT block the revert, while the recorded block is still
    /// restored.
    #[tokio::test]
    async fn preserve_state_revert_skips_the_still_wired_probe() {
        let fx = fixture_with_lock(Y2_BEFORE).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();

        // Hand-copy the vendored block under a key the wiring never named.
        let (sha1, sri) = fx.packed_hashes().await;
        let extra = format!(
            "\nleft-pad@^1.2.0:\n  version \"1.3.0\"\n  resolved \
             \"file:./.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz#{sha1}\"\n  \
             integrity {sri}\n"
        );
        let text = format!("{}{extra}", fx.lock_text().await);
        tokio::fs::write(fx.lock_path(), text).await.unwrap();

        let outcome = revert_yarn_classic_opts(
            &entry,
            fx.root(),
            RevertOpts {
                dry_run: false,
                keep_artifact: true,
            },
        )
        .await;
        assert!(
            outcome.success,
            "the probe protects only the skipped deletion: {:?}",
            outcome.error
        );
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_still_wired_revert_blocked"),
            "{:?}",
            outcome.warnings
        );
        let after = fx.lock_text().await;
        assert!(
            after.contains("resolved \"https://registry.yarnpkg.com/left-pad/"),
            "recorded block still restored: {after}"
        );
        assert!(
            after.contains(&extra),
            "the unrecorded block is left alone: {after}"
        );
        assert!(fx.tgz_path().exists(), "artifact kept");
    }

    /// Direct matrix over [`revert_recorded_block`]'s degradation arms
    /// (shared with the berry backend): every poisoned-or-newer-ledger
    /// record must degrade to a `vendor_lock_entry_drifted` warning (a
    /// vanished block to `vendor_lock_entry_removed`) and
    /// leave the text byte-untouched, the converged-under-a-different-key
    /// arm must stay silent, and (control) a well-formed record restores.
    #[test]
    fn revert_recorded_block_degradations_leave_text_alone() {
        fn wrec(key: Option<&str>, kind: &str, original: Option<Value>) -> WiringRecord {
            WiringRecord {
                file: YARN_LOCK.to_string(),
                kind: kind.to_string(),
                action: WiringAction::Rewritten,
                key: key.map(str::to_string),
                original,
                new: None,
            }
        }
        fn run(text_in: &str, rec: &WiringRecord) -> (bool, String, Vec<VendorWarning>) {
            let mut text = text_in.to_string();
            let mut warnings = Vec::new();
            let changed = revert_recorded_block(
                &mut text,
                rec,
                UUID,
                KIND_LOCK_BLOCK,
                "lock block",
                |lines| classic_field(lines, "resolved"),
                &mut warnings,
            );
            (changed, text, warnings)
        }
        fn assert_drift_warning(warnings: &[VendorWarning], detail_needle: &str) {
            assert_eq!(warnings.len(), 1, "{warnings:?}");
            assert_eq!(warnings[0].code, "vendor_lock_entry_drifted");
            assert!(
                warnings[0].detail.contains(detail_needle),
                "want `{detail_needle}` in: {}",
                warnings[0].detail
            );
        }
        // The verbatim pre-vendor left-pad block out of the fixture itself.
        let orig_block = scan_blocks(Y2_BEFORE)
            .into_iter()
            .find(|b| b.key == "left-pad@^1.3.0")
            .expect("Y2_BEFORE has the left-pad block")
            .lines;

        // (a) Record with no key: warned, left alone.
        let rec = wrec(None, KIND_LOCK_BLOCK, Some(lines_to_json(&orig_block)));
        let (changed, text, warnings) = run(Y2_AFTER, &rec);
        assert!(!changed);
        assert_eq!(text, Y2_AFTER, "text byte-untouched");
        assert_drift_warning(&warnings, "has no key");

        // (b) Unknown wiring kind (newer binary): warned, left alone.
        let rec = wrec(
            Some("left-pad@^1.3.0"),
            "future_kind",
            Some(lines_to_json(&orig_block)),
        );
        let (changed, text, warnings) = run(Y2_AFTER, &rec);
        assert!(!changed);
        assert_eq!(text, Y2_AFTER);
        assert_drift_warning(&warnings, "unknown wiring kind `future_kind`");

        // (c) Recorded key gone AND the original block not live anywhere:
        // the dependency was removed since vendoring. Not drift (#665): it
        // warns `vendor_lock_entry_removed`, and the caller keeps the
        // artifact only while the lock still resolves through it.
        let absent = vec!["absent@^9:".to_string(), "  version \"9.0.0\"".to_string()];
        let rec = wrec(
            Some("absent@^9"),
            KIND_LOCK_BLOCK,
            Some(lines_to_json(&absent)),
        );
        let (changed, text, warnings) = run(Y2_AFTER, &rec);
        assert!(!changed);
        assert_eq!(text, Y2_AFTER);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert_eq!(warnings[0].code, super::super::LOCK_ENTRY_REMOVED_CODE);
        assert!(
            warnings[0]
                .detail
                .contains("no longer exists; nothing to restore"),
            "{}",
            warnings[0].detail
        );

        // (d) ALREADY CONVERGED under a different key: the recorded key is
        // gone but the original block is live verbatim — a silent no-op so
        // the drift-keep gate can converge (berry's rekeying restore
        // produces exactly this state).
        let rec = wrec(
            Some("left-pad@file:./x.tgz"),
            KIND_LOCK_BLOCK,
            Some(lines_to_json(&orig_block)),
        );
        let (changed, text, warnings) = run(Y2_BEFORE, &rec);
        assert!(!changed);
        assert_eq!(text, Y2_BEFORE);
        assert!(warnings.is_empty(), "converged is not drift: {warnings:?}");

        // (e) Live block is ours but the record has NO pre-vendor original
        // (a re-vendor over our own stale edit): warned, left as-is.
        let rec = wrec(Some("left-pad@^1.3.0"), KIND_LOCK_BLOCK, None);
        let (changed, text, warnings) = run(Y2_AFTER, &rec);
        assert!(!changed);
        assert_eq!(text, Y2_AFTER);
        assert_drift_warning(&warnings, "no recorded pre-vendor original");

        // Control: a well-formed record against the vendored text restores
        // the original block (the matrix would prove nothing if the inputs
        // were degenerate).
        let rec = wrec(
            Some("left-pad@^1.3.0"),
            KIND_LOCK_BLOCK,
            Some(lines_to_json(&orig_block)),
        );
        let (changed, text, warnings) = run(Y2_AFTER, &rec);
        assert!(changed, "control record must restore");
        assert_eq!(text, Y2_BEFORE);
        assert!(
            warnings
                .iter()
                .all(|w| w.code == "vendor_prebuilt_downloaded"),
            "{warnings:?}"
        );
    }

    /// Re-vendoring over our own stale edit (a new patch uuid for the same
    /// package) must record `original: None` — never a `.socket/vendor/`
    /// pointer as the "pre-vendor" state — and a revert of that entry
    /// degrades to the no-original drift arm: lock left alone, artifact and
    /// ledger kept.
    #[tokio::test]
    async fn revendor_under_new_uuid_records_no_original_and_drift_keeps_on_revert() {
        let fx = fixture_with_lock(Y2_BEFORE).await;
        let (_, entry_a, _) = expect_done(fx.vendor(false).await);
        assert!(entry_a.is_some());

        // Same package, same files, NEW patch uuid.
        let mut record_b = fx.record.clone();
        record_b.uuid = UUID_B.to_string();
        let blobs = fx.root().join(".socket/blobs");
        let sources = PatchSources::blobs_only(&blobs);
        let outcome = crate::vendor::test_support::vendor_yarn_classic(
            "pkg:npm/left-pad@1.3.0",
            &fx.installed(),
            fx.root(),
            &record_b,
            &sources,
            "2026-06-10T00:00:00Z",
            false,
            false,
            None,
        )
        .await;
        let (result, entry_b, _) = expect_done(outcome);
        assert!(result.success, "{:?}", result.error);
        let entry_b = entry_b.expect("re-vendor under a new uuid is a real edit");
        assert_eq!(entry_b.wiring.len(), 1);
        assert!(
            entry_b.wiring[0].original.is_none(),
            "our own stale edit must never be recorded as the pre-vendor original"
        );
        let new_lines = entry_b.wiring[0].new.as_ref().unwrap().to_string();
        assert!(new_lines.contains(UUID_B), "new block points at uuid B");
        let vendored_b = fx.lock_text().await;
        assert!(vendored_b.contains(UUID_B), "lock repointed at uuid B");
        assert!(!vendored_b.contains(UUID), "stale uuid-A pointer replaced");

        // Reverting entry B: the block is ours, but there is no pre-vendor
        // fragment to restore — drift warning, lock untouched, artifact and
        // (by contract) the ledger entry kept.
        let outcome = revert_yarn_classic(&entry_b, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"
                    && w.detail.contains("no recorded pre-vendor original")),
            "{:?}",
            outcome.warnings
        );
        assert!(outcome.kept_artifact, "drift-skip keeps the artifact");
        assert!(
            fx.root()
                .join(format!(".socket/vendor/npm/{UUID_B}"))
                .exists(),
            "uuid-B dir kept"
        );
        assert_eq!(
            fx.lock_text().await,
            vendored_b,
            "lock left alone (still resolves through uuid B)"
        );
    }

    /// The two pre-wiring failure bubbles: an unsafe purl refuses via the
    /// shared coordinates guard before any disk access, and a stage failure
    /// (installed copy missing) fails the run — both before any write inside
    /// the project.
    #[tokio::test]
    async fn unsafe_purl_and_stage_failure_bubble_before_any_project_write() {
        // (a) Unsafe coordinates: refused, nothing written.
        let fx = fixture_with_lock(Y2_BEFORE).await;
        let blobs = fx.root().join(".socket/blobs");
        let sources = PatchSources::blobs_only(&blobs);
        let outcome = crate::vendor::test_support::vendor_yarn_classic(
            "pkg:npm/left-pad@../evil",
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
        expect_refused(outcome, "unsafe_coordinates");
        assert!(!fx.root().join(".socket/vendor").exists());
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes
        );

        // (b) Stage failure: the installed copy is gone.
        tokio::fs::remove_dir_all(fx.installed()).await.unwrap();
        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(!result.success, "staging a missing install must fail");
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or("")
                .contains("patch service request failed"),
            "{:?}",
            result.error
        );
        assert!(entry.is_none());
        assert!(
            !fx.root().join(".socket/vendor").exists(),
            "stage failure precedes any project write"
        );
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes
        );
    }

    /// The marker is informational: a marker write failure must degrade to a
    /// warning on an otherwise fully successful vendor (tarball packed, lock
    /// rewritten, ledger entry produced).
    #[tokio::test]
    async fn marker_write_failure_is_a_nonfatal_warning() {
        let fx = fixture_with_lock(Y2_BEFORE).await;
        // A DIRECTORY squatting on the marker path: the tarball pack into
        // the (pre-existing) uuid dir succeeds, the marker's atomic rename
        // onto a directory fails.
        let marker_path = fx.root().join(format!(
            ".socket/vendor/npm/{UUID}/socket-patch.vendor.json"
        ));
        tokio::fs::create_dir_all(&marker_path).await.unwrap();

        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some(), "the vendor itself succeeded");
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_marker_write_failed"),
            "{warnings:?}"
        );
        assert!(fx.tgz_path().exists(), "tarball packed");
        let (sha1, sri) = fx.packed_hashes().await;
        assert_eq!(
            fx.lock_text().await,
            spike_after(Y2_AFTER, &sha1, &sri),
            "lock rewrite unaffected by the marker failure"
        );
    }

    /// Revert-side lock-write failure fails closed: the artifact and the
    /// on-disk (still vendored) lock are both untouched, so a re-run after
    /// fixing the permission converges.
    #[cfg(unix)]
    #[tokio::test]
    async fn revert_lock_write_failure_leaves_lock_and_artifact_untouched() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return; // chmod is advisory for root — the failure never fires
        }
        let fx = fixture_with_lock(Y2_BEFORE).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let lock_vendored = tokio::fs::read(fx.lock_path()).await.unwrap();

        // A read-only project root: yarn.lock still reads, but the atomic
        // write (temp file in the root) fails.
        let orig_mode = tokio::fs::metadata(fx.root()).await.unwrap().permissions();
        tokio::fs::set_permissions(fx.root(), std::fs::Permissions::from_mode(0o555))
            .await
            .unwrap();
        let outcome = revert_yarn_classic(&entry, fx.root(), false).await;
        tokio::fs::set_permissions(fx.root(), orig_mode)
            .await
            .unwrap();

        assert!(!outcome.success, "the lock write must fail");
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or("")
                .contains("cannot write yarn.lock"),
            "{:?}",
            outcome.error
        );
        assert!(fx.tgz_path().exists(), "artifact survives the failure");
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            lock_vendored,
            "on-disk lock untouched on write failure"
        );
    }

    /// Artifact-removal failure at the END of a wet revert: the lock is
    /// already restored, the failure is surfaced, and a re-run after fixing
    /// the permission converges (records read as converged, removal
    /// retried).
    #[cfg(unix)]
    #[tokio::test]
    async fn revert_remove_failure_surfaces_and_rerun_converges() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return; // chmod is advisory for root — the failure never fires
        }
        let fx = fixture_with_lock(Y2_BEFORE).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();

        // A read-only .socket/vendor/npm parent: the uuid dir's CONTENTS
        // still unlink (the uuid dir itself is writable), but the final
        // rmdir of the uuid dir fails.
        let npm_dir = fx.root().join(".socket/vendor/npm");
        tokio::fs::set_permissions(&npm_dir, std::fs::Permissions::from_mode(0o555))
            .await
            .unwrap();
        let outcome = revert_yarn_classic(&entry, fx.root(), false).await;
        tokio::fs::set_permissions(&npm_dir, std::fs::Permissions::from_mode(0o755))
            .await
            .unwrap();

        assert!(!outcome.success, "the removal must fail");
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or("")
                .contains(&format!("cannot remove .socket/vendor/npm/{UUID}")),
            "{:?}",
            outcome.error
        );
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes,
            "the lock was already restored before the removal failed"
        );

        // Re-run liveness: the restored block reads as converged (silently),
        // and the removal is retried and succeeds.
        let outcome = revert_yarn_classic(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome.warnings.is_empty(),
            "converged records are not drift: {:?}",
            outcome.warnings
        );
        assert!(
            !fx.root()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "artifact removed on the re-run"
        );
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes
        );
    }

    /// `--preserve-state` with a repair-reconstructed (empty-wiring) entry:
    /// the deletion-protecting refusal must be SKIPPED (the fn doc, bun and
    /// pnpm-legacy all promise it — a preserve-state revert deletes
    /// nothing), so the revert completes as a successful no-op with lock and
    /// artifact intact. Dry-run preview included.
    #[tokio::test]
    async fn empty_wiring_preserve_state_revert_skips_the_deletion_refusal() {
        let fx = fixture_with_lock(Y2_BEFORE).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let mut entry = entry.unwrap();
        entry.wiring.clear();
        let lock_vendored = tokio::fs::read(fx.lock_path()).await.unwrap();

        for dry_run in [true, false] {
            let outcome = revert_yarn_classic_opts(
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
            assert!(fx.tgz_path().exists(), "artifact kept");
            assert_eq!(
                tokio::fs::read(fx.lock_path()).await.unwrap(),
                lock_vendored,
                "empty wiring replays nothing"
            );
        }
    }

    // ── download-plan pre-flight parity ───────────────────────────────────

    /// `(the plan's verdict, the loop's own outcome)` for the fixture's
    /// package — the pre-flight first, since a successful vendor rewrites
    /// the lock it would then read.
    async fn preflight_then_vendor(
        fx: &Fixture,
    ) -> (Result<(), &'static str>, Result<(), &'static str>) {
        let planned = preflight_packages(fx.root(), &[("pkg:npm/left-pad@1.3.0", &fx.record)])
            .await
            .remove(0);
        let looped = match fx.vendor(false).await {
            VendorOutcome::Refused { code, .. } => Err(code),
            VendorOutcome::Done { .. } => Ok(()),
        };
        (planned, looped)
    }

    /// The vendor loop's download plan gates each package with this
    /// backend's own pre-flight (`preflight_packages`): the lock read,
    /// re-sniffed and scanned once, then the candidate gate per package.
    /// Same code wherever the loop refuses, admitted wherever it vendors.
    #[tokio::test]
    async fn preflight_agrees_with_the_loop_on_every_pre_service_refusal() {
        let (planned, looped) = preflight_then_vendor(&fixture_with_lock(Y2_BEFORE).await).await;
        assert_eq!(
            (planned, looped),
            (Ok(()), Ok(())),
            "the plain fixture vendors"
        );

        let absent = Y2_BEFORE.replace("1.3.0", "1.2.0");
        let duplicate_key = r#"# yarn lockfile v1

left-pad@^1.3.0:
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e"
  integrity sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==

left-pad@^1.3.0:
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e"
  integrity sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==
"#;
        let berry = "__metadata:\n  version: 8\n  cacheKey: 10c0\n";
        let cases: [(&str, &str, &str); 3] = [
            ("absent block", &absent, "vendor_lock_entry_not_found"),
            (
                "duplicate key",
                duplicate_key,
                "vendor_lock_entry_ambiguous",
            ),
            ("berry lock", berry, "vendor_lockfile_version_unsupported"),
        ];
        for (label, lock, code) in cases {
            let (planned, looped) = preflight_then_vendor(&fixture_with_lock(lock).await).await;
            assert_eq!(looped, Err(code), "{label}: the loop's own refusal");
            assert_eq!(
                planned, looped,
                "{label}: the plan must refuse as the loop does"
            );
        }

        let fx = fixture_with_lock(Y2_BEFORE).await;
        tokio::fs::remove_file(fx.lock_path()).await.unwrap();
        let (planned, looped) = preflight_then_vendor(&fx).await;
        assert_eq!(looped, Err("vendor_lockfile_missing"));
        assert_eq!(planned, looped);
    }

    /// #363: a git-pattern block is fetched by yarn 1's git fetcher from its
    /// `resolved`, so vendoring must never rewrite it — the registry block
    /// beside it is still wired, and the skip is named, not silent.
    #[tokio::test]
    async fn git_pattern_block_is_skipped_with_warning() {
        let extra = r#"
"left-pad@git+https://github.com/stevemao/left-pad.git#v1.3.0":
  version "1.3.0"
  resolved "git+https://github.com/stevemao/left-pad.git#ff8e7ba5b0b3a5ad2f1bb06a4e6aef1c6b2c3d4e"
"#;
        let lock = format!("{Y2_BEFORE}{extra}");
        let fx = fixture_with_lock(&lock).await;
        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert_eq!(
            entry.unwrap().wiring.len(),
            1,
            "only the registry block rewritten"
        );
        assert_eq!(
            warnings
                .iter()
                .filter(|w| w.code == "vendor_yarn_classic_git_entry_skipped")
                .count(),
            1,
            "{warnings:?}"
        );
        let text = fx.lock_text().await;
        assert!(
            text.contains(extra.trim_start()),
            "git block byte-untouched:\n{text}"
        );
    }

    /// #363, #857: a lock whose ONLY copy is git-sourced has nothing
    /// vendoring can wire — refused before any write, the lock untouched,
    /// with the real reason (the git block, named) rather than the generic
    /// "run `yarn install`" advice, which can't help.
    #[tokio::test]
    async fn git_only_lock_is_refused_untouched() {
        let lock = r#"# yarn lockfile v1


"left-pad@git+file:///tmp/lpgit#v1.3.0":
  version "1.3.0"
  resolved "git+file:///tmp/lpgit#a380ff32159b9beb078ec6ce294cf6fbdad19c55"
"#;
        let fx = fixture_with_lock(lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_not_rewritable");
        assert!(
            detail.contains("left-pad@git+file:///tmp/lpgit#v1.3.0") && detail.contains("git"),
            "{detail}"
        );
        assert!(!detail.contains("yarn install`)"), "{detail}");
        assert_eq!(fx.lock_text().await, lock);
        let pre = preflight_packages(fx.root(), &[("pkg:npm/left-pad@1.3.0", &fx.record)]).await;
        assert_eq!(pre, vec![Err("vendor_lock_entry_not_rewritable")]);
    }

    /// #921: a `file:` directory copy (no `resolved`) that is the only copy
    /// of the package, alone or merged into one key with a registry range,
    /// is refused as not rewritable, naming the block, the lock untouched.
    #[tokio::test]
    async fn file_directory_only_lock_is_refused_untouched() {
        for block in [
            "\"left-pad@file:forks/left-pad\":\n  version \"1.3.0\"\n",
            "left-pad@^1.3.0, \"left-pad@file:forks/left-pad\":\n  version \"1.3.0\"\n",
        ] {
            let lock = format!("# yarn lockfile v1\n\n\n{block}");
            let fx = fixture_with_lock(&lock).await;
            let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_not_rewritable");
            assert!(detail.contains("left-pad@file:forks/left-pad"), "{detail}");
            assert_eq!(fx.lock_text().await, lock);
        }
    }

    /// #921: a `file:` directory copy beside the registry block: the
    /// registry block is wired and the copy is named as staying unpatched.
    #[tokio::test]
    async fn file_directory_copy_beside_registry_is_skipped_with_warning() {
        let extra = "\n\"left-pad@file:forks/left-pad\":\n  version \"1.3.0\"\n";
        let lock = format!("{Y2_BEFORE}{extra}");
        let fx = fixture_with_lock(&lock).await;
        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert_eq!(entry.unwrap().wiring.len(), 1, "only the registry block");
        let skip: Vec<&VendorWarning> = warnings
            .iter()
            .filter(|w| w.code == "vendor_link_entry_skipped")
            .collect();
        assert_eq!(skip.len(), 1, "{warnings:?}");
        assert!(
            skip[0].detail.contains("left-pad@file:forks/left-pad")
                && skip[0].detail.contains("unpatched"),
            "{skip:?}"
        );
        assert!(fx.lock_text().await.contains(extra.trim_start()));
    }

    /// B16: a hosted-git shorthand (locked to a codeload tarball) or URL
    /// copy beside the registry block: the registry block is wired, and
    /// each non-registry copy is named as staying unpatched, its block
    /// byte-identical.
    #[tokio::test]
    async fn non_registry_tarball_copies_beside_registry_are_skipped_with_warning() {
        let extra = "\nleft-pad@stevemao/left-pad#v1.3.0:\n  version \"1.3.0\"\n  \
                     resolved \"https://codeload.github.com/stevemao/left-pad/tar.gz/ff8e7ba5\"\n\
                     \n\"left-pad@https://host.test/fork/left-pad-1.3.0.tgz\":\n  version \"1.3.0\"\n  \
                     resolved \"https://host.test/fork/left-pad-1.3.0.tgz\"\n";
        let lock = format!("{Y2_BEFORE}{extra}");
        let fx = fixture_with_lock(&lock).await;
        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert_eq!(entry.unwrap().wiring.len(), 1, "only the registry block");
        let skipped: Vec<&VendorWarning> = warnings
            .iter()
            .filter(|w| w.code == "vendor_yarn_classic_non_registry_entry_skipped")
            .collect();
        assert_eq!(skipped.len(), 2, "{warnings:?}");
        assert!(
            skipped[0].detail.contains("stevemao/left-pad#v1.3.0"),
            "{skipped:?}"
        );
        assert!(skipped[1].detail.contains("host.test/fork"), "{skipped:?}");
        assert!(fx.lock_text().await.ends_with(extra));
    }
}
