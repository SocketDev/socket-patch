//! yarn classic (v1 lockfile) vendor backend: lock-only block surgery.
//!
//! Vendoring under yarn classic = pack the patched tree into the
//! deterministic tarball under `.socket/vendor/npm/<uuid>/` (shared npm
//! pipeline) and rewrite every matching `yarn.lock` block's
//! `resolved "file:./<rel-tgz>#<sha1>"` + `integrity <sha512 SRI>`.
//! `package.json` is untouched — the block's range keys still match.
//! Spike-proven (Y2/Y5/Y6 in `spikes/PHASE0-V2-FINDINGS.txt`): the rewrite
//! passes `--frozen-lockfile`, installs offline from a fresh checkout, and
//! round-trips yarn's own serializer byte-for-byte.
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

use serde_json::Value;

use crate::manifest::schema::PatchRecord;
use crate::patch::apply::PatchSources;
use crate::patch::copy_tree::remove_tree;
use crate::utils::fs::atomic_write_bytes;

use super::common::{already_patched_verify, synthesized_result};
use super::npm_common::{done_failure, guard_coordinates, refused, stage_patch_pack};
use super::path::{parse_vendor_path, vendor_uuid_dir_rel};
use super::state::{
    write_marker, VendorArtifact, VendorEntry, VendorMarker, WiringAction, WiringRecord,
};
use super::{RevertOutcome, VendorOutcome, VendorWarning};

const YARN_LOCK: &str = "yarn.lock";

/// The `WiringRecord.kind` this backend owns: one rewritten lock block,
/// `original`/`new` = verbatim block line arrays (key line included).
const KIND_LOCK_BLOCK: &str = "yarn_lock_block";

/// Vendor one installed npm package into a yarn-classic project.
///
/// Same contract as [`super::npm_lock::vendor_npm`]: refuse-early, wire-last
/// (every refusal fires before any write inside the project; the lock edit is
/// the final mutation), `entry` is `None` for dry runs and the in-sync
/// re-run.
#[allow(clippy::too_many_arguments)]
pub async fn vendor_yarn_classic(
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
    let uuid_dir_rel = coords.uuid_dir_rel;
    let base_purl = coords.base_purl;

    // ── 2. Lockfile ───────────────────────────────────────────────────────
    let lock_path = project_root.join(YARN_LOCK);
    let text = match tokio::fs::read_to_string(&lock_path).await {
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
    // Defensive re-sniff: the flavor router already separates classic from
    // berry, but rewriting a berry lock with classic grammar would corrupt
    // it — never proceed past a `__metadata:` key.
    if text.lines().any(|l| l.starts_with("__metadata:")) {
        return refused(
            "vendor_lockfile_version_unsupported",
            "yarn.lock is a yarn berry (v2+) lockfile (top-level `__metadata:` key); the \
             yarn-classic backend cannot rewrite it"
                .to_string(),
        );
    }

    // ── 3. Find the rewritable blocks (pre-flight, BEFORE staging) ────────
    let mut candidate_keys: Vec<String> = Vec::new();
    for block in scan_blocks(&text) {
        match classify_classic_block(&block, name, version) {
            BlockClass::Candidate => candidate_keys.push(block.key.clone()),
            BlockClass::LinkSkip(detail) => {
                warnings.push(VendorWarning::new("vendor_link_entry_skipped", detail));
            }
            BlockClass::NoMatch => {}
        }
    }
    if candidate_keys.is_empty() {
        return refused(
            "vendor_lock_entry_not_found",
            format!(
                "{YARN_LOCK} has no rewritable block for {name}@{version} — make sure the \
                 package is installed and locked (`yarn install`) before vendoring"
            ),
        );
    }

    // ── 4–7. Stage → patch → pack (shared flavor-agnostic pipeline) ───────
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
        // Failed patch (no lock writes — wiring is last) or a dry run.
        return VendorOutcome::Done {
            result,
            entry: None,
            warnings,
        };
    };
    let rel_tgz = staged.rel_tgz;
    let packed = staged.packed;
    let staged_pkg_json = staged.staged_pkg_json;
    let dest = project_root.join(&rel_tgz);
    // SECURITY/CORRECTNESS: the `file:./` prefix is load-bearing — a bare
    // path is registry-relative to yarn classic (spike Y2: 404).
    let resolved_value = format!("file:./{rel_tgz}#{}", packed.sha1_hex);

    // ── 8. Lock rewrite: splice each candidate block, byte-preserving ─────
    let eol = detect_eol(&text);
    let mut new_text = text.clone();
    let mut wiring: Vec<WiringRecord> = Vec::new();
    let mut recomputed_deps = false;
    for key in &candidate_keys {
        let edit = {
            let blocks = scan_blocks(&new_text);
            let Some(block) = blocks.iter().find(|b| &b.key == key) else {
                return done_failure(purl, format!("lock block `{key}` vanished mid-rewrite"));
            };
            let new_lines = rewrite_classic_block(
                &block.lines,
                &resolved_value,
                &packed.integrity,
                staged_pkg_json.as_ref(),
            );
            if new_lines == block.lines {
                // Idempotency: already carrying our exact spec — no edit, no
                // wiring record.
                None
            } else {
                // Never record one of our own (stale) edits as the
                // "original" — revert must restore the pre-vendor registry
                // fragment, not a dangling `.socket/vendor/` pointer.
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
            if staged_pkg_json.is_some() {
                recomputed_deps = true;
            }
        }
    }
    if recomputed_deps {
        warnings.push(VendorWarning::new(
            "vendor_dep_manifest_rewritten",
            format!(
                "the patch rewrites {name}@{version}'s package.json; its lock blocks' \
                 dependencies/optionalDependencies sub-maps were recomputed from the patched \
                 manifest"
            ),
        ));
    }

    if wiring.is_empty() {
        // Every block already points at this uuid with the packed hashes:
        // in sync. Touch nothing (the tarball re-pack above was
        // byte-identical by determinism) and synthesize AlreadyPatched.
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

    if let Err(e) = atomic_write_bytes(&lock_path, new_text.as_bytes()).await {
        return done_failure(purl, format!("cannot write {YARN_LOCK}: {e}"));
    }

    // ── 9. Marker + ledger entry ──────────────────────────────────────────
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
        flavor: Some("yarn-classic".to_string()),
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

/// Undo one yarn-classic vendored package: restore the recorded lock blocks
/// and remove the artifact dir.
pub async fn revert_yarn_classic(
    entry: &VendorEntry,
    project_root: &Path,
    dry_run: bool,
) -> RevertOutcome {
    // SECURITY: `entry.uuid` comes from the committed, tamper-able
    // state.json and names the directory tree we are about to DELETE —
    // validate fail-closed before any disk access.
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
    let text = match tokio::fs::read_to_string(&lock_path).await {
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
            revert_one_block(
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

    if let Err(e) = remove_tree(&project_root.join(&uuid_dir_rel)).await {
        return RevertOutcome::failed(format!("cannot remove {uuid_dir_rel}: {e}"));
    }

    outcome
}

/// Apply one wiring record in reverse: restore `original` iff the live block
/// is still ours (drift = a third party re-resolved it; leave theirs alone,
/// with a warning).
fn revert_one_block(
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
    if rec.kind != KIND_LOCK_BLOCK {
        // Forward compatibility: an unknown kind from a newer binary
        // degrades to a warning (see state.rs schema docs).
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
                format!("lock block `{key}` no longer exists; nothing to restore"),
            ));
            return;
        };
        // Ownership gate: the live block's resolved must still point into
        // OUR uuid dir — anything else means a third party re-resolved it.
        let ours = classic_field(&block.lines, "resolved")
            .and_then(parse_vendor_path)
            .is_some_and(|p| p.eco == "npm" && p.uuid == entry_uuid);
        if !ours {
            warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!("lock block `{key}` was re-resolved since vendoring; left alone"),
            ));
            return;
        }
        let Some(original) = rec.original.as_ref().and_then(json_to_lines) else {
            // The record rewrote one of our own earlier edits, so there is
            // no pre-vendor fragment to restore (by design). Surface it
            // instead of guessing a registry URL.
            warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "lock block `{key}` has no recorded pre-vendor original; left as-is \
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

// ─────────────────────────── block classification ───────────────────────────

#[derive(Debug)]
enum BlockClass {
    /// Rewritable instance of the target package.
    Candidate,
    /// Matches the target but cannot be rewired; carries the warning detail.
    LinkSkip(String),
    NoMatch,
}

/// Does this block stand for `name@version`, and can it be rewired?
fn classify_classic_block(block: &LockBlock, name: &str, version: &str) -> BlockClass {
    let patterns = split_key_patterns(&block.key);
    if patterns.is_empty() {
        return BlockClass::NoMatch;
    }
    // Every key pattern must resolve to the target package's real name (an
    // `alias@npm:left-pad@^1.3.0` pattern carries the real name inside the
    // range — spike Y5's alias block).
    if !patterns.iter().all(|p| pattern_real_name(p) == Some(name)) {
        return BlockClass::NoMatch;
    }
    if classic_field(&block.lines, "version") != Some(version) {
        return BlockClass::NoMatch;
    }
    // link: and file:-DIRECTORY ranges resolve from the working tree, not a
    // tarball — rewriting their resolved would not change what installs.
    for pattern in &patterns {
        let range = split_pattern(pattern).map(|(_, r)| r).unwrap_or("");
        if range.starts_with("link:") {
            return BlockClass::LinkSkip(format!(
                "lock block `{}` is a link: dependency; skipped",
                block.key
            ));
        }
        if let Some(path) = range.strip_prefix("file:") {
            if !is_tarball_path(path) {
                return BlockClass::LinkSkip(format!(
                    "lock block `{}` is a file: directory dependency; skipped",
                    block.key
                ));
            }
        }
    }
    if classic_field(&block.lines, "resolved").is_none() {
        return BlockClass::LinkSkip(format!(
            "lock block `{}` has no resolved tarball; skipped",
            block.key
        ));
    }
    BlockClass::Candidate
}

/// Rebuild a block's lines with the vendored `resolved`/`integrity` (adding
/// the integrity line when absent — yarn then enforces both hashes) and,
/// when the patch rewrote the package's own manifest, the recomputed
/// dependency sub-maps.
fn rewrite_classic_block(
    lines: &[String],
    resolved_value: &str,
    integrity_value: &str,
    staged_pkg: Option<&Value>,
) -> Vec<String> {
    let has_integrity = lines
        .iter()
        .skip(1)
        .any(|l| body_field_line(l).is_some_and(|r| r.starts_with("integrity ")));
    let mut out = vec![lines[0].clone()];
    let mut i = 1;
    while i < lines.len() {
        let line = &lines[i];
        if let Some(rest) = body_field_line(line) {
            if rest.starts_with("resolved ") {
                out.push(format!("  resolved \"{resolved_value}\""));
                if !has_integrity {
                    // yarn's field order: version, resolved, integrity, deps.
                    out.push(format!("  integrity {integrity_value}"));
                }
                i += 1;
                continue;
            }
            if rest.starts_with("integrity ") {
                out.push(format!("  integrity {integrity_value}"));
                i += 1;
                continue;
            }
            if staged_pkg.is_some() && (rest == "dependencies:" || rest == "optionalDependencies:")
            {
                // Drop the stale sub-map (header + 4-space entries); the
                // recomputed ones are appended below in yarn's order.
                i += 1;
                while i < lines.len() && body_field_line(&lines[i]).is_none() {
                    i += 1;
                }
                continue;
            }
        }
        out.push(line.clone());
        i += 1;
    }
    if let Some(pkg) = staged_pkg {
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

/// `file:` path → tarball or directory? Directories cannot be rewired.
fn is_tarball_path(path: &str) -> bool {
    let path = path.split('#').next().unwrap_or(path).trim_end_matches('/');
    path.ends_with(".tgz") || path.ends_with(".tar.gz")
}

// ─────────────────── shared yarn-lock text helpers ───────────────────
// (pub(super): the berry backend reuses the same block grammar — key line at
// column 0 ending `:`, indented body, blank-line separated)

/// One key-line block of a yarn lockfile (classic or berry).
#[derive(Debug)]
pub(super) struct LockBlock {
    /// Byte offset of the key line's first byte.
    pub start: usize,
    /// Byte offset one past the last body line (incl. its terminator).
    pub end: usize,
    /// Whether the final line carried a terminator (false only at EOF).
    pub terminated: bool,
    /// Key line text without the trailing `:` (quotes kept verbatim).
    pub key: String,
    /// Verbatim block lines (key line first), without line terminators.
    pub lines: Vec<String>,
}

/// Scan a lockfile into blocks, CRLF-aware. Comments, blank lines, and
/// anything else outside blocks are left to the splicer untouched.
pub(super) fn scan_blocks(text: &str) -> Vec<LockBlock> {
    // (start, end-incl-terminator, content-without-terminator, terminated)
    let mut lines: Vec<(usize, usize, &str, bool)> = Vec::new();
    let mut pos = 0;
    for seg in text.split_inclusive('\n') {
        let start = pos;
        pos += seg.len();
        let terminated = seg.ends_with('\n');
        let mut content = seg;
        if terminated {
            content = &content[..content.len() - 1];
        }
        let content = content.strip_suffix('\r').unwrap_or(content);
        lines.push((start, pos, content, terminated));
    }
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let (start, _, content, _) = lines[i];
        if is_key_line(content) {
            let mut j = i + 1;
            while j < lines.len() && is_body_line(lines[j].2) {
                j += 1;
            }
            blocks.push(LockBlock {
                start,
                end: lines[j - 1].1,
                terminated: lines[j - 1].3,
                key: content[..content.len() - 1].to_string(),
                lines: lines[i..j].iter().map(|l| l.2.to_string()).collect(),
            });
            i = j;
        } else {
            i += 1;
        }
    }
    blocks
}

fn is_key_line(s: &str) -> bool {
    !s.is_empty() && !s.starts_with([' ', '\t', '#']) && s.ends_with(':')
}

fn is_body_line(s: &str) -> bool {
    s.starts_with(' ') || s.starts_with('\t')
}

/// The file's dominant line terminator (new lines we write use it; bytes
/// outside edited blocks keep whatever they had).
pub(super) fn detect_eol(text: &str) -> &'static str {
    if text.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}

/// Splice `new_lines` over `block`'s byte range, preserving every byte
/// outside it.
pub(super) fn replace_block(
    text: &str,
    block: &LockBlock,
    new_lines: &[String],
    eol: &str,
) -> String {
    let mut replacement = new_lines.join(eol);
    if block.terminated {
        replacement.push_str(eol);
    }
    format!(
        "{}{}{}",
        &text[..block.start],
        replacement,
        &text[block.end..]
    )
}

/// A 2-space body field line (`version "1.3.0"` / `resolution: "..."`),
/// returned without the indent; deeper sub-map lines return `None`.
pub(super) fn body_field_line(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("  ")?;
    if rest.starts_with(' ') {
        return None;
    }
    Some(rest)
}

/// Read a classic scalar field (`<name> "<value>"`, integrity unquoted).
pub(super) fn classic_field<'a>(lines: &'a [String], field: &str) -> Option<&'a str> {
    for line in lines.iter().skip(1) {
        let Some(rest) = body_field_line(line) else {
            continue;
        };
        let Some(value) = rest.strip_prefix(field) else {
            continue;
        };
        let Some(value) = value.strip_prefix(' ') else {
            continue;
        };
        return Some(value.trim().trim_matches('"'));
    }
    None
}

/// Split a comma-joined key into its patterns, honoring quoting; the
/// surrounding quotes are dropped from each pattern.
pub(super) fn split_key_patterns(key: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for ch in key.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                let p = cur.trim();
                if !p.is_empty() {
                    out.push(p.to_string());
                }
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    let p = cur.trim();
    if !p.is_empty() {
        out.push(p.to_string());
    }
    out
}

/// Split `name@range` at the first `@` past a leading `@scope/` marker.
pub(super) fn split_pattern(pattern: &str) -> Option<(&str, &str)> {
    let from = usize::from(pattern.starts_with('@'));
    let at = pattern[from..].find('@')? + from;
    let (name, range) = (&pattern[..at], &pattern[at + 1..]);
    if name.is_empty() || range.is_empty() {
        return None;
    }
    Some((name, range))
}

/// The real package a key pattern stands for: its name, unless the range is
/// an `npm:` alias — then the aliased target's name.
pub(super) fn pattern_real_name(pattern: &str) -> Option<&str> {
    let (name, range) = split_pattern(pattern)?;
    if let Some(aliased) = range.strip_prefix("npm:") {
        return match split_pattern(aliased) {
            Some((real, _)) => Some(real),
            None => Some(aliased), // `npm:left-pad` with no range
        };
    }
    Some(name)
}

/// yarn v1's lockfile key quoting (stringify.js `shouldWrapKey`): wrap when
/// the key would not parse bare.
pub(super) fn quote_yarn_key(key: &str) -> String {
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
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::PatchFileInfo;
    use crate::patch::apply::{ApplyResult, VerifyStatus};
    use std::collections::HashMap;
    use base64::Engine as _;
    use serde_json::json;
    use sha1::Digest as _;
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

    /// Verbatim `spikes/yarn-classic/y2-lock-rewrite/before/yarn.lock`
    /// (yarn 1.22.22-generated).
    const Y2_BEFORE: &str = r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


left-pad@^1.3.0:
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e"
  integrity sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==
"#;

    /// Verbatim `spikes/yarn-classic/y2-lock-rewrite/after/yarn.lock` — yarn
    /// itself round-tripped this byte-for-byte (spike Y2's re-serialization
    /// oracle), so it IS yarn's own output shape.
    const Y2_AFTER: &str = r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


left-pad@^1.3.0:
  version "1.3.0"
  resolved "file:./.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz#fa4cc6e38a9a5bc17a402e910ac6270a16a0e2b6"
  integrity sha512-AhUdVqx1bsqgzQOo7owaHwAHqwHbpwHo4Y1U27ucyBdZn2KxEEzoT9kYGApl8gO3eu5oY2TceRVcmbgLXXRmPw==
"#;

    /// Verbatim `spikes/yarn-classic/y5-merged-alias/before/yarn.lock`:
    /// a merged two-pattern block, a separate alias block, and a folder dep.
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

    /// Verbatim `spikes/yarn-classic/y5-merged-alias/after/yarn.lock`.
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
            vendor_yarn_classic(
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
        assert!(warnings.is_empty(), "{warnings:?}");
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
        assert!(warnings.is_empty(), "{warnings:?}");
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
        assert!(warnings.is_empty(), "{warnings:?}");
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
        assert!(!fx
            .root()
            .join(format!(".socket/vendor/npm/{UUID}"))
            .exists());
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

    #[tokio::test]
    async fn revert_refuses_tampered_uuid_fail_closed() {
        let fx = fixture_with_lock(Y2_BEFORE).await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let mut entry = entry.unwrap();
        entry.uuid = "../../escape".to_string();
        let outcome = revert_yarn_classic(&entry, fx.root(), false).await;
        assert!(!outcome.success, "tampered uuid must fail closed");
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
}
