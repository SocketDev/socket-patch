//! bun vendor backend: LOCK-ONLY `bun.lock` surgery.
//!
//! Spike BN3 (`spikes/PHASE0-V2-FINDINGS.txt`, fixtures in `spikes/bun/`)
//! proved the lock-only edit is sound on bun 1.3.x: rewriting just the
//! `packages` entry passes `bun install --frozen-lockfile` / `bun ci`, the
//! lock stays byte-stable under plain `bun install`, the entry's integrity
//! (sha512 of the raw tarball bytes) is enforced fail-closed even on plain
//! installs (BN5), warm caches never shadow the tarball (BN6), and a fresh
//! checkout installs fully offline (BN7). package.json is left UNTOUCHED —
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

use std::collections::HashMap;
use std::path::Path;

use serde_json::Value;

use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{ApplyResult, PatchSources, VerifyResult, VerifyStatus};
use crate::patch::copy_tree::remove_tree;
use crate::utils::fs::atomic_write_bytes;

use super::npm_common::{done_failure, guard_coordinates, refused, stage_patch_pack, tgz_rel_leaf};
use super::path::{parse_vendor_path, vendor_uuid_dir_rel};
use super::state::{
    write_marker, VendorArtifact, VendorEntry, VendorMarker, WiringAction, WiringRecord,
};
use super::{RevertOutcome, VendorOutcome, VendorWarning};

const BUN_LOCK: &str = "bun.lock";

/// The only text-lockfile version the surgery has byte-exact fixtures for
/// (bun 1.3.x; spike pinned 1.3.14).
const SUPPORTED_LOCK_VERSION: u64 = 1;

/// The `WiringRecord.kind` this backend owns: key = the `packages` map key,
/// original/new = the verbatim entry LINE.
const KIND_LOCK_PACKAGE: &str = "bun_lock_package";

/// SECURITY: revert writes are restricted to the one file vendor edits — a
/// poisoned state.json must not be able to point the rewrite at an arbitrary
/// project file. Records naming anything else are skipped with a warning
/// (fail-closed).
const REVERT_ALLOWLIST: [&str; 1] = [BUN_LOCK];

/// Vendor one installed npm package into a bun project (see the module doc).
/// Same contract as `npm_lock::vendor_npm`: refuse-early / wire-last,
/// `entry` present iff `result.success` and not a dry run, and an in-sync
/// re-run synthesizes AlreadyPatched with no entry.
#[allow(clippy::too_many_arguments)]
pub async fn vendor_bun(
    purl: &str,
    installed_dir: &Path,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
) -> VendorOutcome {
    let mut warnings: Vec<VendorWarning> = Vec::new();

    // ── 1. Coordinates (shared fail-closed guard) ─────────────────────────
    let coords = match guard_coordinates(purl, record) {
        Ok(coords) => coords,
        Err(outcome) => return *outcome,
    };
    let (name, version) = (coords.name, coords.version);
    // BN3 spelling: BARE project-relative path, no `file:`/`./` prefix.
    let rel_tgz = format!("{}/{}", coords.uuid_dir_rel, tgz_rel_leaf(name, version));

    // ── 2. Read + strictly parse the lock (refuse before any write) ──────
    let lock_text = match tokio::fs::read_to_string(project_root.join(BUN_LOCK)).await {
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
    let has_match = entries
        .iter()
        .any(|e| classify(e, &target_spec, name).is_some());
    if !has_match {
        return refused(
            "vendor_lock_entry_not_found",
            format!(
                "{BUN_LOCK} has no packages entry resolving {name}@{version} — make sure \
                 the package is installed and locked (`bun install`) before vendoring"
            ),
        );
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
    debug_assert_eq!(staged.rel_tgz, rel_tgz);
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
    for entry in &entries {
        let Some(shape) = classify(entry, &target_spec, name) else {
            continue;
        };
        let (deps_verbatim, was_ours) = match shape {
            TupleShape::Registry => (entry.elems[2].clone(), false),
            TupleShape::Ours { path } => {
                // Idempotency: an instance already carrying this exact path
                // and integrity needs no edit and no wiring record.
                if path == rel_tgz && entry.elems[2] == json_str(&packed.integrity) {
                    continue;
                }
                (entry.elems[1].clone(), true)
            }
        };
        let original_line = lines[entry.line_idx].clone();
        let new_line = format!(
            "{indent}{key}: [\"{name}@{rel_tgz}\", {deps}, \"{integrity}\"]{comma}",
            indent = entry.indent,
            key = entry.key_raw,
            deps = deps_verbatim,
            integrity = packed.integrity,
            comma = if entry.trailing_comma { "," } else { "" },
        );
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
        // integrity: in sync. The tarball re-pack above was byte-identical
        // by determinism; synthesize AlreadyPatched and record nothing.
        let verified = record
            .files
            .keys()
            .map(|f| already_patched_verify(f))
            .collect();
        return VendorOutcome::Done {
            result: synthesized_result(purl, &project_root.join(&rel_tgz), verified, true, None),
            entry: None,
            warnings,
        };
    }

    if let Err(e) =
        atomic_write_bytes(&project_root.join(BUN_LOCK), lines.join("\n").as_bytes()).await
    {
        return done_failure(purl, format!("cannot write {BUN_LOCK}: {e}"));
    }

    // ── 6. Marker + ledger entry ──────────────────────────────────────────
    let mut vulnerabilities: Vec<String> = record.vulnerabilities.keys().cloned().collect();
    vulnerabilities.sort();
    let marker = VendorMarker {
        schema_version: 1,
        purl: coords.base_purl.clone(),
        patch_uuid: record.uuid.clone(),
        ecosystem: "npm".to_string(),
        vulnerabilities,
        vendored_at: vendored_at.to_string(),
    };
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
pub async fn revert_bun(entry: &VendorEntry, project_root: &Path, dry_run: bool) -> RevertOutcome {
    // SECURITY: `entry.uuid` comes from the committed, tamper-able
    // state.json and names the directory tree we are about to DELETE.
    // Validate through the same fail-closed grammar vendor used.
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
            if let Err(e) =
                atomic_write_bytes(&project_root.join(BUN_LOCK), lines.join("\n").as_bytes()).await
            {
                return RevertOutcome::failed(format!("cannot write {BUN_LOCK}: {e}"));
            }
        }
    }

    if let Err(e) = remove_tree(&project_root.join(&uuid_dir_rel)).await {
        return RevertOutcome::failed(format!("cannot remove {uuid_dir_rel}: {e}"));
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
        // Ours iff the line is exactly what we wrote, or its tuple still
        // points into OUR uuid dir (a re-serialized but unmoved entry).
        let exact = Some(lines[idx].as_str()) == rec.new.as_ref().and_then(Value::as_str);
        let ours_uuid = parsed.elems.len() == 3
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

// ───────────────────────── conservative line grammar ──────────────────────

/// One parsed single-line packages entry.
struct BunEntry {
    line_idx: usize,
    /// Leading whitespace, re-emitted verbatim.
    indent: String,
    /// Decoded map key (`left-pad`, `haspad/left-pad`).
    key: String,
    /// The key token exactly as spelled (incl. quotes), re-emitted verbatim.
    key_raw: String,
    /// Verbatim top-level tuple elements (trimmed).
    elems: Vec<String>,
    trailing_comma: bool,
}

/// What a matching entry's tuple looks like.
enum TupleShape {
    /// Registry 4-tuple `["name@version", "<registry>", {deps}, "sha512-…"]`.
    Registry,
    /// Our local 3-tuple (any uuid; the caller decides current vs stale).
    Ours { path: String },
}

/// Classify an entry against the target: `Some(Registry)` for the exact
/// `name@version` registry tuple, `Some(Ours{..})` for one of our own
/// `.socket/vendor/npm/` tuples for the same package, `None` otherwise.
fn classify(entry: &BunEntry, target_spec: &str, name: &str) -> Option<TupleShape> {
    let spec = decode_json_string(entry.elems.first()?)?;
    match entry.elems.len() {
        4 if spec == target_spec
            && decode_json_string(&entry.elems[1]).is_some()
            && entry.elems[2].starts_with('{')
            && decode_json_string(&entry.elems[3]).is_some() =>
        {
            Some(TupleShape::Registry)
        }
        3 => {
            let (entry_name, path) = split_name_spec(&spec)?;
            if entry_name != name || !entry.elems[1].starts_with('{') {
                return None;
            }
            let parts = parse_vendor_path(path)?;
            (parts.eco == "npm").then(|| TupleShape::Ours {
                path: path.to_string(),
            })
        }
        _ => None,
    }
}

/// `name@spec` split at the LAST `@` (scoped names keep their leading `@`).
fn split_name_spec(s: &str) -> Option<(&str, &str)> {
    let at = s.rfind('@').filter(|&i| i > 0)?;
    Some((&s[..at], &s[at + 1..]))
}

/// `"lockfileVersion": <n>` head check — only the fixture-pinned text
/// lockfile version is spliced (fail-closed on anything newer/older).
fn check_lock_version(text: &str) -> Result<(), String> {
    let version = text.lines().take(5).find_map(|line| {
        line.trim()
            .strip_prefix("\"lockfileVersion\":")
            .map(|rest| rest.trim().trim_end_matches(',').to_string())
    });
    match version.as_deref().map(str::parse::<u64>) {
        Some(Ok(v)) if v == SUPPORTED_LOCK_VERSION => Ok(()),
        Some(Ok(v)) => Err(format!(
            "{BUN_LOCK} has lockfileVersion {v}; only {SUPPORTED_LOCK_VERSION} is supported — \
             re-lock with bun >= 1.3"
        )),
        _ => Err(format!(
            "{BUN_LOCK} has no integer lockfileVersion in its head; only \
             {SUPPORTED_LOCK_VERSION} is supported — re-lock with bun >= 1.3"
        )),
    }
}

/// `(header_idx, close_idx)` of the `"packages": {` section.
fn packages_bounds(lines: &[String]) -> Option<(usize, usize)> {
    let start = lines
        .iter()
        .position(|l| l.trim_end() == "  \"packages\": {")?;
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, l)| matches!(l.trim_end(), "  }" | "  },"))
        .map(|(i, _)| i)?;
    Some((start, end))
}

/// Strictly parse every entry line of the packages section. Any line that
/// is neither blank nor a single-line `"key": [tuple]` entry fails CLOSED.
fn parse_packages_section(lines: &[String]) -> Result<Vec<BunEntry>, String> {
    let Some((start, end)) = packages_bounds(lines) else {
        // No (or unterminated) packages section: an empty lock simply has
        // no entries; an unterminated one is malformed.
        return if lines.iter().any(|l| l.trim_end() == "  \"packages\": {") {
            Err("unterminated \"packages\" section".to_string())
        } else {
            Ok(Vec::new())
        };
    };
    let mut entries = Vec::new();
    for (idx, line) in lines.iter().enumerate().take(end).skip(start + 1) {
        if line.trim().is_empty() {
            continue;
        }
        let mut entry = parse_entry_line(line).map_err(|e| format!("line {}: {e}", idx + 1))?;
        entry.line_idx = idx;
        entries.push(entry);
    }
    Ok(entries)
}

/// Parse one `    "key": ["…", …],` line (the only shape bun emits for
/// packages entries). Returns `Err` on anything that deviates.
fn parse_entry_line(line: &str) -> Result<BunEntry, String> {
    let indent_len = line.len() - line.trim_start().len();
    let (indent, s) = line.split_at(indent_len);
    // Key token: a JSON string.
    let key_end = scan_json_string(s)?;
    let key_raw = &s[..key_end];
    let key = decode_json_string(key_raw).ok_or("invalid JSON string key")?;
    // `: [` separator.
    let after = s[key_end..]
        .strip_prefix(':')
        .ok_or("expected `:` after the entry key")?
        .trim_start();
    if !after.starts_with('[') {
        return Err("entry value is not a single-line array".to_string());
    }
    // The tuple, with depth/string tracking up to its matching `]`.
    let close = scan_balanced_array(after)?;
    let interior = &after[1..close - 1];
    let tail = after[close..].trim();
    let trailing_comma = match tail {
        "" => false,
        "," => true,
        other => return Err(format!("unexpected trailing content `{other}`")),
    };
    let elems = split_top_level(interior)?;
    if elems.is_empty() {
        return Err("empty tuple".to_string());
    }
    Ok(BunEntry {
        line_idx: 0, // set by the caller
        indent: indent.to_string(),
        key,
        key_raw: key_raw.to_string(),
        elems,
        trailing_comma,
    })
}

/// Byte index one past the closing quote of the JSON string at the start of
/// `s` (escape-aware).
fn scan_json_string(s: &str) -> Result<usize, String> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'"') {
        return Err("expected a quoted key".to_string());
    }
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return Ok(i + 1),
            _ => i += 1,
        }
    }
    Err("unterminated string".to_string())
}

/// Byte index one past the `]` matching the `[` at the start of `s`
/// (string- and nesting-aware).
fn scan_balanced_array(s: &str) -> Result<usize, String> {
    let bytes = s.as_bytes();
    let mut depth = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i += scan_json_string(&s[i..]).map_err(|e| e.to_string())? - 1,
            b'[' | b'{' => depth += 1,
            b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    Err("unterminated array".to_string())
}

/// Split the tuple interior at top-level commas into verbatim trimmed
/// element substrings.
fn split_top_level(interior: &str) -> Result<Vec<String>, String> {
    let bytes = interior.as_bytes();
    let mut elems = Vec::new();
    let mut depth = 0usize;
    let mut elem_start = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i += scan_json_string(&interior[i..])? - 1,
            b'[' | b'{' => depth += 1,
            b']' | b'}' => {
                depth = depth.checked_sub(1).ok_or("unbalanced brackets")?;
            }
            b',' if depth == 0 => {
                elems.push(interior[elem_start..i].trim().to_string());
                elem_start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let last = interior[elem_start..].trim();
    if !last.is_empty() {
        elems.push(last.to_string());
    }
    if elems.iter().any(String::is_empty) {
        return Err("empty tuple element".to_string());
    }
    Ok(elems)
}

/// Decode a verbatim JSON string token; `None` if it is not one.
fn decode_json_string(token: &str) -> Option<String> {
    if !token.starts_with('"') {
        return None;
    }
    serde_json::from_str::<String>(token).ok()
}

/// Encode for verbatim comparison against a tuple element.
fn json_str(s: &str) -> String {
    format!("\"{s}\"")
}

// ───────────────────────── small shared helpers ───────────────────────────
// (same shapes as npm_lock's; duplicated because that module's helpers are
// private and this file is the only allowed edit surface)

fn synthesized_result(
    package_key: &str,
    path: &Path,
    files_verified: Vec<VerifyResult>,
    success: bool,
    error: Option<String>,
) -> ApplyResult {
    ApplyResult {
        package_key: package_key.to_string(),
        package_path: path.display().to_string(),
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
    use crate::manifest::schema::PatchFileInfo;
    use base64::Engine as _;
    use sha2::{Digest, Sha512};
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

        let lock = BN3_BEFORE_LOCK.replace("\"lockfileVersion\": 1,", "\"lockfileVersion\": 2,");
        let fx = fixture_with(&lock, "node_modules/left-pad").await;
        let detail = expect_refused(
            fx.vendor(false).await,
            "vendor_lockfile_version_unsupported",
        );
        assert!(detail.contains('2'), "{detail}");
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
        assert!(
            !fx.root()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "artifact still removed"
        );
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

    #[test]
    fn line_grammar_parses_the_fixture_shapes() {
        // Registry 4-tuple with deps and trailing comma.
        let e = parse_entry_line(
            r#"    "haspad/left-pad": ["left-pad@1.3.0", "", {}, "sha512-XI=="],"#,
        )
        .unwrap();
        assert_eq!(e.key, "haspad/left-pad");
        assert_eq!(e.key_raw, "\"haspad/left-pad\"");
        assert_eq!(e.indent, "    ");
        assert!(e.trailing_comma);
        assert_eq!(
            e.elems,
            vec!["\"left-pad@1.3.0\"", "\"\"", "{}", "\"sha512-XI==\""]
        );

        // Local 3-tuple with a deps object containing commas + brackets.
        let e = parse_entry_line(
            r#"    "haspad": ["haspad@./h.tgz", { "dependencies": { "a": "^1", "b": "[2]" } }, "sha512-C=="]"#,
        )
        .unwrap();
        assert_eq!(e.elems.len(), 3);
        assert_eq!(
            e.elems[1],
            r#"{ "dependencies": { "a": "^1", "b": "[2]" } }"#
        );
        assert!(!e.trailing_comma);

        // split at the LAST @ (scoped names).
        assert_eq!(
            split_name_spec("@scope/pkg@1.0.0"),
            Some(("@scope/pkg", "1.0.0"))
        );
        assert_eq!(
            split_name_spec("left-pad@.socket/x.tgz"),
            Some(("left-pad", ".socket/x.tgz"))
        );
        assert_eq!(
            split_name_spec("@scope/pkg"),
            None,
            "a scope @ alone is not a version sep"
        );

        // Fail-closed grammar.
        assert!(
            parse_entry_line("    \"k\": [\"a\", ").is_err(),
            "unterminated"
        );
        assert!(parse_entry_line("    k: [\"a\"]").is_err(), "unquoted key");
        assert!(parse_entry_line("    \"k\": \"not an array\"").is_err());
        assert!(
            parse_entry_line("    \"k\": [\"a\"], junk").is_err(),
            "trailing junk"
        );
    }
}
