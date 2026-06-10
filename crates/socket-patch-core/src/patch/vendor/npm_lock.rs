//! npm vendor backend: lock surgery + orchestration.
//!
//! Vendoring an npm package = pack the patched tree into a deterministic
//! tarball under `.socket/vendor/npm/<uuid>/` ([`super::npm_pack`]) and
//! rewrite every matching lockfile entry's `resolved` to a relative `file:`
//! spec + `integrity` to the tarball's recomputed sha512. That lock-only
//! rewrite passes `npm ci` (spike-proven; see `spikes/PHASE0-FINDINGS.txt`):
//! a relative `file:` resolves against the project dir and npm never
//! rewrites/normalizes the entry.
//!
//! The `integrity` recompute is load-bearing, not cosmetic: npm trusts a
//! cache entry that matches `integrity`, so leaving the registry's sha512 in
//! place would make a warm npm cache silently install the UNPATCHED registry
//! bytes — no error, no patch. Every rewrite therefore carries the packed
//! tarball's own hash, never an inherited one.

use std::collections::HashMap;
use std::path::Path;

use serde_json::Value;

use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{ApplyResult, PatchSources, VerifyResult, VerifyStatus};
use crate::patch::copy_tree::remove_tree;
use crate::utils::fs::atomic_write_bytes;

use super::npm_common::{done_failure, guard_coordinates, refused, stage_patch_pack};
use super::path::{parse_vendor_path, vendor_uuid_dir_rel};
use super::state::{
    write_marker, VendorArtifact, VendorEntry, VendorMarker, WiringAction, WiringRecord,
};
use super::{RevertOutcome, VendorOutcome, VendorWarning};

// Test-only re-imports: the helpers moved to `npm_common` but the existing
// suite exercises them through `use super::*` and stays unmodified.
#[cfg(test)]
use super::npm_common::{is_safe_npm_name, parse_npm_purl, tgz_rel_leaf};

/// `npm-shrinkwrap.json` wins over `package-lock.json` when both exist —
/// npm itself ignores the package-lock in that case, so editing it would be
/// a silent no-op.
const SHRINKWRAP: &str = "npm-shrinkwrap.json";
const PACKAGE_LOCK: &str = "package-lock.json";

const NODE_MODULES_SEG: &str = "node_modules/";

/// Wiring kinds (the `WiringRecord.kind` discriminators this backend owns).
const KIND_LOCK_ENTRY: &str = "npm_lock_entry";
const KIND_LOCK_LEGACY_ENTRY: &str = "npm_lock_legacy_entry";

/// Lock-entry fields that mirror the package's own `package.json`. When the
/// patch rewrites that manifest, these go stale in the lock and `npm ci`
/// would resolve the OLD dependency graph — so they are recomputed from the
/// patched manifest (step 7 of [`vendor_npm`]).
const DEP_MANIFEST_FIELDS: [&str; 4] = [
    "dependencies",
    "peerDependencies",
    "optionalDependencies",
    "bin",
];

/// Vendor one installed npm package.
///
/// * `purl` — `pkg:npm/[@scope/]name@version` (qualifiers tolerated).
/// * `installed_dir` — the crawler's `node_modules/<pkg>` dir; read-only
///   input (patching happens on a staged copy, never in place).
/// * `vendored_at` — RFC3339 timestamp for the informational marker.
///
/// Ordering is refuse-early, wire-last: every refusal fires before any write
/// inside the project, and the lockfile edit is the final mutation so a
/// failure can never leave a lock pointing at an artifact that was not
/// produced. On success `entry` carries the ledger record to persist —
/// `None` for dry runs and for the in-sync re-run (the existing ledger entry
/// stays authoritative; we never re-record our own edit as an "original").
#[allow(clippy::too_many_arguments)]
pub async fn vendor_npm(
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

    // ── 1. Coordinates (shared guard: fail-closed before any disk access,
    //       see `npm_common::guard_coordinates` for the security note) ────
    let coords = match guard_coordinates(purl, record) {
        Ok(coords) => coords,
        Err(outcome) => return *outcome,
    };
    let (name, version) = (coords.name, coords.version);
    let uuid_dir_rel = coords.uuid_dir_rel;
    let base_purl = coords.base_purl;

    // ── 2. Lockfile selection ───────────────────────────────────────────
    let (lock_name, lock_bytes) = match select_lockfile(project_root).await {
        Ok(Some(found)) => found,
        Ok(None) => {
            return refused(
                "vendor_lockfile_missing",
                format!(
                    "no {PACKAGE_LOCK} or {SHRINKWRAP} at {} — vendoring rewires the lockfile, \
                     so one must exist (run `npm install` first)",
                    project_root.display()
                ),
            );
        }
        Err(e) => {
            return refused(
                "vendor_lockfile_missing",
                format!("cannot read the lockfile: {e}"),
            );
        }
    };
    let mut lock: Value = match serde_json::from_slice(&lock_bytes) {
        Ok(v) => v,
        Err(e) => {
            return refused(
                "vendor_lockfile_version_unsupported",
                format!("{lock_name} is not parseable JSON: {e}"),
            );
        }
    };
    let lock_version = lock.get("lockfileVersion").and_then(Value::as_u64);
    if !matches!(lock_version, Some(2) | Some(3))
        || !lock.get("packages").is_some_and(Value::is_object)
    {
        return refused(
            "vendor_lockfile_version_unsupported",
            format!(
                "{lock_name} has lockfileVersion {:?}; only v2/v3 locks (with a `packages` \
                 object) are supported — run `npm install` with npm >= 7 to upgrade it",
                lock_version
            ),
        );
    }

    // ── 3. Find the rewritable lock instances ───────────────────────────
    let matches = match scan_lock_matches(&lock, name, version, &mut warnings) {
        LockScan::Matches(m) => m,
        LockScan::WorkspaceMember { key } => {
            // A matching key outside node_modules/ is the user's own
            // workspace member — its source of truth is the working tree,
            // not a tarball; vendoring it would shadow their code.
            return refused(
                "vendor_workspace_member",
                format!(
                    "`{key}` is a workspace member of this project; patch the source directly \
                     instead of vendoring it"
                ),
            );
        }
    };
    if matches.is_empty() {
        return refused(
            "vendor_lock_entry_not_found",
            format!(
                "{lock_name} has no rewritable entry for {name}@{version} — make sure the \
                 package is installed and locked (`npm install`) before vendoring"
            ),
        );
    }

    // ── 4–7. Stage → patch → pack (shared flavor-agnostic pipeline:
    //         tempdir stage outside the project, nested node_modules prune,
    //         bundled-deps refusal, hardened apply, deterministic pack) ────
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
        // Failed patch (no lock writes — wiring is last, so the project is
        // byte-untouched) or a dry run (stops after the verify).
        return VendorOutcome::Done {
            result,
            entry: None,
            warnings,
        };
    };
    // `staged.name`/`staged.version` echo the validated coords (the wiring
    // below keeps using the borrowed `name`/`version`).
    debug_assert_eq!(
        (staged.name.as_str(), staged.version.as_str()),
        (name, version)
    );
    let rel_tgz = staged.rel_tgz;
    let packed = staged.packed;
    let staged_pkg_json = staged.staged_pkg_json;
    let dest = project_root.join(&rel_tgz);
    // Forward slashes by construction (uuid_dir_rel + leaf are built with
    // `/`), relative to the project dir — the spelling npm resolves
    // `file:` specs against.
    let resolved = format!("file:{rel_tgz}");

    // ── 8. Lock rewrite (in-place Value mutation: untouched keys stay
    //       byte-stable thanks to serde_json's preserve_order) ────────────
    let mut wiring: Vec<WiringRecord> = Vec::new();
    let mut changed = false;
    let mut recomputed_deps = false;
    {
        let Some(packages) = lock.get_mut("packages").and_then(Value::as_object_mut) else {
            return done_failure(
                purl,
                "lock `packages` object vanished mid-rewrite".to_string(),
            );
        };
        for m in &matches {
            let Some(live) = packages.get_mut(&m.key).and_then(Value::as_object_mut) else {
                continue;
            };
            // Idempotency: an instance already carrying our exact spec needs
            // no edit and no wiring record.
            if entry_in_sync(live, &resolved, &packed.integrity) {
                continue;
            }
            // Never record one of our own (stale) edits as the "original" —
            // revert must restore the pre-vendor registry fragment, not a
            // dangling `.socket/vendor/` pointer from an earlier uuid.
            let was_vendored = entry_points_into_vendor(live);
            live.insert("resolved".to_string(), Value::String(resolved.clone()));
            live.insert(
                "integrity".to_string(),
                Value::String(packed.integrity.clone()),
            );
            if let Some(pkg) = &staged_pkg_json {
                recompute_dep_fields(live, pkg);
                recomputed_deps = true;
            }
            wiring.push(WiringRecord {
                file: lock_name.clone(),
                kind: KIND_LOCK_ENTRY.to_string(),
                action: WiringAction::Rewritten,
                key: Some(m.key.clone()),
                original: if was_vendored {
                    None
                } else {
                    Some(m.original.clone())
                },
                new: Some(Value::Object(live.clone())),
            });
            changed = true;
        }
    }
    // lockfileVersion 2 keeps a legacy `dependencies` mirror (read by npm 6);
    // leaving the registry resolved/integrity there would let an old client
    // silently install unpatched bytes.
    if lock_version == Some(2) {
        if let Some(deps) = lock.get_mut("dependencies").and_then(Value::as_object_mut) {
            rewrite_legacy_tree(
                deps,
                "/dependencies",
                name,
                version,
                &resolved,
                &packed.integrity,
                &lock_name,
                &mut wiring,
                &mut changed,
            );
        }
    }
    if recomputed_deps {
        warnings.push(VendorWarning::new(
            "vendor_dep_manifest_rewritten",
            format!(
                "the patch rewrites {name}@{version}'s package.json; its lock entries' \
                 dependency/bin fields were recomputed from the patched manifest"
            ),
        ));
    }

    if !changed {
        // Every instance already points at this uuid with the packed
        // integrity: the project is in sync. Touch nothing (the tarball
        // rewrite above was byte-identical by determinism) and synthesize an
        // AlreadyPatched-style success, mirroring the go_redirect hot path.
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

    let indent = detect_indent(&String::from_utf8_lossy(&lock_bytes));
    let out = match serialize_lock(&lock, &indent) {
        Ok(out) => out,
        Err(e) => return done_failure(purl, format!("cannot serialize {lock_name}: {e}")),
    };
    if let Err(e) = atomic_write_bytes(&project_root.join(&lock_name), &out).await {
        return done_failure(purl, format!("cannot write {lock_name}: {e}"));
    }

    // ── 9. Marker + ledger entry ─────────────────────────────────────────
    // The marker is informational belt-and-braces (never a trust input), so
    // a write failure downgrades to a warning rather than failing a vendor
    // whose lock is already correctly wired.
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

/// Undo one vendored npm package: restore the recorded lock fragments and
/// remove the artifact dir.
pub async fn revert_npm(entry: &VendorEntry, project_root: &Path, dry_run: bool) -> RevertOutcome {
    // SECURITY: `entry.uuid` comes from the committed, tamper-able
    // state.json and names the directory tree we are about to DELETE.
    // Validate through the same fail-closed grammar vendor used before any
    // disk access — never delete by an unvalidated path.
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

    // The lockfile(s) the wiring named (normally exactly one). SECURITY:
    // restrict the write targets to the two known lockfile names — a
    // poisoned state.json must not be able to point this rewrite at an
    // arbitrary project file.
    let mut lock_files: Vec<&str> = Vec::new();
    for rec in &entry.wiring {
        if rec.file != PACKAGE_LOCK && rec.file != SHRINKWRAP {
            outcome.warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!("ignoring wiring record for unexpected file `{}`", rec.file),
            ));
            continue;
        }
        if !lock_files.contains(&rec.file.as_str()) {
            lock_files.push(&rec.file);
        }
    }

    for lock_name in lock_files {
        let lock_path = project_root.join(lock_name);
        let lock_bytes = match tokio::fs::read(&lock_path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // The lock is gone (user regenerated the project?); the
                // artifact removal below still proceeds.
                outcome.warnings.push(VendorWarning::new(
                    "vendor_lockfile_missing",
                    format!("{lock_name} is missing; lock fragments cannot be restored"),
                ));
                continue;
            }
            Err(e) => return RevertOutcome::failed(format!("cannot read {lock_name}: {e}")),
        };
        let mut lock: Value = match serde_json::from_slice(&lock_bytes) {
            Ok(v) => v,
            // Fail-closed: editing a lock we cannot parse risks destroying
            // it; the user must repair it before revert can restore.
            Err(e) => {
                return RevertOutcome::failed(format!(
                    "{lock_name} is not parseable JSON ({e}); fix it and re-run revert"
                ))
            }
        };

        let mut changed = false;
        // Reverse application order, like every backend's revert.
        for rec in entry.wiring.iter().rev().filter(|r| r.file == lock_name) {
            revert_one_record(
                &mut lock,
                rec,
                &entry.uuid,
                &mut changed,
                &mut outcome.warnings,
            );
        }

        if changed {
            let indent = detect_indent(&String::from_utf8_lossy(&lock_bytes));
            let out = match serialize_lock(&lock, &indent) {
                Ok(out) => out,
                Err(e) => {
                    return RevertOutcome::failed(format!("cannot serialize {lock_name}: {e}"))
                }
            };
            if let Err(e) = atomic_write_bytes(&lock_path, &out).await {
                return RevertOutcome::failed(format!("cannot write {lock_name}: {e}"));
            }
        }
    }

    // Remove the whole validated uuid dir (tgz + marker + any @scope level)
    // in one tree delete — pruning by leaf would leave empty dirs behind.
    if let Err(e) = remove_tree(&project_root.join(&uuid_dir_rel)).await {
        return RevertOutcome::failed(format!("cannot remove {uuid_dir_rel}: {e}"));
    }

    outcome
}

// ───────────────────────────── lock matching ─────────────────────────────

/// One rewritable `packages` instance found by the scan.
struct LockMatch {
    /// The verbatim `packages` key (`node_modules/a/node_modules/b`).
    key: String,
    /// Verbatim entry snapshot taken BEFORE any mutation — the revert
    /// `original`.
    original: Value,
}

/// What the `packages` scan found.
enum LockScan {
    Matches(Vec<LockMatch>),
    /// A matching key outside `node_modules/` — the caller refuses.
    WorkspaceMember {
        key: String,
    },
}

/// Scan `packages` for instances of `name@version`, pushing skip warnings
/// for the link / inBundle instances that cannot be rewritten.
fn scan_lock_matches(
    lock: &Value,
    name: &str,
    version: &str,
    warnings: &mut Vec<VendorWarning>,
) -> LockScan {
    let mut matches = Vec::new();
    let Some(packages) = lock.get("packages").and_then(Value::as_object) else {
        return LockScan::Matches(matches); // validated earlier; defensive
    };
    for (key, entry) in packages {
        // The root "" entry is the project itself, never a dependency.
        if key.is_empty() {
            continue;
        }
        let Some(obj) = entry.as_object() else {
            continue;
        };
        if entry_name(key, obj) != name {
            continue;
        }
        if obj.get("version").and_then(Value::as_str) != Some(version) {
            continue;
        }
        if !key.contains(NODE_MODULES_SEG) {
            return LockScan::WorkspaceMember { key: key.clone() };
        }
        if obj.get("link").and_then(Value::as_bool) == Some(true) {
            warnings.push(VendorWarning::new(
                "vendor_link_entry_skipped",
                format!("lock entry `{key}` is a link (npm workspaces/file: dir); skipped"),
            ));
            continue;
        }
        if obj.get("inBundle").and_then(Value::as_bool) == Some(true) {
            // LOUD: this copy ships inside its PARENT's tarball, which we do
            // not repack — it will still be the unpatched bytes after vendor.
            warnings.push(VendorWarning::new(
                "vendor_bundled_instance_skipped",
                format!(
                    "lock entry `{key}` is bundled inside its parent's tarball and CANNOT be \
                     rewritten — that copy stays UNPATCHED; vendor or update the bundling \
                     parent to cover it"
                ),
            ));
            continue;
        }
        matches.push(LockMatch {
            key: key.clone(),
            original: entry.clone(),
        });
    }
    LockScan::Matches(matches)
}

/// The package name a lock entry stands for: the explicit `name` field when
/// present (npm writes it for aliases — `npm i alias@npm:real`), else the
/// path after the LAST `node_modules/` (handles nesting AND scopes), else
/// the key's basename (workspace-member keys, for classification only).
fn entry_name<'a>(key: &'a str, obj: &'a serde_json::Map<String, Value>) -> &'a str {
    if let Some(n) = obj.get("name").and_then(Value::as_str) {
        return n;
    }
    if let Some(idx) = key.rfind(NODE_MODULES_SEG) {
        return &key[idx + NODE_MODULES_SEG.len()..];
    }
    key.rsplit('/').next().unwrap_or(key)
}

fn entry_in_sync(live: &serde_json::Map<String, Value>, resolved: &str, integrity: &str) -> bool {
    live.get("resolved").and_then(Value::as_str) == Some(resolved)
        && live.get("integrity").and_then(Value::as_str) == Some(integrity)
}

/// Does this entry's `resolved` already point into `.socket/vendor/npm/`
/// (ours — current or stale uuid)?
fn entry_points_into_vendor(live: &serde_json::Map<String, Value>) -> bool {
    live.get("resolved")
        .and_then(Value::as_str)
        .and_then(parse_vendor_path)
        .is_some_and(|p| p.eco == "npm")
}

/// Replace the lock entry's dependency-manifest mirror fields with the
/// patched package.json's (absent in the manifest ⇒ removed from the entry,
/// matching what npm would regenerate).
fn recompute_dep_fields(live: &mut serde_json::Map<String, Value>, staged_pkg: &Value) {
    for field in DEP_MANIFEST_FIELDS {
        match staged_pkg.get(field) {
            Some(v) => {
                live.insert(field.to_string(), v.clone());
            }
            None => {
                // shift_remove keeps the remaining keys' order stable
                // (preserve_order Maps swap by default).
                live.shift_remove(field);
            }
        }
    }
}

/// Walk the v2 legacy `dependencies` tree and rewrite every node matching
/// `name`+`version`. Nodes are addressed for revert by RFC 6901 JSON
/// Pointer (names may contain `/` — scoped packages — so a plain
/// slash-joined key would be ambiguous; `Value::pointer_mut` handles the
/// `~1` escaping natively).
#[allow(clippy::too_many_arguments)]
fn rewrite_legacy_tree(
    deps: &mut serde_json::Map<String, Value>,
    pointer_base: &str,
    name: &str,
    version: &str,
    resolved: &str,
    integrity: &str,
    lock_name: &str,
    wiring: &mut Vec<WiringRecord>,
    changed: &mut bool,
) {
    for (dep_name, node) in deps.iter_mut() {
        let Some(obj) = node.as_object_mut() else {
            continue;
        };
        let pointer = format!("{pointer_base}/{}", escape_json_pointer_token(dep_name));
        if dep_name == name
            && obj.get("version").and_then(Value::as_str) == Some(version)
            && !entry_in_sync(obj, resolved, integrity)
        {
            let was_vendored = entry_points_into_vendor(obj);
            let original = Value::Object(obj.clone());
            obj.insert("resolved".to_string(), Value::String(resolved.to_string()));
            obj.insert(
                "integrity".to_string(),
                Value::String(integrity.to_string()),
            );
            wiring.push(WiringRecord {
                file: lock_name.to_string(),
                kind: KIND_LOCK_LEGACY_ENTRY.to_string(),
                action: WiringAction::Rewritten,
                key: Some(pointer.clone()),
                original: if was_vendored { None } else { Some(original) },
                new: Some(Value::Object(obj.clone())),
            });
            *changed = true;
        }
        if let Some(sub) = obj.get_mut("dependencies").and_then(Value::as_object_mut) {
            rewrite_legacy_tree(
                sub,
                &format!("{pointer}/dependencies"),
                name,
                version,
                resolved,
                integrity,
                lock_name,
                wiring,
                changed,
            );
        }
    }
}

/// RFC 6901 token escaping (`~` → `~0`, `/` → `~1`).
fn escape_json_pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// Apply one wiring record in reverse: restore `original` iff the live
/// fragment is still ours (drift = third party re-resolved it; leave theirs
/// alone, with a warning).
fn revert_one_record(
    lock: &mut Value,
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
    let live = match rec.kind.as_str() {
        KIND_LOCK_ENTRY => lock.get_mut("packages").and_then(|p| p.get_mut(key)),
        KIND_LOCK_LEGACY_ENTRY => lock.pointer_mut(key),
        other => {
            warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!("unknown wiring kind `{other}` for `{key}`; left alone"),
            ));
            return;
        }
    };
    let Some(live) = live else {
        warnings.push(VendorWarning::new(
            "vendor_lock_entry_drifted",
            format!("lock entry `{key}` no longer exists; nothing to restore"),
        ));
        return;
    };

    // Ours iff resolved is exactly what we wrote, or still points into OUR
    // uuid dir (a re-serialized but unmoved entry).
    let live_resolved = live.get("resolved").and_then(Value::as_str);
    let new_resolved = rec
        .new
        .as_ref()
        .and_then(|n| n.get("resolved"))
        .and_then(Value::as_str);
    let ours = match live_resolved {
        Some(r) => {
            Some(r) == new_resolved
                || parse_vendor_path(r).is_some_and(|p| p.eco == "npm" && p.uuid == entry_uuid)
        }
        None => false,
    };
    if !ours {
        warnings.push(VendorWarning::new(
            "vendor_lock_entry_drifted",
            format!(
                "lock entry `{key}` was re-resolved since vendoring (resolved = {:?}); \
                 left alone",
                live_resolved
            ),
        ));
        return;
    }
    match &rec.original {
        Some(original) => {
            *live = original.clone();
            *changed = true;
        }
        None => {
            // The record rewrote one of our own earlier edits, so there is
            // no pre-vendor fragment to restore (by design — see vendor_npm
            // step 8). Surface it instead of guessing a registry URL.
            warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "lock entry `{key}` has no recorded pre-vendor original; left as-is \
                     (re-run `npm install` to re-resolve it from the registry)"
                ),
            ));
        }
    }
}

// ───────────────────────────── small helpers ─────────────────────────────
// (the flavor-agnostic coordinate/staging helpers live in `npm_common`)

async fn select_lockfile(project_root: &Path) -> std::io::Result<Option<(String, Vec<u8>)>> {
    for lock_name in [SHRINKWRAP, PACKAGE_LOCK] {
        match tokio::fs::read(project_root.join(lock_name)).await {
            Ok(bytes) => return Ok(Some((lock_name.to_string(), bytes))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

/// The lock's indent unit: the leading whitespace of the first indented
/// line (npm emits 2 spaces; respect whatever formatter the project uses
/// so untouched lines stay byte-identical in diffs). Defaults to 2 spaces.
fn detect_indent(text: &str) -> String {
    for line in text.lines() {
        let trimmed = line.trim_start_matches([' ', '\t']);
        if !trimmed.is_empty() && trimmed.len() < line.len() {
            return line[..line.len() - trimmed.len()].to_string();
        }
    }
    "  ".to_string()
}

/// Pretty-print with the detected indent + trailing newline — npm's own
/// output shape, so `npm install` after vendoring produces no format-only
/// churn.
fn serialize_lock(lock: &Value, indent: &str) -> std::io::Result<Vec<u8>> {
    use serde::Serialize;
    let mut out = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(indent.as_bytes());
    let mut ser = serde_json::Serializer::with_formatter(&mut out, formatter);
    lock.serialize(&mut ser).map_err(std::io::Error::other)?;
    out.push(b'\n');
    Ok(out)
}

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
    use serde_json::json;
    use sha2::{Digest, Sha512};
    use std::path::PathBuf;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const ORIG_INDEX: &[u8] = b"module.exports = () => 'orig';\n";
    const PATCHED_INDEX: &[u8] = b"module.exports = () => 'patched';\n";
    const REG_RESOLVED: &str = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";

    struct Fixture {
        tmp: tempfile::TempDir,
        record: PatchRecord,
        /// Bytes of the lockfile exactly as written (the byte-stability
        /// oracle for dry-run / revert round-trips).
        lock_bytes: Vec<u8>,
        name: String,
        version: String,
    }

    impl Fixture {
        fn root(&self) -> &Path {
            self.tmp.path()
        }

        fn installed(&self) -> PathBuf {
            self.root().join("node_modules").join(&self.name)
        }

        fn purl(&self) -> String {
            format!("pkg:npm/{}@{}", self.name, self.version)
        }

        fn expected_rel_tgz(&self) -> String {
            format!(
                ".socket/vendor/npm/{UUID}/{}",
                tgz_rel_leaf(&self.name, &self.version)
            )
        }

        fn lock_path(&self) -> PathBuf {
            self.root().join(PACKAGE_LOCK)
        }

        async fn read_lock(&self) -> Value {
            serde_json::from_slice(&tokio::fs::read(self.lock_path()).await.unwrap()).unwrap()
        }

        async fn vendor(&self, dry_run: bool) -> VendorOutcome {
            let blobs = self.root().join(".socket/blobs");
            let sources = PatchSources::blobs_only(&blobs);
            vendor_npm(
                &self.purl(),
                &self.installed(),
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

    fn installed_pkg_json(name: &str, version: &str) -> Vec<u8> {
        format!("{{\"name\":\"{name}\",\"version\":\"{version}\"}}\n").into_bytes()
    }

    /// Default v3 lock: root entry + a direct left-pad + a NESTED
    /// node_modules/foo/node_modules/left-pad instance.
    fn default_lock() -> Value {
        json!({
            "name": "fixture",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": {
                    "name": "fixture",
                    "version": "1.0.0",
                    "dependencies": { "left-pad": "^1.3.0" }
                },
                "node_modules/foo": {
                    "version": "2.0.0",
                    "resolved": "https://registry.npmjs.org/foo/-/foo-2.0.0.tgz",
                    "integrity": "sha512-foo=="
                },
                "node_modules/foo/node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": REG_RESOLVED,
                    "integrity": "sha512-orig=="
                },
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": REG_RESOLVED,
                    "integrity": "sha512-orig==",
                    "license": "WTFPL"
                }
            }
        })
    }

    async fn fixture() -> Fixture {
        fixture_with("left-pad", "1.3.0", default_lock()).await
    }

    /// Build a project tempdir: installed package, patched blob, lockfile,
    /// and the PatchRecord. The lock is written in production format (the
    /// same serializer + 2-space indent) so byte-identity assertions are
    /// meaningful.
    async fn fixture_with(name: &str, version: &str, lock: Value) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        let installed = root.join("node_modules").join(name);
        tokio::fs::create_dir_all(&installed).await.unwrap();
        tokio::fs::write(
            installed.join("package.json"),
            installed_pkg_json(name, version),
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

        let lock_bytes = serialize_lock(&lock, "  ").unwrap();
        tokio::fs::write(root.join(PACKAGE_LOCK), &lock_bytes)
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
            lock_bytes,
            name: name.to_string(),
            version: version.to_string(),
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

    fn sri_sha512(bytes: &[u8]) -> String {
        format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
        )
    }

    #[tokio::test]
    async fn happy_path_rewrites_every_instance_and_records_wiring() {
        let fx = fixture().await;
        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(warnings.is_empty(), "{warnings:?}");
        let entry = entry.expect("success must carry a ledger entry");

        // Tarball on disk; ledger artifact facts describe it.
        let rel_tgz = fx.expected_rel_tgz();
        let tgz = tokio::fs::read(fx.root().join(&rel_tgz)).await.unwrap();
        assert_eq!(entry.artifact.path, rel_tgz);
        assert_eq!(entry.artifact.size, Some(tgz.len() as u64));
        assert_eq!(
            entry.artifact.sha256,
            hex::encode(sha2::Sha256::digest(&tgz))
        );
        let expected_integrity = sri_sha512(&tgz);

        // BOTH instances (direct + nested) rewritten; everything else intact.
        let lock = fx.read_lock().await;
        let expected_resolved = format!("file:{rel_tgz}");
        for key in [
            "node_modules/left-pad",
            "node_modules/foo/node_modules/left-pad",
        ] {
            let e = &lock["packages"][key];
            assert_eq!(e["resolved"], json!(expected_resolved), "{key}");
            assert_eq!(
                e["integrity"],
                json!(expected_integrity),
                "{key}: integrity MUST be the recomputed tarball hash"
            );
            assert_eq!(e["version"], json!("1.3.0"), "{key}: version untouched");
        }
        assert_eq!(
            lock["packages"]["node_modules/left-pad"]["license"],
            json!("WTFPL")
        );
        assert_eq!(
            lock["packages"]["node_modules/foo"],
            default_lock()["packages"]["node_modules/foo"],
            "unrelated entry untouched"
        );

        // Wiring: one record per instance, verbatim originals.
        assert_eq!(entry.wiring.len(), 2);
        for rec in &entry.wiring {
            assert_eq!(rec.file, PACKAGE_LOCK);
            assert_eq!(rec.kind, KIND_LOCK_ENTRY);
            assert_eq!(rec.action, WiringAction::Rewritten);
            let key = rec.key.as_deref().unwrap();
            assert_eq!(
                rec.original.as_ref().unwrap(),
                &default_lock()["packages"][key],
                "original must be the verbatim pre-vendor entry for {key}"
            );
            assert_eq!(
                rec.new.as_ref().unwrap()["resolved"],
                json!(expected_resolved)
            );
        }

        // Marker sits next to the artifact.
        let marker = tokio::fs::read_to_string(fx.root().join(format!(
            ".socket/vendor/npm/{UUID}/socket-patch.vendor.json"
        )))
        .await
        .unwrap();
        assert!(marker.contains(UUID));
        assert!(marker.contains("pkg:npm/left-pad@1.3.0"));

        // The tarball contains the PATCHED bytes under package/.
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(tgz.as_slice()));
        let mut found = false;
        for e in archive.entries().unwrap() {
            let mut e = e.unwrap();
            if e.path().unwrap().to_string_lossy() == "package/index.js" {
                let mut data = Vec::new();
                std::io::Read::read_to_end(&mut e, &mut data).unwrap();
                assert_eq!(data, PATCHED_INDEX);
                found = true;
            }
        }
        assert!(found, "package/index.js missing from the tarball");
    }

    #[tokio::test]
    async fn rerun_is_in_sync_and_byte_stable() {
        let fx = fixture().await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        assert!(entry.is_some());
        let lock_after_first = tokio::fs::read(fx.lock_path()).await.unwrap();
        let tgz_path = fx.root().join(fx.expected_rel_tgz());
        let tgz_first = tokio::fs::read(&tgz_path).await.unwrap();

        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success);
        assert!(
            entry.is_none(),
            "in-sync re-run must not produce a new ledger entry"
        );
        assert!(
            result
                .files_verified
                .iter()
                .all(|v| v.status == VerifyStatus::AlreadyPatched),
            "in-sync re-run reports AlreadyPatched: {:?}",
            result.files_verified
        );
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            lock_after_first,
            "lock must be byte-stable across re-runs"
        );
        assert_eq!(
            tokio::fs::read(&tgz_path).await.unwrap(),
            tgz_first,
            "tarball must be byte-identical across re-runs"
        );
    }

    #[tokio::test]
    async fn scoped_package_uses_scope_subdirectory() {
        let lock = json!({
            "name": "fixture",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "fixture", "version": "1.0.0" },
                "node_modules/@scope/pkg": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz",
                    "integrity": "sha512-orig=="
                }
            }
        });
        let fx = fixture_with("@scope/pkg", "1.0.0", lock).await;
        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();

        let rel = format!(".socket/vendor/npm/{UUID}/@scope/pkg-1.0.0.tgz");
        assert_eq!(entry.artifact.path, rel);
        assert!(fx.root().join(&rel).exists(), "tarball at the scoped path");
        let lock = fx.read_lock().await;
        assert_eq!(
            lock["packages"]["node_modules/@scope/pkg"]["resolved"],
            json!(format!("file:{rel}"))
        );
    }

    #[tokio::test]
    async fn alias_entry_is_matched_by_name_field() {
        // `npm i aliased@npm:left-pad@1.3.0` → key node_modules/aliased,
        // entry carries the real name.
        let mut lock = default_lock();
        lock["packages"]["node_modules/aliased"] = json!({
            "name": "left-pad",
            "version": "1.3.0",
            "resolved": REG_RESOLVED,
            "integrity": "sha512-orig=="
        });
        let fx = fixture_with("left-pad", "1.3.0", lock).await;
        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success);
        let entry = entry.unwrap();
        assert_eq!(
            entry.wiring.len(),
            3,
            "direct + nested + alias all rewritten"
        );

        let lock = fx.read_lock().await;
        let alias = &lock["packages"]["node_modules/aliased"];
        assert_eq!(
            alias["resolved"],
            json!(format!("file:{}", fx.expected_rel_tgz()))
        );
        assert_eq!(
            alias["name"],
            json!("left-pad"),
            "alias name field preserved"
        );
    }

    #[tokio::test]
    async fn link_and_in_bundle_instances_are_skipped_with_warnings() {
        let mut lock = default_lock();
        lock["packages"]["node_modules/linked-pad"] = json!({
            "name": "left-pad",
            "version": "1.3.0",
            "resolved": "projects/left-pad",
            "link": true
        });
        lock["packages"]["node_modules/bundler/node_modules/left-pad"] = json!({
            "version": "1.3.0",
            "resolved": REG_RESOLVED,
            "integrity": "sha512-orig==",
            "inBundle": true
        });
        let fx = fixture_with("left-pad", "1.3.0", lock.clone()).await;
        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success);
        assert_eq!(
            entry.unwrap().wiring.len(),
            2,
            "only the rewritable instances"
        );

        let codes: Vec<&str> = warnings.iter().map(|w| w.code).collect();
        assert!(codes.contains(&"vendor_link_entry_skipped"), "{codes:?}");
        assert!(
            codes.contains(&"vendor_bundled_instance_skipped"),
            "{codes:?}"
        );
        let bundled = warnings
            .iter()
            .find(|w| w.code == "vendor_bundled_instance_skipped")
            .unwrap();
        assert!(
            bundled.detail.contains("UNPATCHED"),
            "loud warning: {}",
            bundled.detail
        );

        // Skipped entries are byte-untouched.
        let live = fx.read_lock().await;
        assert_eq!(
            live["packages"]["node_modules/linked-pad"],
            lock["packages"]["node_modules/linked-pad"]
        );
        assert_eq!(
            live["packages"]["node_modules/bundler/node_modules/left-pad"],
            lock["packages"]["node_modules/bundler/node_modules/left-pad"]
        );
    }

    #[tokio::test]
    async fn workspace_member_is_refused() {
        let lock = json!({
            "name": "fixture",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "fixture", "version": "1.0.0" },
                "packages/left-pad": { "name": "left-pad", "version": "1.3.0" }
            }
        });
        let fx = fixture_with("left-pad", "1.3.0", lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_workspace_member");
        assert!(detail.contains("packages/left-pad"));
        assert!(
            !fx.root().join(".socket/vendor").exists(),
            "refusal writes nothing"
        );
    }

    #[tokio::test]
    async fn bundled_deps_package_is_refused_before_lock_writes() {
        let fx = fixture().await;
        tokio::fs::write(
            fx.installed().join("package.json"),
            br#"{"name":"left-pad","version":"1.3.0","bundleDependencies":["dep"]}"#,
        )
        .await
        .unwrap();
        expect_refused(fx.vendor(false).await, "vendor_bundled_deps_unsupported");
        assert!(!fx.root().join(".socket/vendor").exists());
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes,
            "lock untouched by the refusal"
        );
    }

    #[tokio::test]
    async fn lockfile_v1_is_refused() {
        let lock = json!({
            "name": "fixture",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "dependencies": {
                "left-pad": { "version": "1.3.0", "resolved": REG_RESOLVED, "integrity": "sha512-orig==" }
            }
        });
        let fx = fixture_with("left-pad", "1.3.0", lock).await;
        expect_refused(
            fx.vendor(false).await,
            "vendor_lockfile_version_unsupported",
        );
    }

    #[tokio::test]
    async fn missing_lockfile_is_refused() {
        let fx = fixture().await;
        tokio::fs::remove_file(fx.lock_path()).await.unwrap();
        let detail = expect_refused(fx.vendor(false).await, "vendor_lockfile_missing");
        assert!(
            detail.contains("npm install"),
            "actionable detail: {detail}"
        );
    }

    #[tokio::test]
    async fn no_matching_entry_is_refused() {
        let mut lock = default_lock();
        // Lock knows only a DIFFERENT version of left-pad.
        lock["packages"]["node_modules/left-pad"]["version"] = json!("1.2.0");
        lock["packages"]["node_modules/foo/node_modules/left-pad"]["version"] = json!("1.2.0");
        let fx = fixture_with("left-pad", "1.3.0", lock).await;
        let detail = expect_refused(fx.vendor(false).await, "vendor_lock_entry_not_found");
        assert!(
            detail.contains("npm install"),
            "actionable detail: {detail}"
        );
    }

    #[tokio::test]
    async fn shrinkwrap_wins_over_package_lock() {
        let fx = fixture().await;
        // Same content as the package-lock, but under the shrinkwrap name.
        tokio::fs::write(fx.root().join(SHRINKWRAP), &fx.lock_bytes)
            .await
            .unwrap();

        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success);
        let entry = entry.unwrap();
        assert!(entry.wiring.iter().all(|r| r.file == SHRINKWRAP));

        // package-lock.json byte-untouched; shrinkwrap rewritten.
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes
        );
        let shrink: Value =
            serde_json::from_slice(&tokio::fs::read(fx.root().join(SHRINKWRAP)).await.unwrap())
                .unwrap();
        assert_eq!(
            shrink["packages"]["node_modules/left-pad"]["resolved"],
            json!(format!("file:{}", fx.expected_rel_tgz()))
        );
    }

    #[tokio::test]
    async fn v2_lock_rewrites_the_legacy_dependencies_mirror_and_reverts() {
        let lock = json!({
            "name": "fixture",
            "version": "1.0.0",
            "lockfileVersion": 2,
            "requires": true,
            "packages": {
                "": { "name": "fixture", "version": "1.0.0" },
                "node_modules/foo": {
                    "version": "2.0.0",
                    "resolved": "https://registry.npmjs.org/foo/-/foo-2.0.0.tgz",
                    "integrity": "sha512-foo=="
                },
                "node_modules/foo/node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": REG_RESOLVED,
                    "integrity": "sha512-orig=="
                },
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": REG_RESOLVED,
                    "integrity": "sha512-orig=="
                }
            },
            "dependencies": {
                "foo": {
                    "version": "2.0.0",
                    "resolved": "https://registry.npmjs.org/foo/-/foo-2.0.0.tgz",
                    "integrity": "sha512-foo==",
                    "requires": { "left-pad": "^1.3.0" },
                    "dependencies": {
                        "left-pad": {
                            "version": "1.3.0",
                            "resolved": REG_RESOLVED,
                            "integrity": "sha512-orig=="
                        }
                    }
                },
                "left-pad": {
                    "version": "1.3.0",
                    "resolved": REG_RESOLVED,
                    "integrity": "sha512-orig=="
                }
            }
        });
        let fx = fixture_with("left-pad", "1.3.0", lock).await;
        let (result, entry, _) = expect_done(fx.vendor(false).await);
        assert!(result.success);
        let entry = entry.unwrap();

        let legacy: Vec<&WiringRecord> = entry
            .wiring
            .iter()
            .filter(|r| r.kind == KIND_LOCK_LEGACY_ENTRY)
            .collect();
        assert_eq!(
            legacy.len(),
            2,
            "top-level + nested legacy nodes: {:?}",
            entry.wiring
        );
        let keys: Vec<&str> = legacy.iter().map(|r| r.key.as_deref().unwrap()).collect();
        assert!(keys.contains(&"/dependencies/left-pad"), "{keys:?}");
        assert!(
            keys.contains(&"/dependencies/foo/dependencies/left-pad"),
            "{keys:?}"
        );

        let resolved = json!(format!("file:{}", fx.expected_rel_tgz()));
        let live = fx.read_lock().await;
        assert_eq!(live["dependencies"]["left-pad"]["resolved"], resolved);
        assert_eq!(
            live["dependencies"]["foo"]["dependencies"]["left-pad"]["resolved"],
            resolved
        );
        assert_eq!(
            live["dependencies"]["foo"]["resolved"],
            json!("https://registry.npmjs.org/foo/-/foo-2.0.0.tgz"),
            "non-matching legacy node untouched"
        );

        // Pointer-addressed revert restores the v2 lock byte-for-byte.
        let outcome = revert_npm(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes
        );
    }

    #[tokio::test]
    async fn dry_run_writes_nothing() {
        let fx = fixture().await;
        let (result, entry, _) = expect_done(fx.vendor(true).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_none(), "dry run must not produce a ledger entry");
        assert!(result.files_patched.is_empty(), "dry run patches nothing");

        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes,
            "lock byte-untouched"
        );
        assert!(
            !fx.root().join(".socket/vendor").exists(),
            ".socket/vendor absent"
        );
        // The installed package is never patched in place by vendor.
        assert_eq!(
            tokio::fs::read(fx.installed().join("index.js"))
                .await
                .unwrap(),
            ORIG_INDEX
        );
    }

    #[tokio::test]
    async fn patched_package_json_recomputes_lock_dep_fields() {
        let mut fx = fixture().await;
        // Give one lock instance dep-mirror fields the patch obsoletes.
        let mut lock = default_lock();
        lock["packages"]["node_modules/left-pad"]["peerDependencies"] = json!({ "gone": "^1.0.0" });
        let lock_bytes = serialize_lock(&lock, "  ").unwrap();
        tokio::fs::write(fx.lock_path(), &lock_bytes).await.unwrap();
        fx.lock_bytes = lock_bytes;

        // The patch rewrites package.json: adds a dependency + a bin.
        let before = installed_pkg_json("left-pad", "1.3.0");
        let after: &[u8] =
            br#"{"name":"left-pad","version":"1.3.0","dependencies":{"wow":"^1.0.0"},"bin":{"lp":"cli.js"}}"#;
        let after_hash = compute_git_sha256_from_bytes(after);
        tokio::fs::write(fx.root().join(".socket/blobs").join(&after_hash), after)
            .await
            .unwrap();
        fx.record.files.insert(
            "package/package.json".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(&before),
                after_hash,
            },
        );

        let (result, entry, warnings) = expect_done(fx.vendor(false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_dep_manifest_rewritten"),
            "{warnings:?}"
        );

        let live = fx.read_lock().await;
        let e = &live["packages"]["node_modules/left-pad"];
        assert_eq!(e["dependencies"], json!({ "wow": "^1.0.0" }));
        assert_eq!(e["bin"], json!({ "lp": "cli.js" }));
        assert!(
            e.get("peerDependencies").is_none(),
            "field absent from the patched manifest must be removed"
        );
        assert_eq!(e["license"], json!("WTFPL"), "non-dep fields untouched");
    }

    #[tokio::test]
    async fn revert_round_trips_the_lock_and_removes_the_artifact() {
        let fx = fixture().await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();
        let tgz_path = fx.root().join(fx.expected_rel_tgz());
        assert!(tgz_path.exists());

        // Dry-run revert: success, nothing removed/restored.
        let outcome = revert_npm(&entry, fx.root(), true).await;
        assert!(outcome.success);
        assert!(
            tgz_path.exists(),
            "dry-run revert must not delete the artifact"
        );
        assert_ne!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes,
            "dry-run revert must not touch the lock"
        );

        let outcome = revert_npm(&entry, fx.root(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes,
            "lock restored byte-for-byte"
        );
        assert!(!tgz_path.exists(), "tarball removed");
        assert!(
            !fx.root()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "uuid dir pruned"
        );
    }

    #[tokio::test]
    async fn revert_leaves_drifted_entries_alone_with_warning() {
        let fx = fixture().await;
        let (_, entry, _) = expect_done(fx.vendor(false).await);
        let entry = entry.unwrap();

        // The user re-resolved the DIRECT instance behind our back.
        let mut live = fx.read_lock().await;
        live["packages"]["node_modules/left-pad"]["resolved"] =
            json!("https://example.com/their-fork.tgz");
        tokio::fs::write(fx.lock_path(), serialize_lock(&live, "  ").unwrap())
            .await
            .unwrap();

        let outcome = revert_npm(&entry, fx.root(), false).await;
        assert!(outcome.success);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "{:?}",
            outcome.warnings
        );

        let after = fx.read_lock().await;
        assert_eq!(
            after["packages"]["node_modules/left-pad"]["resolved"],
            json!("https://example.com/their-fork.tgz"),
            "drifted entry left alone"
        );
        assert_eq!(
            after["packages"]["node_modules/foo/node_modules/left-pad"],
            default_lock()["packages"]["node_modules/foo/node_modules/left-pad"],
            "non-drifted instance restored"
        );
        assert!(!fx
            .root()
            .join(format!(".socket/vendor/npm/{UUID}"))
            .exists());
    }

    #[tokio::test]
    async fn traversal_uuid_is_refused_before_any_write() {
        let mut fx = fixture().await;
        fx.record.uuid = "../../x".to_string();
        expect_refused(fx.vendor(false).await, "unsafe_coordinates");
        assert!(!fx.root().join(".socket/vendor").exists());
        assert_eq!(
            tokio::fs::read(fx.lock_path()).await.unwrap(),
            fx.lock_bytes
        );
        // And revert refuses to delete through a tampered uuid too.
        let entry = VendorEntry {
            ecosystem: "npm".into(),
            base_purl: fx.purl(),
            uuid: "../../x".into(),
            artifact: VendorArtifact {
                path: "whatever".into(),
                sha256: String::new(),
                size: None,
                platform_locked: None,
            },
            wiring: Vec::new(),
            lock: None,
            took_over_go_patches: false,
            flavor: None,
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
        };
        let outcome = revert_npm(&entry, fx.root(), false).await;
        assert!(!outcome.success, "tampered uuid must fail closed");
    }

    #[test]
    fn purl_and_name_helpers() {
        assert_eq!(
            parse_npm_purl("pkg:npm/left-pad@1.3.0"),
            Some(("left-pad", "1.3.0"))
        );
        assert_eq!(
            parse_npm_purl("pkg:npm/@scope/pkg@1.0.0?foo=bar"),
            Some(("@scope/pkg", "1.0.0"))
        );
        assert_eq!(parse_npm_purl("pkg:npm/@scope/pkg"), None, "no version");
        assert_eq!(
            parse_npm_purl("pkg:pypi/six@1.16.0"),
            None,
            "wrong ecosystem"
        );

        assert!(is_safe_npm_name("left-pad"));
        assert!(is_safe_npm_name("@scope/pkg"));
        assert!(!is_safe_npm_name("../escape"));
        assert!(!is_safe_npm_name("a/b"), "slash without a scope");
        assert!(!is_safe_npm_name("@scope/a/b"), "extra path level");
        assert!(!is_safe_npm_name("@scope"), "scope marker without a name");

        assert_eq!(tgz_rel_leaf("left-pad", "1.3.0"), "left-pad-1.3.0.tgz");
        assert_eq!(tgz_rel_leaf("@scope/pkg", "1.0.0"), "@scope/pkg-1.0.0.tgz");
    }

    #[test]
    fn indent_detection_and_pointer_escaping() {
        assert_eq!(detect_indent("{\n  \"a\": 1\n}\n"), "  ");
        assert_eq!(detect_indent("{\n\t\"a\": 1\n}\n"), "\t");
        assert_eq!(detect_indent("{\n    \"a\": 1\n}\n"), "    ");
        assert_eq!(detect_indent("{}"), "  ", "default for flat files");

        assert_eq!(escape_json_pointer_token("@scope/name"), "@scope~1name");
        assert_eq!(escape_json_pointer_token("a~b"), "a~0b");
    }
}
