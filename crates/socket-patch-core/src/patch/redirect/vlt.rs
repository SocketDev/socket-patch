//! vlt `vlt-lock.json` hosted rewriter, the byte-for-byte twin of the TS
//! `registry-rewrite/vlt.ts`.
//!
//! A default-registry node keeps its DepID and has only slot [2] (the
//! patched sha512) and slot [3] (the hosted URL) spliced into its one-line
//! tuple; nothing else in the lock changes. The ledger records entry text
//! (`"<DepID>": <tuple>`, no indent, comma or `\r`), because vlt moves
//! commas and re-lays flags and trailing slots on later saves, so the
//! revert ([`revert_vlt_slots`]) works slot by slot.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::{full_name, DepOverride, FileEdit, RewriteResult, RewriteWarning};
use crate::constants::npm_family::{
    BUN_LOCK, BUN_LOCKB, NPM_LOCKS, PNPM_LOCK, VLT_CONFIG, VLT_HIDDEN_LOCK_REL, VLT_LOCK,
};
use crate::vendor::vlt_lock_text::{
    entry_text, is_default_registry, nodes_block, parse_node_entry_text, parse_node_line,
    parse_vendored_path, render_entry_line, render_tuple_with_slots, sniff_lock, split_dep_id,
    split_lines, DepIdKind, LockSniff, NodeEntry, ParsedLock, SectionSpan,
};

/// The ledger kind of a hosted vlt node splice.
pub const KIND: &str = "redirect_vlt_lock_node";

/// Every other npm-family lock whose presence makes `vlt-lock.json`
/// ambiguous as the install driver.
const SIBLING_LOCKS: [&str; 6] = [
    NPM_LOCKS[1],
    NPM_LOCKS[0],
    "yarn.lock",
    PNPM_LOCK,
    BUN_LOCK,
    BUN_LOCKB,
];

/// Does vlt drive hosted confirmation and the artifact preflight?
/// `vlt-lock.json` must be present, and either vlt's install state (the
/// `node_modules/.vlt-lock.json` sentinel) is too, or no other npm-family
/// lock is. Otherwise both locks are rewritten and neither decides alone.
pub fn vlt_drives(files: &BTreeMap<String, String>) -> bool {
    files.contains_key(VLT_LOCK)
        && (files.contains_key(VLT_HIDDEN_LOCK_REL)
            || !SIBLING_LOCKS.iter().any(|lock| files.contains_key(*lock)))
}

fn lock_unsupported(detail: &str) -> RewriteWarning {
    RewriteWarning {
        code: "redirect_vlt_lock_unsupported".into(),
        detail: format!(
            "vlt-lock.json {detail}; re-save it with a current vlt (`vlt install`) or update \
             socket-patch"
        ),
    }
}

/// A lock that passed the lock-level parse, with its nodes section located.
struct HostedLock {
    parsed: ParsedLock,
    nodes: Option<SectionSpan>,
}

fn parse_hosted_lock(text: &str) -> Result<HostedLock, RewriteWarning> {
    let parsed = match sniff_lock(text) {
        LockSniff::Readable(parsed) => parsed,
        LockSniff::Bom => {
            return Err(lock_unsupported(
                "starts with a UTF-8 BOM, which vlt cannot read",
            ))
        }
        LockSniff::NotJsonObject => return Err(lock_unsupported("is not a JSON object")),
        LockSniff::UnsupportedVersion(raw) => {
            return Err(lock_unsupported(&format!("has lockfileVersion {raw}")))
        }
    };
    let lines = split_lines(text);
    let nodes = nodes_block(&lines);
    let one_node_per_line = nodes.is_some_and(|span| {
        matches!(span, SectionSpan::Inline { .. })
            || span
                .entry_lines()
                .any(|i| parse_node_line(lines[i]).is_some())
    });
    if !one_node_per_line && parsed.nodes().is_some_and(|n| !n.is_empty()) {
        return Err(lock_unsupported(
            "nodes section is not in vlt's canonical layout",
        ));
    }
    Ok(HostedLock { parsed, nodes })
}

/// The lock-level refusal alone, run before any vendored vlt entry is
/// reverted for a hosted takeover. An absent lock passes.
pub fn preflight_vlt_hosted(files: &BTreeMap<String, String>) -> Result<(), RewriteWarning> {
    match files.get(VLT_LOCK) {
        Some(text) => parse_hosted_lock(text).map(|_| ()),
        None => Ok(()),
    }
}

/// Is `id` a registry node of `name@version`, and is its segment the
/// default registry? `None` for any other node.
fn registry_instance(
    id: &str,
    name: &str,
    version: &str,
    options: Option<&Map<String, Value>>,
) -> Option<bool> {
    let dep_id = split_dep_id(id)?;
    (dep_id.registry_identity()? == (name, version))
        .then(|| is_default_registry(&dep_id.first, options))
}

fn is_old_lockfile_ignored(lock: &HostedLock, files: &BTreeMap<String, String>) -> bool {
    if lock.parsed.version == Some(1) {
        return false;
    }
    let options = lock.parsed.options();
    let has_legacy_default = lock.parsed.nodes().is_some_and(|nodes| {
        nodes.keys().any(|id| {
            split_dep_id(id).is_some_and(|dep_id| {
                dep_id.kind == DepIdKind::Registry
                    && dep_id.first != "npm"
                    && is_default_registry(&dep_id.first, options)
            })
        })
    });
    let declares_modifiers = files.get(VLT_CONFIG).is_some_and(|text| {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        serde_json::from_str::<Value>(text)
            .ok()
            .and_then(|v| v.as_object().map(|o| o.contains_key("modifiers")))
            .unwrap_or(false)
    });
    has_legacy_default && !declares_modifiers
}

fn is_scalar_registry_ignored(lock: &HostedLock) -> bool {
    let options = lock.parsed.options();
    let scalar = options
        .and_then(|o| o.get("registry"))
        .is_some_and(Value::is_string);
    let registries_npm = options
        .and_then(|o| o.get("registries"))
        .and_then(|r| r.get("npm"))
        .is_some_and(Value::is_string);
    scalar && (lock.parsed.version != Some(1) || !registries_npm)
}

fn lock_level_warnings(lock: &HostedLock, files: &BTreeMap<String, String>) -> Vec<RewriteWarning> {
    let mut warnings = Vec::new();
    if lock.parsed.version.is_none() {
        warnings.push(RewriteWarning {
            code: "redirect_vlt_lockfile_version_missing".into(),
            detail: "vlt-lock.json has no lockfileVersion; vlt ≥ 1.0.0-rc.15 silently \
                     re-resolves it on `vlt install` (and `vlt ci` fails); re-lock with a \
                     current vlt"
                .into(),
        });
    }
    if is_old_lockfile_ignored(lock, files) {
        warnings.push(RewriteWarning {
            code: "redirect_vlt_old_lockfile_ignored".into(),
            detail: "vlt 0.0.0-16 … 0.0.0-24 ignore vlt-lock.json unless vlt.json declares \
                     \"modifiers\": {}; upgrade vlt or add \"modifiers\": {} to vlt.json"
                .into(),
        });
    }
    if is_scalar_registry_ignored(lock) {
        warnings.push(RewriteWarning {
            code: "redirect_vlt_scalar_registry_ignored".into(),
            detail: "vlt 1.0.0-rc.7 … rc.29 ignore vlt-lock.json when a scalar `registry` is \
                     configured; upgrade vlt to ≥ 1.0.0-rc.30"
                .into(),
        });
    }
    if !vlt_drives(files) {
        let others: Vec<&str> = SIBLING_LOCKS
            .iter()
            .copied()
            .filter(|lock| files.contains_key(*lock))
            .collect();
        warnings.push(RewriteWarning {
            code: "redirect_vlt_sibling_lockfiles".into(),
            detail: format!(
                "vlt-lock.json and {} are both present; socket-patch rewrote both — delete the \
                 lock your installs do not use",
                others.join(", ")
            ),
        });
    }
    warnings
}

fn npm_purl(name: &str, version: &str) -> String {
    format!("pkg:npm/{}@{version}", name.replacen('@', "%40", 1))
}

/// A `file` node of socket-patch's vendored vlt shape for `name@version`.
fn has_vendored_node(nodes: &Map<String, Value>, name: &str, version: &str) -> bool {
    nodes.iter().any(|(id, tuple)| {
        let slot1 = tuple.get(1).and_then(Value::as_str);
        split_dep_id(id).is_some_and(|dep_id| {
            dep_id.kind == DepIdKind::File
                && slot1 == Some(name)
                && parse_vendored_path(&dep_id.first, name).is_some_and(|p| p.version == version)
        })
    })
}

/// The ledger key of an instance: `<name>@<version>`, plus `~` and the raw
/// extra segment for a peer or modifier variant, in either era.
fn ledger_key(name: &str, version: &str, extra: Option<&str>) -> String {
    match extra {
        Some(extra) => format!("{name}@{version}~{extra}"),
        None => format!("{name}@{version}"),
    }
}

/// Does a ledger edit of [`KIND`] belong to `name@version`? Claims are by
/// key, with a `~` boundary before a variant's extra segment.
pub(crate) fn claims_key(key: &str, name: &str, version: &str) -> bool {
    let base = format!("{name}@{version}");
    key.strip_prefix(base.as_str())
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('~'))
}

/// The one nodes-section line index keyed `id` that parses under the node
/// grammar with slot [1] naming `name`; `None` when there are zero or
/// several lines with that key, or the one line is outside the grammar.
fn instance_line(
    lines: &[String],
    span: Option<SectionSpan>,
    id: &str,
    name: &str,
) -> Option<usize> {
    let span = span?;
    let prefix = format!("    \"{id}\": ");
    let mut found = span
        .entry_lines()
        .filter(|&i| lines[i].starts_with(prefix.as_str()));
    let idx = found.next()?;
    if found.next().is_some() {
        return None;
    }
    let line = parse_node_line(&lines[idx])?;
    (line.entry.key == id && line.entry.name().as_deref() == Some(name)).then_some(idx)
}

/// The residual gate: re-parsed, every instance carries the patched slots.
fn every_instance_pinned(text: &str, ids: &[&str], sha512: &str, url: &str) -> Option<()> {
    let json: Value = serde_json::from_str(text).ok()?;
    let nodes = json.get("nodes")?.as_object()?;
    ids.iter()
        .all(|id| {
            let tuple = nodes.get(*id).and_then(Value::as_array);
            tuple.is_some_and(|t| {
                t.get(2).and_then(Value::as_str) == Some(sha512)
                    && t.get(3).and_then(Value::as_str) == Some(url)
            })
        })
        .then_some(())
}

struct Splice {
    line: usize,
    text: String,
    edit: FileEdit,
}

fn unsupported_key(result: &mut RewriteResult, dep: &DepOverride, id: &str) {
    result.warnings.push(RewriteWarning {
        code: "redirect_vlt_unsupported_lock_key".into(),
        detail: format!(
            "vlt-lock.json entry {id} cannot be rewritten safely; re-save the lock with `vlt \
             install`"
        ),
    });
    result.refused_vlt_uuids.insert(dep.patch_uuid.clone());
}

/// Rewrite one override's default-registry instances, or none of them.
/// Returns whether any line changed.
fn rewrite_dep(
    lock: &HostedLock,
    lines: &mut [String],
    dep: &DepOverride,
    result: &mut RewriteResult,
) -> bool {
    let name = full_name(dep);
    let version = dep.version.as_str();
    let options = lock.parsed.options();
    let empty = Map::new();
    let nodes = lock.parsed.nodes().unwrap_or(&empty);

    let mut defaults: Vec<&str> = Vec::new();
    let mut foreign: Vec<&str> = Vec::new();
    for id in nodes.keys() {
        match registry_instance(id, &name, version, options) {
            Some(true) => defaults.push(id),
            Some(false) => foreign.push(id),
            None => {}
        }
    }
    if !foreign.is_empty() {
        result.warnings.push(RewriteWarning {
            code: "redirect_vlt_custom_registry_skipped".into(),
            detail: format!(
                "hosted mode only redirects packages from vlt's default registry; {} left \
                 unchanged (use --mode vendored or agent mode)",
                foreign.join(", ")
            ),
        });
    }
    let Some(sha512) = dep.integrity.sha512.as_deref().filter(|s| !s.is_empty()) else {
        result.warnings.push(RewriteWarning {
            code: "redirect_vlt_missing_sha512".into(),
            detail: format!(
                "hosted artifact for {} has no sha512 integrity; retry later",
                npm_purl(&name, version)
            ),
        });
        result.refused_vlt_uuids.insert(dep.patch_uuid.clone());
        return false;
    };
    if defaults.is_empty() {
        let warning = if has_vendored_node(nodes, &name, version) {
            RewriteWarning {
                code: "redirect_vlt_entry_vendored".into(),
                detail: format!(
                    "{name}@{version} is vendored; re-run `socket-patch scan --mode hosted` from \
                     a ledger that owns it, or `socket-patch vendor --revert`"
                ),
            }
        } else {
            RewriteWarning {
                code: "redirect_vlt_entry_not_found".into(),
                detail: format!(
                    "vlt-lock.json has no default-registry entry for {name}@{version}; run `vlt \
                     install` first"
                ),
            }
        };
        result.warnings.push(warning);
        return false;
    }

    let mut located: Vec<(usize, &str)> = Vec::new();
    for id in &defaults {
        match instance_line(lines, lock.nodes, id, &name) {
            Some(idx) => located.push((idx, id)),
            None => {
                unsupported_key(result, dep, id);
                return false;
            }
        }
    }
    located.sort_unstable();

    let s2 = serde_json::to_string(sha512).expect("a str serializes to JSON infallibly");
    let s3 = serde_json::to_string(&dep.artifact_url).expect("a str serializes to JSON infallibly");
    let mut splices: Vec<Splice> = Vec::new();
    for &(idx, id) in &located {
        let line = parse_node_line(&lines[idx]).expect("instance_line parsed this line");
        let elems = &line.entry.elems;
        if elems.len() >= 4 && elems[2] == s2 && elems[3] == s3 {
            continue;
        }
        let tuple = render_tuple_with_slots(elems, Some(&s2), Some(&s3));
        let new_text = entry_text(id, &tuple);
        let extra = split_dep_id(id).and_then(|dep_id| dep_id.extra);
        splices.push(Splice {
            line: idx,
            text: render_entry_line(&new_text, line.comma, line.cr),
            edit: FileEdit {
                path: VLT_LOCK.into(),
                kind: KIND.into(),
                action: "rewritten".into(),
                key: Some(ledger_key(&name, version, extra.as_deref())),
                original: Some(Value::String(line.entry.entry_text())),
                new: Some(Value::String(new_text)),
            },
        });
    }

    let mut candidate: Vec<String> = lines.to_vec();
    for splice in &splices {
        candidate[splice.line].clone_from(&splice.text);
    }
    let ids: Vec<&str> = located.iter().map(|(_, id)| *id).collect();
    if every_instance_pinned(&candidate.join("\n"), &ids, sha512, &dep.artifact_url).is_none() {
        unsupported_key(result, dep, ids[0]);
        return false;
    }

    result.confirmed_vlt_uuids.insert(dep.patch_uuid.clone());
    let changed = !splices.is_empty();
    for splice in splices {
        lines[splice.line] = splice.text;
        result.edits.push(splice.edit);
    }
    changed
}

/// The hosted vlt rewrite (DESIGN §3.2–§3.8): lock-level refusal and
/// advisories, then each npm override's default-registry instances.
pub(super) fn rewrite_vlt_lock(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    let npm: Vec<&DepOverride> = overrides.iter().filter(|o| o.ecosystem == "npm").collect();
    if npm.is_empty() {
        return;
    }
    let Some(text) = files.get(VLT_LOCK) else {
        if files.contains_key(VLT_CONFIG) || files.contains_key(VLT_HIDDEN_LOCK_REL) {
            result.warnings.push(RewriteWarning {
                code: "redirect_vlt_no_lockfile".into(),
                detail: "vlt project has no vlt-lock.json; run `vlt install` and commit \
                         vlt-lock.json"
                    .into(),
            });
        }
        return;
    };
    let lock = match parse_hosted_lock(text) {
        Ok(lock) => lock,
        Err(warning) => {
            result.warnings.push(warning);
            return;
        }
    };
    result.warnings.extend(lock_level_warnings(&lock, files));

    let mut lines: Vec<String> = split_lines(text).into_iter().map(str::to_string).collect();
    let mut changed = false;
    for dep in npm {
        changed |= rewrite_dep(&lock, &mut lines, dep, result);
    }
    if changed {
        result.files.insert(VLT_LOCK.into(), lines.join("\n"));
    }
}

// ── revert ───────────────────────────────────────────────────────────────

fn slot_value(entry: &NodeEntry<'_>, index: usize) -> Option<Value> {
    match entry.slot(index) {
        None | Some("null") => None,
        Some(raw) => serde_json::from_str(raw).ok(),
    }
}

fn same_slots(a: &NodeEntry<'_>, b: &NodeEntry<'_>) -> bool {
    slot_value(a, 2) == slot_value(b, 2) && slot_value(a, 3) == slot_value(b, 3)
}

fn drift(id: &str, why: &str) -> String {
    format!(
        "vlt-lock.json {why}; restore the registry pin for {id} manually, or re-run \
         `socket-patch scan --mode hosted` and then roll back"
    )
}

/// Undo one [`KIND`] edit by slots. The line keyed by the recorded DepID
/// gets `original`'s slots [2] and [3] back while its current flags,
/// trailing slots, indent, comma and `\r` stay, so a lock vlt re-laid since
/// the rewrite still reverts. `Ok(None)` when there is nothing to revert:
/// the line already holds `original`'s slots, or the DepID and the hosted
/// URL are both gone (a re-lock). Anything else is drift.
pub(crate) fn revert_vlt_slots(text: &str, edit: &FileEdit) -> Result<Option<String>, String> {
    fn fragment(v: &Option<Value>) -> Option<&str> {
        v.as_ref().and_then(Value::as_str)
    }
    let (Some(original), Some(new)) = (fragment(&edit.original), fragment(&edit.new)) else {
        return Err(format!("{KIND} edit is missing its recorded fragments"));
    };
    let (Some(original), Some(new)) = (parse_node_entry_text(original), parse_node_entry_text(new))
    else {
        return Err(format!(
            "{KIND} edit records fragments that are not vlt node entries"
        ));
    };
    if original.key != new.key {
        return Err(format!("{KIND} edit records two different DepIDs"));
    }
    let id = original.key;
    let lines = split_lines(text);
    let Some(span) = nodes_block(&lines) else {
        return Err(drift(id, "nodes section is not in vlt's canonical layout"));
    };
    let prefix = format!("    \"{id}\": ");
    let keyed: Vec<usize> = span
        .entry_lines()
        .filter(|&i| lines[i].starts_with(prefix.as_str()))
        .collect();
    let url = slot_value(&new, 3);
    match keyed.as_slice() {
        [] => {
            let url_left = url
                .as_ref()
                .and_then(Value::as_str)
                .is_some_and(|url| lines.iter().any(|line| line.contains(url)));
            if url_left {
                Err(drift(
                    id,
                    &format!("no longer has {id}, but still pins its hosted URL"),
                ))
            } else {
                Ok(None)
            }
        }
        [idx] => {
            let Some(line) = parse_node_line(lines[*idx]) else {
                return Err(drift(
                    id,
                    &format!("entry {id} is outside vlt's node grammar"),
                ));
            };
            if same_slots(&line.entry, &original) {
                return Ok(None);
            }
            if !same_slots(&line.entry, &new) {
                return Err(drift(
                    id,
                    &format!("entry {id} drifted from the recorded redirect"),
                ));
            }
            let tuple = render_tuple_with_slots(
                &line.entry.elems,
                original.slot(2).filter(|s| *s != "null"),
                original.slot(3).filter(|s| *s != "null"),
            );
            let mut out: Vec<String> = lines.iter().map(|l| (*l).to_string()).collect();
            out[*idx] = render_entry_line(&entry_text(id, &tuple), line.comma, line.cr);
            Ok(Some(out.join("\n")))
        }
        _ => Err(drift(id, &format!("has {id} more than once"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "sha512-PATCHED==";
    const URL: &str = "https://patch.socket.dev/patch/npm/t/u/left-pad-1.3.0.tgz";
    const REG_SHA: &str = "sha512-REGISTRY==";
    const REG_URL: &str = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";

    fn files(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn dep(name: &str, version: &str, sha512: Option<&str>) -> DepOverride {
        serde_json::from_value(serde_json::json!({
            "ecosystem": "npm",
            "name": name,
            "version": version,
            "token": "t",
            "patchUuid": format!("uuid-{name}"),
            "artifactUrl": URL,
            "integrity": { "sha512": sha512 },
        }))
        .unwrap()
    }

    fn lock_with(node_lines: &[&str]) -> String {
        let mut out =
            String::from("{\n  \"lockfileVersion\": 1,\n  \"options\": {},\n  \"nodes\": {\n");
        for (i, line) in node_lines.iter().enumerate() {
            out.push_str("    ");
            out.push_str(line);
            if i + 1 < node_lines.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("  },\n  \"edges\": {}\n}\n");
        out
    }

    fn rewrite(lock: &str, deps: &[DepOverride]) -> RewriteResult {
        let mut result = RewriteResult::default();
        rewrite_vlt_lock(&files(&[(VLT_LOCK, lock)]), deps, &mut result);
        result
    }

    fn codes(result: &RewriteResult) -> Vec<&str> {
        result.warnings.iter().map(|w| w.code.as_str()).collect()
    }

    fn vlt_edit(original: &str, new: &str) -> FileEdit {
        FileEdit {
            path: VLT_LOCK.into(),
            kind: KIND.into(),
            action: "rewritten".into(),
            key: Some("left-pad@1.3.0".into()),
            original: Some(Value::String(original.into())),
            new: Some(Value::String(new.into())),
        }
    }

    const ID: &str = "~npm~left-pad@1.3.0";

    fn registry_entry() -> String {
        format!("\"{ID}\": [0,\"left-pad\",\"{REG_SHA}\",\"{REG_URL}\"]")
    }

    fn hosted_entry() -> String {
        format!("\"{ID}\": [0,\"left-pad\",\"{SHA}\",\"{URL}\"]")
    }

    #[test]
    fn vlt_drives_needs_the_lock_and_the_sentinel_or_no_sibling() {
        let sentinel = (VLT_HIDDEN_LOCK_REL, "");
        let lock = (VLT_LOCK, "{}");
        assert!(!vlt_drives(&files(&[])));
        assert!(!vlt_drives(&files(&[sentinel, (VLT_CONFIG, "{}")])));
        assert!(vlt_drives(&files(&[lock])));
        assert!(vlt_drives(&files(&[lock, (VLT_CONFIG, "{}")])));
        for sibling in SIBLING_LOCKS {
            let other = (sibling, "x");
            assert!(!vlt_drives(&files(&[lock, other])), "{sibling}");
            assert!(vlt_drives(&files(&[lock, other, sentinel])), "{sibling}");
        }
        assert!(!vlt_drives(&files(&[
            lock,
            ("package-lock.json", "x"),
            ("bun.lockb", "x")
        ])));
        assert!(vlt_drives(&files(&[
            lock,
            ("packages/a/package-lock.json", "x")
        ])));
    }

    #[test]
    fn ledger_keys_carry_the_raw_extra_after_a_tilde() {
        let lock = lock_with(&[
            &format!("\"·npm·left-pad@1.3.0·%E1%B9%97%3A3\": [0,\"left-pad\",\"{REG_SHA}\"]"),
            &format!("\"~npm~left-pad@1.3.0~_croot_s_g_s#x\": [0,\"left-pad\",\"{REG_SHA}\"]"),
            &format!("\"~npm~left-pad@1.3.0~peer.2\": [0,\"left-pad\",\"{REG_SHA}\"]"),
            &format!("\"{ID}\": [0,\"left-pad\",\"{REG_SHA}\"]"),
        ]);
        let result = rewrite(&lock, &[dep("left-pad", "1.3.0", Some(SHA))]);
        let keys: Vec<&str> = result
            .edits
            .iter()
            .map(|e| e.key.as_deref().unwrap())
            .collect();
        assert_eq!(
            keys,
            [
                "left-pad@1.3.0~%E1%B9%97%3A3",
                "left-pad@1.3.0~_croot_s_g_s#x",
                "left-pad@1.3.0~peer.2",
                "left-pad@1.3.0",
            ]
        );
        for key in keys {
            assert!(claims_key(key, "left-pad", "1.3.0"), "{key}");
        }
        assert!(result.confirmed_vlt_uuids.contains("uuid-left-pad"));
    }

    #[test]
    fn claims_stop_at_the_version_boundary() {
        assert!(claims_key("@s/p@1.0.0", "@s/p", "1.0.0"));
        assert!(claims_key("@s/p@1.0.0~peer.1", "@s/p", "1.0.0"));
        for foreign in [
            "left-pad@1.3.01",
            "left-pad@1.3.0-rc.1",
            "left-pad@1.3.0(peer)",
            "left-pad@1.3.0_x",
            "long-left-pad@1.3.0",
            "left-pad@1.3",
        ] {
            assert!(!claims_key(foreign, "left-pad", "1.3.0"), "{foreign}");
        }
    }

    #[test]
    fn residual_gate_refuses_when_the_parsed_node_is_not_the_spliced_line() {
        let entry = format!("    \"{ID}\": [0,\"left-pad\",\"{REG_SHA}\"]");
        let lock = format!(
            "{{\n  \"lockfileVersion\": 1,\n  \"nodes\": {{\n{entry}\n  }},\n  \"nodes\": {{\n{entry}\n  }}\n}}\n"
        );
        let result = rewrite(&lock, &[dep("left-pad", "1.3.0", Some(SHA))]);
        assert_eq!(codes(&result), ["redirect_vlt_unsupported_lock_key"]);
        assert!(result.files.is_empty() && result.edits.is_empty());
        assert!(result.refused_vlt_uuids.contains("uuid-left-pad"));
        assert!(result.confirmed_vlt_uuids.is_empty());
    }

    #[test]
    fn an_unsupported_instance_refuses_every_instance_of_the_dep_only() {
        let lock = format!(
            "{{\n  \"lockfileVersion\": 1,\n  \"nodes\": {{\n    \"{ID}\": [0,\"left-pad\",\"{REG_SHA}\"],\n    \"~npm~left-pad@1.3.0~peer.1\": [0, \"left-pad\"],\n    \"~npm~ms@2.1.3\": [0,\"ms\",\"{REG_SHA}\"]\n  }}\n}}\n"
        );
        let result = rewrite(
            &lock,
            &[
                dep("left-pad", "1.3.0", Some(SHA)),
                dep("ms", "2.1.3", Some(SHA)),
            ],
        );
        assert_eq!(codes(&result), ["redirect_vlt_unsupported_lock_key"]);
        assert_eq!(result.edits.len(), 1);
        assert_eq!(result.edits[0].key.as_deref(), Some("ms@2.1.3"));
        assert!(result.refused_vlt_uuids.contains("uuid-left-pad"));
        assert!(result.confirmed_vlt_uuids.contains("uuid-ms"));
    }

    #[test]
    fn a_name_mismatch_in_slot_one_is_unsupported() {
        let lock = lock_with(&[&format!("\"{ID}\": [0,\"other\",\"{REG_SHA}\"]")]);
        let result = rewrite(&lock, &[dep("left-pad", "1.3.0", Some(SHA))]);
        assert_eq!(codes(&result), ["redirect_vlt_unsupported_lock_key"]);
    }

    #[test]
    fn lock_level_parse_refusals() {
        let refused = |text: &str| {
            preflight_vlt_hosted(&files(&[(VLT_LOCK, text)]))
                .unwrap_err()
                .detail
        };
        assert!(refused("\u{feff}{}").contains("UTF-8 BOM"));
        assert!(refused("[]").contains("not a JSON object"));
        assert!(refused("{\"lockfileVersion\": 1.0}").contains("lockfileVersion 1.0"));
        let pretty = format!(
            "{{\n  \"lockfileVersion\": 1,\n  \"nodes\": {{\n    \"{ID}\": [\n      0,\n      \"left-pad\"\n    ]\n  }}\n}}\n"
        );
        assert!(refused(&pretty).contains("canonical layout"));
        assert!(preflight_vlt_hosted(&files(&[])).is_ok());
        assert!(preflight_vlt_hosted(&files(&[(VLT_LOCK, "{\"nodes\": {}}")])).is_ok());
        let ok = lock_with(&[&registry_entry()]);
        assert!(preflight_vlt_hosted(&files(&[(VLT_LOCK, &ok)])).is_ok());
    }

    #[test]
    fn missing_sha512_and_empty_sha512_refuse() {
        let lock = lock_with(&[&registry_entry()]);
        for sha in [None, Some("")] {
            let result = rewrite(&lock, &[dep("left-pad", "1.3.0", sha)]);
            assert_eq!(codes(&result), ["redirect_vlt_missing_sha512"]);
            assert!(result.refused_vlt_uuids.contains("uuid-left-pad"));
        }
    }

    #[test]
    fn non_npm_overrides_leave_everything_alone() {
        let mut other = dep("left-pad", "1.3.0", Some(SHA));
        other.ecosystem = "pypi".into();
        let mut result = RewriteResult::default();
        rewrite_vlt_lock(&files(&[(VLT_CONFIG, "{}")]), &[other], &mut result);
        assert!(result.warnings.is_empty());
    }

    fn revert(lock: &str, edit: &FileEdit) -> Result<Option<String>, String> {
        revert_vlt_slots(lock, edit)
    }

    #[test]
    fn revert_restores_the_slots_after_a_comma_move() {
        let edit = vlt_edit(&registry_entry(), &hosted_entry());
        let lone = lock_with(&[&hosted_entry()]);
        assert_eq!(
            revert(&lone, &edit).unwrap().unwrap(),
            lock_with(&[&registry_entry()])
        );
        let sibling = "\"~npm~zz@1.0.0\": [0,\"zz\",\"sha512-z\"]";
        let moved = lock_with(&[&hosted_entry(), sibling]);
        assert_eq!(
            revert(&moved, &edit).unwrap().unwrap(),
            lock_with(&[&registry_entry(), sibling])
        );
    }

    #[test]
    fn revert_keeps_a_changed_flag_and_new_trailing_slots() {
        let edit = vlt_edit(&registry_entry(), &hosted_entry());
        let relaid = lock_with(&[&format!(
            "\"{ID}\": [2,\"left-pad\",\"{SHA}\",\"{URL}\",null,null,null,null,{{  \"lp\": \"bin.js\"}}]"
        )]);
        assert_eq!(
            revert(&relaid, &edit).unwrap().unwrap(),
            lock_with(&[&format!(
                "\"{ID}\": [2,\"left-pad\",\"{REG_SHA}\",\"{REG_URL}\",null,null,null,null,{{  \"lp\": \"bin.js\"}}]"
            )])
        );
    }

    #[test]
    fn revert_of_a_three_tuple_original() {
        let original = format!("\"{ID}\": [0,\"left-pad\",\"{REG_SHA}\"]");
        let edit = vlt_edit(&original, &hosted_entry());
        assert_eq!(
            revert(&lock_with(&[&hosted_entry()]), &edit)
                .unwrap()
                .unwrap(),
            lock_with(&[&original])
        );
        let five = lock_with(&[&format!(
            "\"{ID}\": [1,\"left-pad\",\"{SHA}\",\"{URL}\",\"lib\"]"
        )]);
        assert_eq!(
            revert(&five, &edit).unwrap().unwrap(),
            lock_with(&[&format!(
                "\"{ID}\": [1,\"left-pad\",\"{REG_SHA}\",null,\"lib\"]"
            )])
        );
    }

    #[test]
    fn revert_after_an_lf_resave_of_a_crlf_lock() {
        let edit = vlt_edit(&registry_entry(), &hosted_entry());
        let crlf = lock_with(&[&hosted_entry()]).replace('\n', "\r\n");
        assert_eq!(
            revert(&crlf, &edit).unwrap().unwrap(),
            lock_with(&[&registry_entry()]).replace('\n', "\r\n")
        );
        let lf = lock_with(&[&hosted_entry()]);
        assert_eq!(
            revert(&lf, &edit).unwrap().unwrap(),
            lock_with(&[&registry_entry()])
        );
    }

    #[test]
    fn revert_already_reverted() {
        let edit = vlt_edit(&registry_entry(), &hosted_entry());
        assert_eq!(revert(&lock_with(&[&registry_entry()]), &edit), Ok(None));
        let relaid = lock_with(&[&format!(
            "\"{ID}\": [2,\"left-pad\",\"{REG_SHA}\",\"{REG_URL}\"]"
        )]);
        assert_eq!(revert(&relaid, &edit), Ok(None));
        let relocked = lock_with(&[&format!(
            "\"~npm~left-pad@1.3.0~peer.1\": [0,\"left-pad\",\"{REG_SHA}\",\"{REG_URL}\"]"
        )]);
        assert_eq!(revert(&relocked, &edit), Ok(None));
    }

    #[test]
    fn revert_refuses_drift() {
        let edit = vlt_edit(&registry_entry(), &hosted_entry());
        let other = lock_with(&[&format!(
            "\"{ID}\": [0,\"left-pad\",\"sha512-OTHER==\",\"{URL}\"]"
        )]);
        assert!(revert(&other, &edit).unwrap_err().contains("drifted"));
        let moved = lock_with(&[&format!(
            "\"~npm~left-pad@1.3.0~peer.1\": [0,\"left-pad\",\"{SHA}\",\"{URL}\"]"
        )]);
        let err = revert(&moved, &edit).unwrap_err();
        assert!(err.contains("still pins its hosted URL"), "{err}");
        assert!(err.contains("restore the registry pin for ~npm~left-pad@1.3.0 manually"));
        let twice = format!(
            "{{\n  \"nodes\": {{\n    {},\n    {}\n  }}\n}}\n",
            hosted_entry(),
            hosted_entry()
        );
        assert!(revert(&twice, &edit)
            .unwrap_err()
            .contains("more than once"));
        let multi = format!("{{\n  \"nodes\": {{\n    \"{ID}\": [\n      0\n    ]\n  }}\n}}\n");
        assert!(revert(&multi, &edit).unwrap_err().contains("node grammar"));
        assert!(revert("{\"nodes\": {}}", &edit)
            .unwrap_err()
            .contains("canonical"));
    }

    #[test]
    fn revert_refuses_a_malformed_ledger_edit() {
        let mut edit = vlt_edit(&registry_entry(), &hosted_entry());
        edit.original = None;
        assert!(revert(&lock_with(&[&hosted_entry()]), &edit).is_err());
        let edit = vlt_edit("not an entry", &hosted_entry());
        assert!(revert(&lock_with(&[&hosted_entry()]), &edit).is_err());
        let edit = vlt_edit(
            &format!("\"~npm~other@1.0.0\": [0,\"other\",\"{REG_SHA}\"]"),
            &hosted_entry(),
        );
        assert!(revert(&lock_with(&[&hosted_entry()]), &edit)
            .unwrap_err()
            .contains("two different DepIDs"));
    }
}
