//! Cross-mode takeover: per-purl revert of a HOSTED redirect, driven by the
//! redirect ledger's recorded [`FileEdit`]s.
//!
//! The vendored flows (`vendor`, `scan --mode vendored`) call this BEFORE
//! vendoring a package the hosted redirect ledger still claims, so a
//! hosted→vendored migration leaves the project FULLY in vendored mode.
//!
//! Cargo: Cargo.toml loses its `registry = "socket-patch-…"` pin, Cargo.lock
//! gets its original crates.io `source`/`checksum` back (so the subsequent
//! vendor detach records the PRISTINE originals in the vendor ledger, not the
//! hosted values), and the now-unused `[registries.socket-patch-…]` block is
//! dropped. Without this, `[patch.crates-io]` cannot even apply (it only
//! patches crates-io-sourced deps) and the project is unbuildable in both
//! modes.
//!
//! npm family (package-lock/npm-shrinkwrap, yarn classic, yarn berry, pnpm):
//! each recorded lock edit's `original` fragment is replayed over its `new`
//! fragment. Here the follow-up vendor rewire happens to succeed either way
//! (the vendored wiring replaces whatever resolution is present), but
//! WITHOUT the pre-revert the vendor ledger records the grant-tokenized
//! hosted fragment as its unrecoverable pre-vendor "original" (so `vendor
//! --revert` restores an expiring hosted URL with no CLI path back to
//! registry state), and the superseded redirect records/edits survive
//! forever — a stale ledger that VEX/audits keep reading and a replay hazard
//! for any later redirect revert.
//!
//! FAIL CLOSED: a file that matches neither the recorded redirected fragment
//! nor the recorded original has drifted — the revert refuses (`Err`) rather
//! than half-applying, and the caller must then refuse to vendor that purl.
//! Refusing has to leave the project byte-identical across ALL the files the
//! ledger claims, not just the one that drifted: the caller reports the purl
//! as untouched ("cannot vendor over the live hosted redirect"), so an
//! already-rewritten Cargo.lock behind that message would be a half-hosted
//! project nobody is told about, and every retry refuses on the same drift.
//! So each inverse is resolved against a staged view and NOTHING reaches disk
//! until all of them have resolved.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde_json::Value;

use crate::utils::purl::{normalize_purl, parse_cargo_purl, strip_purl_qualifiers};

use super::state::RedirectState;
use super::FileEdit;

/// What a redirect revert rewrote.
#[derive(Debug, Default)]
pub struct RedirectRevert {
    /// Repo-relative files this revert actually rewrote or removed.
    pub reverted_files: Vec<String>,
}

/// Pre-rename alias (the struct was cargo-only before the npm-family port).
pub type CargoRedirectRevert = RedirectRevert;

/// Does [`revert_redirect_purl`] have an implementation for this purl's
/// ecosystem? Callers (the vendor dispatch loop's cross-mode takeover gate)
/// must consult this instead of hardcoding `pkg:cargo/`.
pub fn redirect_revert_supported(purl: &str) -> bool {
    purl.starts_with("pkg:cargo/") || purl.starts_with("pkg:npm/")
}

/// Revert every hosted-redirect edit the ledger records for `purl`, then
/// drop that purl's record and edits from `state`. The caller persists the
/// mutated ledger (see `persist_redirect_state`). Dispatches per ecosystem;
/// purls outside [`redirect_revert_supported`] are refused (fail closed).
pub async fn revert_redirect_purl(
    project_root: &Path,
    state: &mut RedirectState,
    purl: &str,
) -> Result<RedirectRevert, String> {
    if purl.starts_with("pkg:cargo/") {
        revert_cargo_redirect_purl(project_root, state, purl).await
    } else if purl.starts_with("pkg:npm/") {
        revert_npm_redirect_purl(project_root, state, purl).await
    } else {
        Err(format!(
            "no hosted-redirect revert implementation for {purl}"
        ))
    }
}

/// Read a project file, distinguishing missing (`Ok(None)`) from unreadable.
async fn read_rel(project_root: &Path, rel: &str) -> Result<Option<String>, String> {
    match tokio::fs::read_to_string(project_root.join(rel)).await {
        Ok(c) => Ok(Some(c)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("read {rel}: {e}")),
    }
}

async fn write_rel(project_root: &Path, rel: &str, content: &str) -> Result<(), String> {
    tokio::fs::write(project_root.join(rel), content)
        .await
        .map_err(|e| format!("write {rel}: {e}"))
}

/// Files the unwind has decided but not yet written: `Some(content)` to
/// write, `None` to remove.
type Staged = BTreeMap<String, Option<String>>;

/// Read a project file through the staged writes, so each unwind step sees
/// what the earlier steps decided. Both the re-redirect chain (a step's
/// `original` is the previous step's `new`) and the registry block's
/// still-referenced probe depend on that view, and neither may depend on the
/// bytes having landed.
async fn staged_read(
    staged: &Staged,
    project_root: &Path,
    rel: &str,
) -> Result<Option<String>, String> {
    match staged.get(rel) {
        Some(pending) => Ok(pending.clone()),
        None => read_rel(project_root, rel).await,
    }
}

/// Write the staged files. Only reached once every inverse resolved, so a
/// drift refusal never gets here; an I/O fault partway through is the one
/// remaining way to stop mid-set, and it surfaces as `Err` with the write
/// already reported by path.
async fn flush_staged(project_root: &Path, staged: &Staged) -> Result<(), String> {
    for (rel, pending) in staged {
        let Some(content) = pending else {
            let path = project_root.join(rel);
            match tokio::fs::remove_file(&path).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("remove {rel}: {e}")),
            }
            // Best-effort: prune a now-empty `.cargo/` dir.
            if let Some(parent) = path.parent() {
                let _ = tokio::fs::remove_dir(parent).await;
            }
            continue;
        };
        write_rel(project_root, rel, content).await?;
    }
    Ok(())
}

/// Revert every hosted-redirect edit the ledger records for `purl` (a cargo
/// package), then drop that purl's record and edits from `state`. The caller
/// persists the mutated ledger (see `persist_redirect_state`).
///
/// Chained re-redirects (the same purl redirected at successive patch uuids)
/// unwind newest-first: each edit's `new` fragment is replaced by its
/// `original`, and an intermediate edit whose `original` is already live is a
/// no-op. `[registries.socket-patch-…]` blocks tied to this purl's uuids are
/// removed only when nothing in Cargo.toml / Cargo.lock still references them.
pub async fn revert_cargo_redirect_purl(
    project_root: &Path,
    state: &mut RedirectState,
    purl: &str,
) -> Result<RedirectRevert, String> {
    let canon = |p: &str| normalize_purl(strip_purl_qualifiers(p)).into_owned();
    let target = canon(purl);
    let Some(record_key) = state.records.keys().find(|k| canon(k) == target).cloned() else {
        return Err(format!(
            "the redirect ledger records no hosted redirect for {purl}"
        ));
    };
    let Some((name, version)) = parse_cargo_purl(&target) else {
        return Err(format!("not a cargo purl: {purl}"));
    };
    let (name, version) = (name.to_string(), version.to_string());
    let lock_key = format!("{name}@{version}");

    let is_wiring_edit = |e: &FileEdit| {
        (e.kind == "redirect_cargo_toml_dep" && e.key.as_deref() == Some(name.as_str()))
            || (e.kind == "redirect_cargo_lock_entry"
                && e.key.as_deref() == Some(lock_key.as_str()))
    };
    // Registry blocks tie to this purl via the `socket-patch-<uuid>` names in
    // its record + wiring edits (a patch uuid is per purl, so this cannot
    // claim another package's block).
    let mut uuids: HashSet<String> = HashSet::new();
    uuids.insert(state.records[&record_key].uuid.clone());
    let uuid_re =
        regex::Regex::new(r"socket-patch-([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})")
            .expect("static regex");
    for e in state.edits.iter().filter(|e| is_wiring_edit(e)) {
        for v in [&e.original, &e.new] {
            if let Some(s) = v.as_ref().and_then(Value::as_str) {
                for c in uuid_re.captures_iter(s) {
                    uuids.insert(c[1].to_string());
                }
            }
        }
    }
    let is_registry_edit = |e: &FileEdit| {
        e.kind == "redirect_cargo_registry"
            && e.key
                .as_deref()
                .and_then(|k| k.strip_prefix("socket-patch-"))
                .is_some_and(|u| uuids.contains(u))
    };

    let mine: Vec<usize> = state
        .edits
        .iter()
        .enumerate()
        .filter(|(_, e)| is_wiring_edit(e) || is_registry_edit(e))
        .map(|(i, _)| i)
        .collect();

    let mut out = RedirectRevert::default();
    let mut staged: Staged = Staged::new();
    // Newest-first: the hosted flow appends edits, so reverse index order
    // unwinds re-redirect chains correctly (each step's `original` is the
    // previous step's `new`), and the registry-block removals — recorded
    // before their wiring edits — run last, after the references are gone.
    for &i in mine.iter().rev() {
        let edit = state.edits[i].clone();
        match edit.kind.as_str() {
            "redirect_cargo_toml_dep" | "redirect_cargo_lock_entry" => {
                let (Some(new), Some(orig)) = (
                    edit.new.as_ref().and_then(Value::as_str),
                    edit.original.as_ref().and_then(Value::as_str),
                ) else {
                    return Err(format!(
                        "the redirect ledger edit for {} in {} records no original \
                         fragment; cannot revert the hosted redirect",
                        name, edit.path
                    ));
                };
                let Some(content) = staged_read(&staged, project_root, &edit.path).await? else {
                    return Err(format!(
                        "{} no longer exists; cannot revert the recorded hosted \
                         redirect for {name}@{version}",
                        edit.path
                    ));
                };
                if content.contains(new) {
                    let reverted = content.replacen(new, orig, 1);
                    staged.insert(edit.path.clone(), Some(reverted));
                    out.reverted_files.push(edit.path.clone());
                } else if content.contains(orig) {
                    // Already at (or unwound to) the pre-redirect fragment.
                } else {
                    return Err(format!(
                        "the {} entry for {name}@{version} has drifted from the \
                         recorded hosted redirect (neither the redirected nor the \
                         original fragment is present); refusing to touch it — \
                         re-run `scan --mode hosted` to normalize the redirect, \
                         or restore the crates.io wiring manually, then re-run",
                        edit.path
                    ));
                }
            }
            "redirect_cargo_registry" => {
                let Some(block) = edit.new.as_ref().and_then(Value::as_str) else {
                    continue; // nothing recorded to remove — leave the config
                };
                let Some(content) = staged_read(&staged, project_root, &edit.path).await? else {
                    continue; // config already gone
                };
                if !content.contains(block) {
                    continue; // block already removed
                }
                // Keep the block while anything still references its registry
                // name or index URL (defensive — a hand-edited project may
                // have pinned another dep to it).
                let reg = edit.key.as_deref().unwrap_or_default();
                let index = block
                    .split('"')
                    .nth(1)
                    .map(str::to_string)
                    .unwrap_or_default();
                let mut referenced = false;
                for probe in ["Cargo.toml", "Cargo.lock"] {
                    if let Some(text) = staged_read(&staged, project_root, probe).await? {
                        if (!reg.is_empty() && text.contains(reg))
                            || (!index.is_empty() && text.contains(&index))
                        {
                            referenced = true;
                            break;
                        }
                    }
                }
                if referenced {
                    continue;
                }
                // A REGENERATED block (`action: "rewritten"` — the rewriter
                // replaced a degraded/commented region in place and recorded
                // it as `original`) restores that pre-existing region instead
                // of deleting it: the original bytes are the user's.
                if let Some(orig) = edit.original.as_ref().and_then(Value::as_str) {
                    let reverted = content.replacen(block, orig, 1);
                    staged.insert(edit.path.clone(), Some(reverted));
                    out.reverted_files.push(edit.path.clone());
                    continue;
                }
                let mut trimmed = content.replacen(block, "", 1);
                // Collapse the blank separator the rewrite inserted.
                while trimmed.contains("\n\n\n") {
                    trimmed = trimmed.replace("\n\n\n", "\n\n");
                }
                let trimmed = trimmed.trim_start_matches('\n').to_string();
                if trimmed.trim().is_empty() {
                    staged.insert(edit.path.clone(), None);
                } else {
                    staged.insert(edit.path.clone(), Some(trimmed));
                }
                out.reverted_files.push(edit.path.clone());
            }
            _ => {}
        }
    }

    // Every inverse resolved — only now does any of it reach disk, so a
    // refusal above left the project exactly as it was found.
    flush_staged(project_root, &staged).await?;

    // Only after every inverse applied cleanly: drop this purl's edits and
    // record from the ledger (the caller persists it).
    let drop: HashSet<usize> = mine.into_iter().collect();
    let mut idx = 0usize;
    state.edits.retain(|_| {
        let keep = !drop.contains(&idx);
        idx += 1;
        keep
    });
    state.records.remove(&record_key);
    Ok(out)
}

/// `pkg:npm/<name>@<version>` (canonical, percent-decoded form) →
/// `(name, version)`; the name keeps its `@scope/` namespace.
fn parse_npm_purl(canon: &str) -> Option<(&str, &str)> {
    let rest = canon.strip_prefix("pkg:npm/")?;
    let (name, version) = rest.rsplit_once('@')?;
    (!name.is_empty() && !version.is_empty()).then_some((name, version))
}

/// The npm-family text-fragment edit kinds: `original`/`new` hold the whole
/// lock fragment as a string, and the revert is a `replacen(new, original)`.
const NPM_TEXT_KINDS: [&str; 3] = [
    "redirect_yarn_classic_entry",
    "redirect_yarn_berry_entry",
    "redirect_pnpm_resolution",
];

/// Revert every hosted-redirect edit the ledger records for `purl` (an npm
/// package), then drop that purl's record and edits from `state`. The caller
/// persists the mutated ledger (see `persist_redirect_state`).
///
/// Same fail-closed contract as [`revert_cargo_redirect_purl`]: every inverse
/// is resolved against a staged view and NOTHING reaches disk until all of
/// them have resolved, so a drift refusal leaves the project byte-identical
/// across ALL the files the ledger claims.
pub async fn revert_npm_redirect_purl(
    project_root: &Path,
    state: &mut RedirectState,
    purl: &str,
) -> Result<RedirectRevert, String> {
    let canon = |p: &str| normalize_purl(strip_purl_qualifiers(p)).into_owned();
    let target = canon(purl);
    let Some(record_key) = state.records.keys().find(|k| canon(k) == target).cloned() else {
        return Err(format!(
            "the redirect ledger records no hosted redirect for {purl}"
        ));
    };
    let Some((name, version)) = parse_npm_purl(&target) else {
        return Err(format!("not an npm purl: {purl}"));
    };
    let (name, version) = (name.to_string(), version.to_string());
    let lock_key = format!("{name}@{version}");

    // The package-lock/shrinkwrap files any `redirect_npm_lock_entry` edits
    // touch, parsed once from disk: an ALIAS install (`npm i alias@npm:name`)
    // keys its entry by the alias, so ownership is resolved through the
    // entry's `name` field — exactly how the rewriter matched it (the rewrite
    // never touches name/version, so the probe is symmetric).
    let mut disk_locks: BTreeMap<String, Option<Value>> = BTreeMap::new();
    for e in &state.edits {
        if e.kind == "redirect_npm_lock_entry" && !disk_locks.contains_key(&e.path) {
            let parsed = read_rel(project_root, &e.path)
                .await?
                .and_then(|c| serde_json::from_str::<Value>(&c).ok());
            disk_locks.insert(e.path.clone(), parsed);
        }
    }

    // Claim this purl's edits. Text-fragment kinds and the berry/classic/pnpm
    // rewriters key edits by `<name>@<version>`; the legacy npm v2
    // `dependencies` tree keys by bare name; the v3 `packages` map keys by
    // the lock path. A bun.lock edit that may belong to this purl is a hard
    // refusal: bun edits key by the lock's package key (not name@version)
    // and their revert is not implemented, so vendoring over one would drop
    // the record while stranding its edits — half a takeover.
    let mut mine: Vec<usize> = Vec::new();
    for (i, e) in state.edits.iter().enumerate() {
        let key = e.key.as_deref().unwrap_or_default();
        let claimed = match e.kind.as_str() {
            k if NPM_TEXT_KINDS.contains(&k) => key == lock_key,
            "redirect_npm_lock_dep" => key == name,
            "redirect_npm_lock_entry" => {
                let key_name = key
                    .rsplit_once("node_modules/")
                    .map(|(_, n)| n)
                    .unwrap_or(key);
                key_name == name
                    || disk_locks
                        .get(&e.path)
                        .and_then(|l| l.as_ref())
                        .and_then(|l| l.get("packages"))
                        .and_then(|p| p.get(key))
                        .is_some_and(|entry| {
                            entry.get("name").and_then(Value::as_str) == Some(name.as_str())
                        })
            }
            "redirect_bun_lock_package" => {
                let probe = format!("\"{name}@");
                let holds = |v: &Option<Value>| {
                    v.as_ref()
                        .and_then(Value::as_str)
                        .is_some_and(|s| s.contains(&probe))
                };
                if holds(&e.new) || holds(&e.original) {
                    return Err(format!(
                        "the redirect ledger records a bun.lock hosted redirect \
                         for {name}, which this revert cannot replay yet; \
                         restore the registry wiring manually (or re-lock with \
                         `bun install`), remove the ledger entry, then re-run"
                    ));
                }
                false
            }
            _ => false,
        };
        if claimed {
            mine.push(i);
        }
    }

    let mut out = RedirectRevert::default();
    let mut staged: Staged = Staged::new();
    // Newest-first: the hosted flow appends edits, so reverse index order
    // unwinds re-redirect chains correctly (each step's `original` is the
    // previous step's `new`).
    for &i in mine.iter().rev() {
        let edit = state.edits[i].clone();
        if NPM_TEXT_KINDS.contains(&edit.kind.as_str()) {
            let (Some(new), Some(orig)) = (
                edit.new.as_ref().and_then(Value::as_str),
                edit.original.as_ref().and_then(Value::as_str),
            ) else {
                return Err(format!(
                    "the redirect ledger edit for {name} in {} records no \
                     original fragment; cannot revert the hosted redirect",
                    edit.path
                ));
            };
            let Some(content) = staged_read(&staged, project_root, &edit.path).await? else {
                return Err(format!(
                    "{} no longer exists; cannot revert the recorded hosted \
                     redirect for {lock_key}",
                    edit.path
                ));
            };
            if content.contains(new) {
                staged.insert(edit.path.clone(), Some(content.replacen(new, orig, 1)));
                out.reverted_files.push(edit.path.clone());
            } else if content.contains(orig) {
                // Already at (or unwound to) the pre-redirect fragment.
            } else {
                return Err(format!(
                    "the {} entry for {lock_key} has drifted from the recorded \
                     hosted redirect (neither the redirected nor the original \
                     fragment is present); refusing to touch it — re-run \
                     `scan --mode hosted` to normalize the redirect, or \
                     restore the registry wiring manually, then re-run",
                    edit.path
                ));
            }
        } else {
            revert_npm_json_edit(project_root, &mut staged, &edit, &name, &version, &mut out)
                .await?;
        }
    }

    // Every inverse resolved — only now does any of it reach disk, so a
    // refusal above left the project exactly as it was found.
    flush_staged(project_root, &staged).await?;

    // Only after every inverse applied cleanly: drop this purl's edits and
    // record from the ledger (the caller persists it).
    let drop: HashSet<usize> = mine.into_iter().collect();
    let mut idx = 0usize;
    state.edits.retain(|_| {
        let keep = !drop.contains(&idx);
        idx += 1;
        keep
    });
    state.records.remove(&record_key);
    Ok(out)
}

/// Replay one recorded package-lock JSON edit (`redirect_npm_lock_entry` /
/// `redirect_npm_lock_dep`) through the staged view.
async fn revert_npm_json_edit(
    project_root: &Path,
    staged: &mut Staged,
    edit: &FileEdit,
    name: &str,
    version: &str,
    out: &mut RedirectRevert,
) -> Result<(), String> {
    let Some(content) = staged_read(staged, project_root, &edit.path).await? else {
        return Err(format!(
            "{} no longer exists; cannot revert the recorded hosted redirect \
             for {name}@{version}",
            edit.path
        ));
    };
    let mut lock: Value = serde_json::from_str(&content).map_err(|e| {
        format!(
            "{} is not valid JSON ({e}); cannot revert the recorded hosted \
             redirect for {name}@{version}",
            edit.path
        )
    })?;
    let key = edit.key.as_deref().unwrap_or_default();
    let changed = match edit.kind.as_str() {
        "redirect_npm_lock_entry" => {
            let Some(entry) = lock.get_mut("packages").and_then(|p| p.get_mut(key)) else {
                return Err(format!(
                    "the {} entry `{key}` for {name}@{version} no longer \
                     exists; cannot revert the recorded hosted redirect",
                    edit.path
                ));
            };
            replay_resolved_integrity(entry, edit, &edit.path, key)?
        }
        "redirect_npm_lock_dep" => {
            let Some(deps) = lock.get_mut("dependencies").and_then(Value::as_object_mut) else {
                return Err(format!(
                    "{} no longer holds a `dependencies` tree; cannot revert \
                     the recorded hosted redirect for {name}@{version}",
                    edit.path
                ));
            };
            let mut any_found = false;
            let mut changed = false;
            revert_v2_deps(
                deps,
                name,
                version,
                edit,
                &edit.path,
                &mut any_found,
                &mut changed,
            )?;
            if !any_found {
                return Err(format!(
                    "the {} `dependencies` entry for {name}@{version} no \
                     longer exists; cannot revert the recorded hosted redirect",
                    edit.path
                ));
            }
            changed
        }
        other => {
            return Err(format!(
                "no revert implementation for redirect edit kind `{other}`"
            ));
        }
    };
    if changed {
        staged.insert(edit.path.clone(), Some(super::serialize_json(&lock)));
        out.reverted_files.push(edit.path.clone());
    }
    Ok(())
}

/// Replace an entry's `resolved`/`integrity` with the edit's recorded
/// originals. `Ok(false)` when the entry already holds the originals;
/// `Err` (drift, fail closed) when it holds neither the recorded redirected
/// values nor the originals.
fn replay_resolved_integrity(
    entry: &mut Value,
    edit: &FileEdit,
    path: &str,
    key: &str,
) -> Result<bool, String> {
    let field = |v: &Option<Value>, f: &str| -> Value {
        v.as_ref()
            .and_then(|o| o.get(f))
            .cloned()
            .unwrap_or(Value::Null)
    };
    let orig_res = field(&edit.original, "resolved");
    let orig_int = field(&edit.original, "integrity");
    let cur = |f: &str| entry.get(f).cloned().unwrap_or(Value::Null);
    if cur("resolved") == orig_res && cur("integrity") == orig_int {
        return Ok(false); // already at (or unwound to) the pre-redirect values
    }
    if cur("resolved") != field(&edit.new, "resolved")
        || cur("integrity") != field(&edit.new, "integrity")
    {
        return Err(format!(
            "the {path} entry `{key}` has drifted from the recorded hosted \
             redirect (neither the redirected nor the original \
             resolved/integrity is present); refusing to touch it — re-run \
             `scan --mode hosted` to normalize the redirect, or restore the \
             registry wiring manually, then re-run"
        ));
    }
    let Some(obj) = entry.as_object_mut() else {
        return Err(format!("the {path} entry `{key}` is not an object"));
    };
    for (f, orig) in [("resolved", orig_res), ("integrity", orig_int)] {
        if orig.is_null() {
            obj.remove(f);
        } else {
            obj.insert(f.to_string(), orig);
        }
    }
    Ok(true)
}

/// Recursive twin of the rewriter's `rewrite_npm_v2_deps` walk: replay the
/// edit's originals over every legacy `dependencies` node for this
/// name+version. Bundled nodes mirror the rewriter's skip — they were never
/// rewritten, so their registry-shaped (or absent) values must not read as
/// drift.
fn revert_v2_deps(
    deps: &mut serde_json::Map<String, Value>,
    name: &str,
    version: &str,
    edit: &FileEdit,
    path: &str,
    any_found: &mut bool,
    changed: &mut bool,
) -> Result<(), String> {
    for (dep_name, entry) in deps.iter_mut() {
        if dep_name == name
            && entry.get("version").and_then(Value::as_str) == Some(version)
            && entry.get("bundled").and_then(Value::as_bool) != Some(true)
        {
            *any_found = true;
            if replay_resolved_integrity(entry, edit, path, dep_name)? {
                *changed = true;
            }
        }
        if let Some(nested) = entry.get_mut("dependencies").and_then(Value::as_object_mut) {
            revert_v2_deps(nested, name, version, edit, path, any_found, changed)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::schema::PatchRecord;
    use std::collections::BTreeMap;
    use std::collections::HashMap;

    const UUID: &str = "6b7c8d9e-0f1a-4a1b-8c2d-3e4f5a6b7c8d";
    const PURL: &str = "pkg:cargo/cfg-if@1.0.4";
    const INDEX: &str = "sparse+http://127.0.0.1:5555/index/";
    const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

    fn record() -> PatchRecord {
        PatchRecord {
            uuid: UUID.to_string(),
            exported_at: String::new(),
            files: HashMap::new(),
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    fn pristine_toml() -> String {
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ncfg-if = \"1.0\"\n"
            .to_string()
    }

    fn pristine_lock_block() -> String {
        format!(
            "[[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"{CRATES_IO}\"\nchecksum = \"{}\"",
            "9".repeat(64)
        )
    }

    /// Run the real hosted rewriter over a pristine project, write its output
    /// to a tempdir, and return the resulting ledger — the exact state the
    /// takeover revert consumes in production.
    async fn redirected_fixture() -> (tempfile::TempDir, RedirectState) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let lock = format!(
            "# This file is automatically @generated by Cargo.\nversion = 4\n\n{}\n",
            pristine_lock_block()
        );
        let mut files: BTreeMap<String, String> = BTreeMap::new();
        files.insert("Cargo.toml".into(), pristine_toml());
        files.insert("Cargo.lock".into(), lock.clone());
        let dep: crate::patch::redirect::DepOverride = serde_json::from_value(serde_json::json!({
            "ecosystem": "cargo",
            "name": "cfg-if",
            "version": "1.0.4",
            "token": "tok",
            "patchUuid": UUID,
            "artifactUrl": format!("http://127.0.0.1:5555/cfg-if-1.0.4.crate"),
            "registryOverride": {
                "kind": "cargo-sparse",
                "indexUrl": INDEX,
                "identifiers": {
                    "name": "cfg-if", "version": "1.0.4",
                    "cargoCksumSha256": "a".repeat(64),
                },
            },
            "integrity": { "sha256": "a".repeat(64) },
        }))
        .unwrap();
        let rewrite = crate::patch::redirect::rewrite_registry_redirect(&files, &[dep]);
        tokio::fs::write(root.join("Cargo.toml"), &pristine_toml())
            .await
            .unwrap();
        tokio::fs::write(root.join("Cargo.lock"), &lock)
            .await
            .unwrap();
        for (rel, content) in &rewrite.files {
            let path = root.join(rel);
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await.unwrap();
            }
            tokio::fs::write(&path, content).await.unwrap();
        }
        let mut state = RedirectState::new();
        state.edits = rewrite.edits;
        state.records.insert(PURL.to_string(), record());
        (tmp, state)
    }

    #[tokio::test]
    async fn reverts_toml_lock_and_registry_block_and_drops_ledger_entries() {
        let (tmp, mut state) = redirected_fixture().await;
        let root = tmp.path();
        // Sanity: the fixture really is hosted-wired.
        let toml = tokio::fs::read_to_string(root.join("Cargo.toml"))
            .await
            .unwrap();
        assert!(toml.contains("socket-patch-"), "{toml}");

        let out = revert_cargo_redirect_purl(root, &mut state, PURL)
            .await
            .expect("revert succeeds");
        assert!(!out.reverted_files.is_empty());

        let toml = tokio::fs::read_to_string(root.join("Cargo.toml"))
            .await
            .unwrap();
        assert_eq!(toml, pristine_toml(), "Cargo.toml restored byte-identical");
        let lock = tokio::fs::read_to_string(root.join("Cargo.lock"))
            .await
            .unwrap();
        assert!(
            lock.contains(CRATES_IO),
            "crates.io source restored: {lock}"
        );
        assert!(!lock.contains("sparse+"), "hosted index gone: {lock}");
        assert!(
            !root.join(".cargo/config.toml").exists(),
            "socket-only config removed"
        );
        assert!(state.records.is_empty(), "record dropped");
        assert!(state.edits.is_empty(), "edits dropped");
    }

    #[tokio::test]
    async fn preserves_user_config_content_when_removing_the_registry_block() {
        let (tmp, mut state) = redirected_fixture().await;
        let root = tmp.path();
        // Prepend user content to the config the rewrite created.
        let cfg_path = root.join(".cargo/config.toml");
        let cfg = tokio::fs::read_to_string(&cfg_path).await.unwrap();
        tokio::fs::write(&cfg_path, format!("[net]\nretry = 2\n{cfg}"))
            .await
            .unwrap();

        revert_cargo_redirect_purl(root, &mut state, PURL)
            .await
            .expect("revert succeeds");
        let cfg = tokio::fs::read_to_string(&cfg_path).await.unwrap();
        assert!(cfg.contains("[net]"), "user content kept: {cfg}");
        assert!(!cfg.contains("socket-patch-"), "block removed: {cfg}");
    }

    #[tokio::test]
    async fn refuses_on_drifted_lock_fail_closed() {
        let (tmp, mut state) = redirected_fixture().await;
        let root = tmp.path();
        // A third party re-resolved the lock to a shape the ledger never saw.
        tokio::fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"registry+https://corp.example/index\"\n",
        )
        .await
        .unwrap();
        let records_before = state.records.len();
        let edits_before = state.edits.len();

        let err = revert_cargo_redirect_purl(root, &mut state, PURL)
            .await
            .expect_err("drifted lock must refuse");
        assert!(err.contains("drifted"), "{err}");
        // The ledger keeps everything on refusal.
        assert_eq!(state.records.len(), records_before);
        assert_eq!(state.edits.len(), edits_before);
    }

    /// The unwind runs newest-first (edits are recorded config, manifest,
    /// lock), so Cargo.lock's inverse resolves BEFORE Cargo.toml's. Drifting
    /// only Cargo.toml therefore refuses at a point where the lock's inverse
    /// has already been decided — and the caller reports the purl as
    /// untouched ("cannot vendor over the live hosted redirect"), so a
    /// revert that had written the lock by then would leave the project
    /// half-hosted behind a message saying nothing happened.
    #[tokio::test]
    async fn a_later_drifted_edit_leaves_every_earlier_file_untouched() {
        let (tmp, mut state) = redirected_fixture().await;
        let root = tmp.path();
        let drifted_toml =
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ncfg-if = { version = \"1.0\", registry = \"corp-mirror\" }\n";
        tokio::fs::write(root.join("Cargo.toml"), drifted_toml)
            .await
            .unwrap();
        let lock_before = tokio::fs::read_to_string(root.join("Cargo.lock"))
            .await
            .unwrap();
        let cfg_before = tokio::fs::read_to_string(root.join(".cargo/config.toml"))
            .await
            .unwrap();
        assert!(
            lock_before.contains("sparse+"),
            "fixture is hosted-wired: {lock_before}"
        );

        let err = revert_cargo_redirect_purl(root, &mut state, PURL)
            .await
            .expect_err("drifted manifest must refuse");
        assert!(err.contains("drifted"), "{err}");

        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_before,
            "Cargo.lock must be untouched — its inverse resolved before the refusal"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.toml"))
                .await
                .unwrap(),
            drifted_toml,
            "Cargo.toml untouched"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(".cargo/config.toml"))
                .await
                .unwrap(),
            cfg_before,
            ".cargo/config.toml untouched"
        );
        assert!(!state.records.is_empty(), "ledger keeps the record");
        assert!(!state.edits.is_empty(), "ledger keeps the edits");
    }

    #[tokio::test]
    async fn missing_record_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = RedirectState::new();
        let err = revert_cargo_redirect_purl(tmp.path(), &mut state, PURL)
            .await
            .expect_err("no record");
        assert!(err.contains("records no hosted redirect"), "{err}");
    }

    // ── npm family ───────────────────────────────────────────────────────

    const NPM_PURL: &str = "pkg:npm/left-pad@1.3.0";
    const NPM_URL: &str =
        "http://127.0.0.1:5555/patch/npm/left-pad/1.3.0/tok/6b7c/left-pad-1.3.0.tgz";

    fn npm_dep() -> crate::patch::redirect::DepOverride {
        serde_json::from_value(serde_json::json!({
            "ecosystem": "npm",
            "name": "left-pad",
            "version": "1.3.0",
            "token": "tok",
            "patchUuid": UUID,
            "artifactUrl": NPM_URL,
            "integrity": {
                "sha512": format!("sha512-{}==", "B".repeat(86)),
                "sha1": "1".repeat(40),
                "yarnBerry10c0": format!("10c0/{}", "b".repeat(128)),
            },
        }))
        .unwrap()
    }

    /// Run the real hosted rewriter over one pristine lock, write its output
    /// to a tempdir, and return the resulting ledger — the exact state the
    /// takeover revert consumes in production.
    async fn npm_redirected_fixture(
        rel: &str,
        pristine: &str,
    ) -> (tempfile::TempDir, RedirectState) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut files: BTreeMap<String, String> = BTreeMap::new();
        files.insert(rel.to_string(), pristine.to_string());
        let rewrite = crate::patch::redirect::rewrite_registry_redirect(&files, &[npm_dep()]);
        let rewritten = rewrite
            .files
            .get(rel)
            .unwrap_or_else(|| panic!("rewriter must rewrite {rel}: {:?}", rewrite.warnings));
        tokio::fs::write(root.join(rel), rewritten).await.unwrap();
        let mut state = RedirectState::new();
        state.edits = rewrite.edits;
        state.records.insert(NPM_PURL.to_string(), record());
        (tmp, state)
    }

    fn classic_pristine() -> String {
        "# yarn lockfile v1\n\n\nleft-pad@1.3.0:\n  version \"1.3.0\"\n  resolved \
         \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a\"\n  \
         integrity sha512-original==\n"
            .to_string()
    }

    fn berry_pristine() -> String {
        "# This file is generated by running \"yarn install\" inside your project.\n\n\
         __metadata:\n  version: 8\n  cacheKey: 10c0\n\n\
         \"left-pad@npm:1.3.0\":\n  version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n  \
         checksum: 10c0/cccc\n  languageName: node\n  linkType: hard\n"
            .to_string()
    }

    /// Pristine package-lock (lockfileVersion 2: BOTH the v3 `packages` map
    /// and the legacy v2 `dependencies` tree), serialized exactly as the
    /// rewriter serializes, so the revert round-trip is byte-comparable.
    fn package_lock_pristine() -> String {
        let lock = serde_json::json!({
            "name": "app",
            "version": "1.0.0",
            "lockfileVersion": 2,
            "requires": true,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                    "integrity": "sha512-pristine=="
                }
            },
            "dependencies": {
                "left-pad": {
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                    "integrity": "sha512-pristine=="
                }
            }
        });
        format!("{}\n", serde_json::to_string_pretty(&lock).unwrap())
    }

    #[test]
    fn revert_supported_gate_covers_cargo_and_npm_only() {
        assert!(redirect_revert_supported("pkg:cargo/cfg-if@1.0.4"));
        assert!(redirect_revert_supported("pkg:npm/left-pad@1.3.0"));
        assert!(redirect_revert_supported("pkg:npm/%40scope/x@1.0.0"));
        assert!(!redirect_revert_supported("pkg:gem/rack@3.0.0"));
        assert!(!redirect_revert_supported("pkg:pypi/flask@2.0.0"));
    }

    #[tokio::test]
    async fn npm_classic_lock_round_trips_and_drops_ledger_entries() {
        let (tmp, mut state) = npm_redirected_fixture("yarn.lock", &classic_pristine()).await;
        let root = tmp.path();
        let wired = tokio::fs::read_to_string(root.join("yarn.lock"))
            .await
            .unwrap();
        assert!(wired.contains(NPM_URL), "fixture is hosted-wired: {wired}");

        let out = revert_redirect_purl(root, &mut state, NPM_PURL)
            .await
            .expect("revert succeeds");
        assert_eq!(out.reverted_files, vec!["yarn.lock".to_string()]);
        assert_eq!(
            tokio::fs::read_to_string(root.join("yarn.lock"))
                .await
                .unwrap(),
            classic_pristine(),
            "yarn.lock restored byte-identical"
        );
        assert!(state.records.is_empty(), "record dropped");
        assert!(state.edits.is_empty(), "edits dropped");
    }

    #[tokio::test]
    async fn npm_berry_lock_round_trips_and_drops_ledger_entries() {
        let (tmp, mut state) = npm_redirected_fixture("yarn.lock", &berry_pristine()).await;
        let root = tmp.path();
        let wired = tokio::fs::read_to_string(root.join("yarn.lock"))
            .await
            .unwrap();
        assert!(
            wired.contains("::__archiveUrl="),
            "fixture is hosted-wired: {wired}"
        );

        revert_redirect_purl(root, &mut state, NPM_PURL)
            .await
            .expect("revert succeeds");
        assert_eq!(
            tokio::fs::read_to_string(root.join("yarn.lock"))
                .await
                .unwrap(),
            berry_pristine(),
            "yarn.lock restored byte-identical"
        );
        assert!(state.records.is_empty(), "record dropped");
        assert!(state.edits.is_empty(), "edits dropped");
    }

    #[tokio::test]
    async fn npm_package_lock_v2_round_trips_both_trees() {
        let (tmp, mut state) =
            npm_redirected_fixture("package-lock.json", &package_lock_pristine()).await;
        let root = tmp.path();
        assert_eq!(state.edits.len(), 2, "packages + dependencies edits");
        let wired = tokio::fs::read_to_string(root.join("package-lock.json"))
            .await
            .unwrap();
        assert!(wired.contains(NPM_URL), "fixture is hosted-wired: {wired}");

        revert_npm_redirect_purl(root, &mut state, NPM_PURL)
            .await
            .expect("revert succeeds");
        assert_eq!(
            tokio::fs::read_to_string(root.join("package-lock.json"))
                .await
                .unwrap(),
            package_lock_pristine(),
            "package-lock.json restored byte-identical (both trees)"
        );
        assert!(state.records.is_empty(), "record dropped");
        assert!(state.edits.is_empty(), "edits dropped");
    }

    #[tokio::test]
    async fn npm_refuses_on_drifted_lock_fail_closed() {
        let (tmp, mut state) = npm_redirected_fixture("yarn.lock", &classic_pristine()).await;
        let root = tmp.path();
        // A third party re-resolved the entry to a shape the ledger never saw.
        let drifted = classic_pristine().replace(
            "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a",
            "https://corp.example/left-pad-1.3.0.tgz#dead",
        );
        tokio::fs::write(root.join("yarn.lock"), &drifted)
            .await
            .unwrap();
        let records_before = state.records.len();
        let edits_before = state.edits.len();

        let err = revert_npm_redirect_purl(root, &mut state, NPM_PURL)
            .await
            .expect_err("drifted lock must refuse");
        assert!(err.contains("drifted"), "{err}");
        // The ledger keeps everything on refusal, and the file is untouched.
        assert_eq!(state.records.len(), records_before);
        assert_eq!(state.edits.len(), edits_before);
        assert_eq!(
            tokio::fs::read_to_string(root.join("yarn.lock"))
                .await
                .unwrap(),
            drifted
        );
    }

    #[tokio::test]
    async fn npm_missing_record_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = RedirectState::new();
        let err = revert_npm_redirect_purl(tmp.path(), &mut state, NPM_PURL)
            .await
            .expect_err("no record");
        assert!(err.contains("records no hosted redirect"), "{err}");
    }

    #[tokio::test]
    async fn npm_bun_lock_edit_is_a_fail_closed_refusal() {
        // The bun revert is not implemented; a ledger claiming this purl via
        // a bun.lock edit must refuse rather than drop the record while
        // stranding the edit.
        let tmp = tempfile::tempdir().unwrap();
        let mut state = RedirectState::new();
        state.records.insert(NPM_PURL.to_string(), record());
        state.edits.push(FileEdit {
            path: "bun.lock".into(),
            kind: "redirect_bun_lock_package".into(),
            action: "rewritten".into(),
            key: Some("left-pad".into()),
            original: Some(Value::String(
                "    \"left-pad\": [\"left-pad@1.3.0\", \"reg\", {}, \"sha512-p==\"],".into(),
            )),
            new: Some(Value::String(format!(
                "    \"left-pad\": [\"left-pad@{NPM_URL}\", {{}}, \"sha512-h==\"],"
            ))),
        });
        let err = revert_npm_redirect_purl(tmp.path(), &mut state, NPM_PURL)
            .await
            .expect_err("bun edits must refuse");
        assert!(err.contains("bun.lock"), "{err}");
        assert!(!state.records.is_empty(), "ledger keeps the record");
        assert!(!state.edits.is_empty(), "ledger keeps the edit");
    }
}
