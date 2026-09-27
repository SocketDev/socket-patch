//! The hosted redirect ledger (`.socket/vendor/redirect-state.json`) delta:
//! how a run's recorded edits and patch records merge into the loaded
//! ledger (edits appended unless already recorded, [`REBASE_KINDS`]
//! rebased, records extended newest-wins), plus the in-memory load and the
//! disk writer's bytes. Kept apart from the engine ([`super::engine`]) so
//! the engine never depends on the ledger: a caller that no longer keeps
//! one simply never calls into this module.

use std::collections::BTreeMap;

use crate::manifest::schema::PatchRecord;
use crate::patch::redirect::{CorruptRedirectState, FileEdit, RedirectState, REDIRECT_STATE_REL};
use crate::vendor::lock_inventory::{MemoryEntry, MemoryProject};

/// Fragment-edit kinds whose lockfile the package manager re-lays in place
/// (keeping the Socket source) — a re-scan REBASES their ledger edits instead
/// of appending; see the ledger merge below.
pub const REBASE_KINDS: &[&str] = &[
    "redirect_poetry_lock_package",
    "redirect_pdm_lock_package",
    crate::patch::redirect::vlt::KIND,
];


/// Merge this run's vlt node edits into the recorded ones. A fresh edit
/// for the same `key` and DepID keeps the oldest recorded `original` (the
/// pristine registry entry), takes the fresh `new` and drops the chain's
/// later links (a server-written ledger appends one per hosted PR). One
/// whose recorded same-key edits all name DepIDs the pre-run lock no longer
/// holds (a re-lock, or a new id grammar after a vlt upgrade) replaces
/// them. So does one for another key of the same `name@version` whose
/// vanished recorded edit's pin vlt carried to the fresh DepID (a new peer
/// context). A replacing edit keeps the recorded pristine slots when vlt
/// carried the pin ([`carried_pin_original`]). Returns, per fresh edit,
/// whether it was merged (anything else is appended as usual).
pub fn rebase_vlt_edits(
    ledger: &mut Vec<crate::patch::redirect::FileEdit>,
    fresh: &[crate::patch::redirect::FileEdit],
    before_lock: Option<&str>,
) -> Vec<bool> {
    use crate::patch::redirect::vlt::{
        carried_pin_original, edit_dep_id, lock_node_ids, KIND,
    };
    use crate::patch::redirect::FileEdit;
    fn superseding(edit: &FileEdit, old: &FileEdit) -> FileEdit {
        let mut next = edit.clone();
        if let Some(original) = carried_pin_original(edit, old) {
            next.original = Some(original);
        }
        next
    }
    fn key_base(key: &Option<String>) -> Option<&str> {
        key.as_deref()
            .map(|k| k.split_once('~').map_or(k, |(base, _)| base))
    }
    let live = before_lock.and_then(lock_node_ids).unwrap_or_default();
    let mut merged = vec![false; fresh.len()];
    for (i, edit) in fresh.iter().enumerate() {
        if edit.kind != KIND {
            continue;
        }
        let id = edit_dep_id(edit);
        let same_key: Vec<usize> = ledger
            .iter()
            .enumerate()
            .filter(|(_, old)| old.kind == KIND && old.path == edit.path && old.key == edit.key)
            .map(|(j, _)| j)
            .collect();
        let same_dep: Vec<usize> = same_key
            .iter()
            .copied()
            .filter(|&j| id.is_some() && edit_dep_id(&ledger[j]) == id)
            .collect();
        if let Some((&first, rest)) = same_dep.split_first() {
            ledger[first].new = edit.new.clone();
            ledger[first].action = edit.action.clone();
            for &j in rest.iter().rev() {
                ledger.remove(j);
            }
            merged[i] = true;
            continue;
        }
        let vanished = |j: &usize| edit_dep_id(&ledger[*j]).is_none_or(|old| !live.contains(&old));
        let gone: Vec<usize> = same_key.into_iter().filter(vanished).collect();
        if let Some((&first, rest)) = gone.split_first() {
            ledger[first] = superseding(edit, &ledger[first]);
            for &j in rest.iter().rev() {
                ledger.remove(j);
            }
            merged[i] = true;
            continue;
        }
        let rekeyed = (0..ledger.len()).find(|j| {
            let old = &ledger[*j];
            old.kind == KIND
                && old.path == edit.path
                && old.key != edit.key
                && key_base(&old.key) == key_base(&edit.key)
                && vanished(j)
                && carried_pin_original(edit, old).is_some()
        });
        if let Some(j) = rekeyed {
            ledger[j] = superseding(edit, &ledger[j]);
            merged[i] = true;
        }
    }
    merged
}

/// Merge this run's `edits` and `records` into `ledger`. `files` are the
/// pre-rewrite candidate contents the rebase drift check reads.
///
/// REBASE instead of append for fragment kinds whose file the package
/// manager itself rewrites in place: when the ledger already holds edits
/// for the same (path, kind, key) and the file no longer carried their
/// `new` fragments before this run (Poetry 1.1/1.2 `poetry lock
/// --no-update` keeps the Socket source but re-lays the unit and drops the
/// inserted `files` line), appending this run's edits — recorded against
/// the RELOCKED text — would build a chain whose older links match nothing,
/// so rollback and remove refuse forever. Keeping the oldest `original`
/// (the pristine fragment) and adopting the fresh `new` keeps the chain a
/// single invertible link: replay swaps the fragment this run wrote back
/// to the fragment the very first run found.
pub fn merge(
    ledger: &mut RedirectState,
    edits: &[FileEdit],
    records: BTreeMap<String, PatchRecord>,
    files: &BTreeMap<String, String>,
) {
    // Older ledgers carry `"mode": "redirect"`; normalize on rewrite (the
    // loader accepts either).
    ledger.mode = "hosted".to_string();
    let vlt_merged = rebase_vlt_edits(
        &mut ledger.edits,
        edits,
        files
            .get(crate::constants::npm_family::VLT_LOCK)
            .map(String::as_str),
    );
    let mut rebased: Vec<usize> = Vec::new();
    for edit in edits.iter().filter(|e| {
        REBASE_KINDS.contains(&e.kind.as_str()) && e.kind != crate::patch::redirect::vlt::KIND
    }) {
        let siblings: Vec<usize> = ledger
            .edits
            .iter()
            .enumerate()
            .filter(|(_, old)| {
                old.path == edit.path && old.kind == edit.kind && old.key == edit.key
            })
            .map(|(i, _)| i)
            .collect();
        let before = files.get(&edit.path).map(String::as_str).unwrap_or("");
        let drifted = !siblings.is_empty()
            && siblings.iter().all(|&i| {
                ledger.edits[i]
                    .new
                    .as_ref()
                    .and_then(serde_json::Value::as_str)
                    .is_none_or(|new| !before.contains(new))
            });
        if !drifted {
            continue;
        }
        // Positional pairing: the rewriter emits a key's fragments in a
        // fixed order (package unit, then the legacy integrity entry).
        let nth = edits
            .iter()
            .filter(|e| e.path == edit.path && e.kind == edit.kind && e.key == edit.key)
            .position(|e| std::ptr::eq(e, edit))
            .unwrap_or(0);
        if let Some(&target) = siblings.get(nth) {
            if !rebased.contains(&target) {
                // `pdm lock` fully un-patches the lock (registry source
                // restored) and may reflow line endings (CRLF → LF), so the
                // fresh run's `original` IS the correct relocked-registry
                // rollback target and the stale recorded one would restore a
                // mismatched fragment. Poetry's relock instead KEEPS the
                // Socket source (it only drops the inserted `files` line), so
                // its oldest `original` — the true pre-patch fragment — must
                // survive; only its `new` is refreshed.
                if edit.kind == "redirect_pdm_lock_package" {
                    ledger.edits[target].original = edit.original.clone();
                }
                ledger.edits[target].new = edit.new.clone();
                ledger.edits[target].action = edit.action.clone();
                rebased.push(target);
            }
        }
    }
    // Dedup against the ledger as this run found it, never within this
    // run: one run legitimately records identical edits (a Cargo.toml
    // declaring the crate with the same line in two sections), and each one
    // reverts one occurrence.
    let recorded = ledger.edits.len();
    for (i, edit) in edits.iter().enumerate() {
        if vlt_merged[i] {
            continue;
        }
        let is_rebased = REBASE_KINDS.contains(&edit.kind.as_str())
            && rebased.iter().any(|&t| {
                let old = &ledger.edits[t];
                old.path == edit.path
                    && old.kind == edit.kind
                    && old.key == edit.key
                    && old.new == edit.new
            });
        if !is_rebased && !ledger.edits[..recorded].contains(edit) {
            ledger.edits.push(edit.clone());
        }
    }
    ledger.records.extend(records);
}

/// Load an in-memory project's ledger: `Ok(None)` when absent, `Err` (the
/// disk loader's message, naming `display_path`) when present but
/// unreadable or malformed.
pub fn load_memory(
    project: &MemoryProject,
    display_path: &str,
) -> Result<Option<RedirectState>, String> {
    let corrupt = |detail: String, unreadable: bool| {
        CorruptRedirectState {
            path: display_path.into(),
            detail,
            quarantined_to: None,
            unreadable,
        }
        .to_string()
    };
    let bytes: &[u8] = match project.get(REDIRECT_STATE_REL) {
        None => return Ok(None),
        Some(MemoryEntry::Text(text)) => text.as_bytes(),
        Some(MemoryEntry::Binary(bytes)) => bytes,
        Some(MemoryEntry::Present) => {
            return Err(corrupt("file content was not provided".into(), true))
        }
        Some(MemoryEntry::Symlink) => return Err(corrupt("is a symbolic link".into(), true)),
    };
    serde_json::from_slice(bytes)
        .map(Some)
        .map_err(|e| corrupt(format!("invalid JSON: {e}"), false))
}

/// The ledger's on-disk bytes (the disk writer's `to_vec_pretty` + `\n`).
pub fn serialize(ledger: &RedirectState) -> Result<String, String> {
    let mut bytes = serde_json::to_vec_pretty(ledger).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edit(kind: &str, new: &str) -> FileEdit {
        FileEdit {
            path: "poetry.lock".into(),
            kind: kind.into(),
            action: "replaced".into(),
            key: Some("k".into()),
            original: Some(serde_json::json!("orig")),
            new: Some(serde_json::json!(new)),
        }
    }

    #[test]
    fn corrupt_and_absent_ledgers() {
        let mut p = MemoryProject::new();
        assert!(load_memory(&p, REDIRECT_STATE_REL).unwrap().is_none());
        p.insert_text(REDIRECT_STATE_REL, "{not json");
        let err = load_memory(&p, "sub/.socket/vendor/redirect-state.json").unwrap_err();
        assert!(
            err.contains("sub/.socket/vendor/redirect-state.json"),
            "{err}"
        );
        assert!(err.contains("malformed"), "{err}");
        p.insert_symlink(REDIRECT_STATE_REL);
        assert!(load_memory(&p, REDIRECT_STATE_REL)
            .unwrap_err()
            .contains("cannot be read"));
    }

    #[test]
    fn merge_appends_new_edits_and_rebases_drifted_fragments() {
        let mut ledger = RedirectState::new();
        ledger.edits.push(edit("redirect_npm_lock_entry", "a"));
        ledger
            .edits
            .push(edit("redirect_poetry_lock_package", "old-new"));
        let files = BTreeMap::from([("poetry.lock".to_string(), "relocked".to_string())]);
        merge(
            &mut ledger,
            &[
                edit("redirect_npm_lock_entry", "a"),
                edit("redirect_npm_lock_entry", "b"),
                edit("redirect_poetry_lock_package", "fresh"),
            ],
            BTreeMap::new(),
            &files,
        );
        let news: Vec<&str> = ledger
            .edits
            .iter()
            .map(|e| e.new.as_ref().and_then(|v| v.as_str()).unwrap())
            .collect();
        assert_eq!(news, vec!["a", "fresh", "b"]);
        let text = serialize(&ledger).unwrap();
        assert!(text.ends_with("}\n"));
    }
}
