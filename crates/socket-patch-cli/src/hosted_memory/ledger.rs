//! The redirect ledger (`.socket/vendor/redirect-state.json`) in memory:
//! loaded strictly (a malformed ledger is a project error, never a fresh
//! start), merged exactly like the disk flow (edits appended unless already
//! recorded, `REBASE_KINDS` rebased, records extended newest-wins), and
//! serialized with the disk writer's bytes (`to_vec_pretty` + `\n`).

use std::collections::BTreeMap;

use socket_patch_core::manifest::schema::PatchRecord;
use socket_patch_core::patch::redirect::{
    CorruptRedirectState, FileEdit, RedirectState, REDIRECT_STATE_REL,
};
use socket_patch_core::vendor::lock_inventory::{MemoryEntry, MemoryProject};

use crate::commands::scan::hosted::{rebase_vlt_edits, REBASE_KINDS};

/// Load the project's ledger: `Ok(None)` when absent, `Err` (the disk
/// message) when present but unreadable or malformed.
pub(crate) fn load(project: &MemoryProject, root: &str) -> Result<Option<RedirectState>, String> {
    let path = super::roots::join_root(root, REDIRECT_STATE_REL);
    let corrupt = |detail: String, unreadable: bool| {
        CorruptRedirectState {
            path: path.clone().into(),
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

/// Merge this run's `edits` and `records` into `ledger` (the disk flow's
/// merge, verbatim). `files` are the pre-rewrite candidate contents the
/// rebase drift check reads.
pub(crate) fn merge(
    ledger: &mut RedirectState,
    edits: &[FileEdit],
    records: BTreeMap<String, PatchRecord>,
    files: &BTreeMap<String, String>,
) {
    ledger.mode = "hosted".to_string();
    let vlt_merged = rebase_vlt_edits(
        &mut ledger.edits,
        edits,
        files
            .get(socket_patch_core::constants::npm_family::VLT_LOCK)
            .map(String::as_str),
    );
    let mut rebased: Vec<usize> = Vec::new();
    for edit in edits.iter().filter(|e| {
        REBASE_KINDS.contains(&e.kind.as_str())
            && e.kind != socket_patch_core::patch::redirect::vlt::KIND
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
        let nth = edits
            .iter()
            .filter(|e| e.path == edit.path && e.kind == edit.kind && e.key == edit.key)
            .position(|e| std::ptr::eq(e, edit))
            .unwrap_or(0);
        if let Some(&target) = siblings.get(nth) {
            if !rebased.contains(&target) {
                if edit.kind == "redirect_pdm_lock_package" {
                    ledger.edits[target].original = edit.original.clone();
                }
                ledger.edits[target].new = edit.new.clone();
                ledger.edits[target].action = edit.action.clone();
                rebased.push(target);
            }
        }
    }
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

/// The ledger's on-disk bytes.
pub(crate) fn serialize(ledger: &RedirectState) -> Result<String, String> {
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
        assert!(load(&p, "").unwrap().is_none());
        p.insert_text(REDIRECT_STATE_REL, "{not json");
        let err = load(&p, "sub").unwrap_err();
        assert!(
            err.contains("sub/.socket/vendor/redirect-state.json"),
            "{err}"
        );
        assert!(err.contains("malformed"), "{err}");
        p.insert_symlink(REDIRECT_STATE_REL);
        assert!(load(&p, "").unwrap_err().contains("cannot be read"));
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
