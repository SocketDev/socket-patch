//! Cross-mode takeover: per-purl revert of a HOSTED cargo redirect, driven by
//! the redirect ledger's recorded [`FileEdit`]s.
//!
//! The vendored flows (`vendor`, `scan --mode vendored`) call this BEFORE
//! vendoring a package the hosted redirect ledger still claims, so a
//! hosted→vendored migration leaves the project FULLY in vendored mode:
//! Cargo.toml loses its `registry = "socket-patch-…"` pin, Cargo.lock gets its
//! original crates.io `source`/`checksum` back (so the subsequent vendor
//! detach records the PRISTINE originals in the vendor ledger, not the hosted
//! values), and the now-unused `[registries.socket-patch-…]` block is dropped.
//! Without this, `[patch.crates-io]` cannot even apply (it only patches
//! crates-io-sourced deps) and the project is unbuildable in both modes.
//!
//! FAIL CLOSED: a file that matches neither the recorded redirected fragment
//! nor the recorded original has drifted — the revert refuses (`Err`) rather
//! than half-applying, and the caller must then refuse to vendor that purl.

use std::collections::HashSet;
use std::path::Path;

use serde_json::Value;

use crate::utils::purl::{normalize_purl, parse_cargo_purl, strip_purl_qualifiers};

use super::state::RedirectState;
use super::FileEdit;

/// What [`revert_cargo_redirect_purl`] rewrote.
#[derive(Debug, Default)]
pub struct CargoRedirectRevert {
    /// Repo-relative files this revert actually rewrote or removed.
    pub reverted_files: Vec<String>,
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
) -> Result<CargoRedirectRevert, String> {
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

    let mut out = CargoRedirectRevert::default();
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
                let Some(content) = read_rel(project_root, &edit.path).await? else {
                    return Err(format!(
                        "{} no longer exists; cannot revert the recorded hosted \
                         redirect for {name}@{version}",
                        edit.path
                    ));
                };
                if content.contains(new) {
                    let reverted = content.replacen(new, orig, 1);
                    write_rel(project_root, &edit.path, &reverted).await?;
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
                let Some(content) = read_rel(project_root, &edit.path).await? else {
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
                    if let Some(text) = read_rel(project_root, probe).await? {
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
                let mut trimmed = content.replacen(block, "", 1);
                // Collapse the blank separator the rewrite inserted.
                while trimmed.contains("\n\n\n") {
                    trimmed = trimmed.replace("\n\n\n", "\n\n");
                }
                let trimmed = trimmed.trim_start_matches('\n').to_string();
                if trimmed.trim().is_empty() {
                    let path = project_root.join(&edit.path);
                    match tokio::fs::remove_file(&path).await {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(format!("remove {}: {e}", edit.path)),
                    }
                    // Best-effort: prune a now-empty `.cargo/` dir.
                    if let Some(parent) = path.parent() {
                        let _ = tokio::fs::remove_dir(parent).await;
                    }
                } else {
                    write_rel(project_root, &edit.path, &trimmed).await?;
                }
                out.reverted_files.push(edit.path.clone());
            }
            _ => {}
        }
    }

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

    #[tokio::test]
    async fn missing_record_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = RedirectState::new();
        let err = revert_cargo_redirect_purl(tmp.path(), &mut state, PURL)
            .await
            .expect_err("no record");
        assert!(err.contains("records no hosted redirect"), "{err}");
    }
}
