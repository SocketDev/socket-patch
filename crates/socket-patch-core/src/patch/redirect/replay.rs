//! Whole-ledger reverse replay of hosted-redirect edits.
//!
//! The per-purl reverts in [`super::takeover`] cover cargo and the
//! npm-family lock flavors. Everything else the hosted rewriters touch —
//! gem, golang, pypi, composer, bun, and the non-package rideshare edits
//! (the pnpm `trustLockfile` auto-config, the bun.lockb migration marker) —
//! has no per-purl revert: their unwind rides the ledger's designed
//! whole-list contract ("edits appended in write order, a revert walks
//! them in reverse", see [`super::state`]).
//!
//! [`revert_remaining_redirect_edits`] performs that walk over whatever
//! edits are still in the ledger (callers run the per-purl reverts first;
//! those drop the edits they claim). Each edit kind maps to an inverse in
//! a closed per-kind table; edits are grouped by the ecosystem that wrote
//! them and each GROUP is staged all-or-nothing — one drifted or
//! unhandled edit refuses the whole group byte-untouched (the same
//! fail-closed posture as the per-purl reverts), while other groups still
//! proceed. maven and nuget record structured metadata (not file
//! fragments), so their groups refuse with `hosted_revert_unsupported`
//! until bespoke reverts exist; their records and edits stay in the
//! ledger for a later `scan --mode hosted` normalize.
//!
//! Ledger accounting is per-outcome: successfully replayed (or
//! already-at-original) edits are dropped from `state.edits`; a record is
//! dropped only when every group its ecosystem writes ended clean, so a
//! refused group keeps both its edits and its records — the
//! intermediate-but-coherent ledger a retry needs. The caller persists.

use super::state::RedirectState;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The exact pnpm-workspace.yaml the trust auto-config CREATES when no
/// workspace file existed (see `plan_workspace_trust` in the hosted flow).
/// A `created` trust edit deletes the file only while it still carries
/// exactly this scaffold — anything else means the user built on it, and
/// the revert downgrades to removing the one line it owns.
const PNPM_TRUST_SCAFFOLD: &str = "packages:\n  - '.'\ntrustLockfile: true\n";

/// The single line the trust auto-config APPENDS to an existing
/// pnpm-workspace.yaml (`action: "added"`); its `new` records the VALUE
/// (`"true"`), not the line, so the inverse is kind-specific.
const PNPM_TRUST_LINE: &str = "trustLockfile: true";

/// How one edit kind unwinds.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Inverse {
    /// `original` and `new` are both file fragments (action `rewritten` /
    /// `updated`): restore by replacing `new` with `original` once.
    /// `contains(new)` is checked BEFORE `contains(original)` — several
    /// writers record an `original` that is a substring of `new` (the
    /// Cargo.toml insert variant, the maven version suffix).
    ReplaceFragment,
    /// action `added` with only `new` recorded: the redirect inserted the
    /// fragment into a pre-existing file, so the inverse removes it once
    /// (an absent fragment is the desired end state — no-op).
    RemoveAddedFragment,
    /// action `removed` with only `original` recorded: the redirect
    /// pruned lines the pristine file needs back (go.sum entries of the
    /// upstream module). Re-insert by appending — go.sum lines are
    /// order-insensitive.
    ReinsertRemoved,
    /// Cleanup of PRIOR socket wiring performed during a redirect refresh
    /// (`redirect_golang_stale_*`). The removal already moved the file
    /// toward pristine; restoring it would re-create socket wiring, so
    /// the inverse is a no-op and the edit is simply dropped.
    NoopDrop,
    /// The pnpm `trustLockfile` auto-config (kind-specific: `created`
    /// deletes the scaffold, `added` removes exactly one line).
    PnpmTrust,
    /// bun.lockb was migrated to a text bun.lock; the binary original was
    /// never captured (git history is the restore path). Warn and drop.
    BunLockbMigrated,
    /// Owned by a per-purl revert (npm JSON kinds). Present here only
    /// when that revert failed — refuse the group rather than guess.
    PerPurlOnly,
    /// No revert implementation exists for the recorded shape (maven /
    /// nuget structured metadata, unknown future kinds).
    Unsupported,
}

/// (group label, inverse) for one recorded edit. The group is the
/// all-or-nothing staging unit — every kind an ecosystem writes lands in
/// one group so correlated files (go.mod + go.sum, Gemfile +
/// Gemfile.lock) revert together or not at all.
fn classify(kind: &str, action: &str) -> (&'static str, Inverse) {
    match kind {
        "redirect_requirements_line" | "redirect_uv_lock_wheel" => ("pypi", Inverse::ReplaceFragment),
        "redirect_composer_dist" => ("composer", Inverse::ReplaceFragment),
        "redirect_cargo_toml_dep" | "redirect_cargo_lock_entry" => ("cargo", Inverse::ReplaceFragment),
        "redirect_cargo_registry" => (
            "cargo",
            if action == "added" {
                Inverse::RemoveAddedFragment
            } else {
                Inverse::ReplaceFragment
            },
        ),
        "redirect_pnpm_resolution" => ("pnpm", Inverse::ReplaceFragment),
        "redirect_pnpm_workspace_trust" => ("pnpm", Inverse::PnpmTrust),
        "redirect_yarn_classic_entry" | "redirect_yarn_berry_entry" => {
            ("yarn", Inverse::ReplaceFragment)
        }
        "redirect_bun_lock_package" => ("bun", Inverse::ReplaceFragment),
        "redirect_bun_lockb_migrated" => ("bun", Inverse::BunLockbMigrated),
        "redirect_gemfile_lock_dependency_pin"
        | "redirect_gemfile_lock_checksum"
        | "redirect_gemfile_source_block" => (
            "gem",
            if action == "added" {
                Inverse::RemoveAddedFragment
            } else {
                Inverse::ReplaceFragment
            },
        ),
        "redirect_gemfile_lock_source_url" | "redirect_gemfile_source_url" => {
            ("gem", Inverse::ReplaceFragment)
        }
        // The section-move record: the writer drained the spec (+ sublines)
        // out of its upstream GEM section into a new socket GEM section but
        // recorded only the bare remote URLs — not the moved block — so a
        // URL swap would claim success while leaving the moved spec and the
        // scaffold section in place. Refuse until the writer records enough
        // to invert the move.
        "redirect_gemfile_lock_gem_source" => ("gem", Inverse::Unsupported),
        // "updated" carries the prior socket directive in `original`;
        // the chain unwinds newest-first down to the first run's "added".
        "redirect_golang_replace" => (
            "golang",
            if action == "added" {
                Inverse::RemoveAddedFragment
            } else {
                Inverse::ReplaceFragment
            },
        ),
        "redirect_golang_gosum" => ("golang", Inverse::RemoveAddedFragment),
        "redirect_golang_gosum_prune" => ("golang", Inverse::ReinsertRemoved),
        "redirect_golang_stale_replace_removed" | "redirect_golang_stale_gosum_removed" => {
            ("golang", Inverse::NoopDrop)
        }
        "redirect_npm_lock_entry" | "redirect_npm_lock_dep" => ("npm", Inverse::PerPurlOnly),
        "redirect_maven_repository"
        | "redirect_maven_dep_management"
        | "redirect_maven_config"
        | "redirect_maven_trusted_checksums" => ("maven", Inverse::Unsupported),
        "redirect_maven_dep_version" => ("maven", Inverse::ReplaceFragment),
        "redirect_nuget_source" | "redirect_nuget_lock" => ("nuget", Inverse::Unsupported),
        _ => ("unknown", Inverse::Unsupported),
    }
}

/// The replay groups a record's ecosystem can have written edits into —
/// the drop rule holds a record while ANY of its groups refused. npm
/// purls fan across every npm-family lock flavor.
fn groups_for_record_purl(purl: &str) -> &'static [&'static str] {
    if purl.starts_with("pkg:npm/") {
        &["npm", "yarn", "pnpm", "bun"]
    } else if purl.starts_with("pkg:cargo/") {
        &["cargo"]
    } else if purl.starts_with("pkg:gem/") {
        &["gem"]
    } else if purl.starts_with("pkg:pypi/") {
        &["pypi"]
    } else if purl.starts_with("pkg:composer/") {
        &["composer"]
    } else if purl.starts_with("pkg:golang/") {
        &["golang"]
    } else if purl.starts_with("pkg:maven/") {
        &["maven"]
    } else if purl.starts_with("pkg:nuget/") {
        &["nuget"]
    } else {
        // Unknown ecosystems fail closed: tie them to the reserved
        // "unknown" group, which refuses whenever it holds edits.
        &["unknown"]
    }
}

/// One refused group: its files were left byte-identical and its edits
/// and records stay in the ledger.
#[derive(Debug)]
pub struct GroupRefusal {
    pub group: String,
    pub files: BTreeSet<String>,
    pub reason: String,
}

/// What one replay pass did (or, on dry-run, would do).
#[derive(Debug, Default)]
pub struct ReplayOutcome {
    /// Files whose staged revert flushed (repo-relative), including files
    /// staged for deletion.
    pub reverted_files: BTreeSet<String>,
    /// Groups that refused fail-closed; their edits/records remain.
    pub refusals: Vec<GroupRefusal>,
    /// Advisory (code, detail) pairs — unrestorable bun.lockb, modified
    /// trust scaffold, and similar honest degradations.
    pub warnings: Vec<(String, String)>,
    /// Records dropped from the ledger (purls, sorted by BTreeMap walk).
    pub dropped_records: Vec<String>,
    /// Edits dropped from the ledger.
    pub dropped_edits: usize,
}

impl ReplayOutcome {
    /// True when every group replayed clean (a refusal-free pass).
    pub fn fully_reverted(&self) -> bool {
        self.refusals.is_empty()
    }
}

/// Ledger paths are written by this tool as plain repo-relative slash
/// paths; anything else (absolute, `..`, empty) refuses fail-closed
/// rather than letting a tampered ledger write outside the project.
fn safe_rel_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.starts_with('\\')
        && !path.contains(':')
        && !path.split(['/', '\\']).any(|c| c == "..")
}

/// FIFO-guarded read: a planted FIFO squatting a lockfile path must fail
/// fast (`InvalidInput`) instead of wedging the replay on a blocking open
/// — the same posture as every other raw read in the patch engine.
async fn read_rel(project_root: &Path, rel: &str) -> Result<Option<String>, String> {
    use tokio::io::AsyncReadExt;
    let path = project_root.join(rel);
    let (mut file, _) = match crate::utils::fs::open_regular_file(&path).await {
        Ok(pair) => pair,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read {rel}: {e}")),
    };
    let mut content = String::new();
    file.read_to_string(&mut content)
        .await
        .map_err(|e| format!("read {rel}: {e}"))?;
    Ok(Some(content))
}

/// Files the group's unwind has decided but not yet written:
/// `Some(content)` to write, `None` to delete.
type Staged = BTreeMap<String, Option<String>>;

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

/// Remove one inserted fragment, eating the separators the writer added
/// around it. Position-based: several writers record the fragment WITHOUT
/// the indentation they inserted it with (the gem DEPENDENCIES pin and
/// CHECKSUMS line record `target.trim_start()`), so when everything
/// between the fragment and its line start is whitespace the whole line
/// is removed — a bare `replacen` would strand the orphaned indent onto
/// the NEXT line and corrupt indentation-sensitive locks. An EOF-removed
/// fragment additionally collapses the trailing blank run to the
/// canonical single newline: the append shape (maybe-a-blank-separator +
/// fragment + newline) is byte-AMBIGUOUS to invert — `"m\n\n" + "F\n"`
/// and `"m\n" + "\nF\n"` produce identical files — so the tidy form (the
/// one `go mod tidy` itself emits) is chosen.
fn remove_fragment_once(content: &str, fragment: &str) -> String {
    let Some(pos) = content.find(fragment) else {
        return content.to_string();
    };
    let mut end = pos + fragment.len();
    // The fragment's own indentation, when the writer recorded it stripped.
    let line_start = content[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let start = if content[line_start..pos]
        .chars()
        .all(|c| c == ' ' || c == '\t')
    {
        line_start
    } else {
        pos
    };
    // The removed line's own newline goes with it — but only when the
    // whole line is removed: a fragment spliced out from behind a
    // non-whitespace prefix (the user commented the line out) leaves the
    // prefix as its own line, and eating the newline would join that
    // prefix onto the FOLLOWING line, commenting it out too.
    if start == line_start && content[end..].starts_with('\n') {
        end += 1;
    }
    if end >= content.len() {
        // EOF removal: collapse the (ambiguous) trailing separator run.
        let trimmed = content[..start].trim_end_matches('\n');
        if trimmed.is_empty() {
            return String::new();
        }
        return format!("{trimmed}\n");
    }
    format!("{}{}", &content[..start], &content[end..])
}

/// The string payloads of an edit, or `None` when a payload is missing or
/// not a string (a shape the inverse table said must be there).
fn str_payload(v: &Option<Value>) -> Option<&str> {
    v.as_ref().and_then(Value::as_str)
}

/// Walk every edit still in `state` in reverse write order, grouped per
/// ecosystem, staging each group's inverse and flushing it all-or-nothing.
/// Mutates `state` (drops replayed edits and fully-unwound records) —
/// the CALLER persists via `persist_redirect_state`. With `dry_run` the
/// staging and every drift check run identically, but nothing is written
/// and `state` is left untouched; the outcome reports what a wet run
/// would do.
pub async fn revert_remaining_redirect_edits(
    project_root: &Path,
    state: &mut RedirectState,
    dry_run: bool,
) -> ReplayOutcome {
    let mut outcome = ReplayOutcome::default();

    // Group edit indices by ecosystem, keeping ledger order within each.
    let mut groups: BTreeMap<&'static str, Vec<usize>> = BTreeMap::new();
    for (idx, edit) in state.edits.iter().enumerate() {
        let (group, _) = classify(&edit.kind, &edit.action);
        groups.entry(group).or_default().push(idx);
    }

    let mut drop_indices: BTreeSet<usize> = BTreeSet::new();
    let mut refused_groups: BTreeSet<&'static str> = BTreeSet::new();
    let mut pending_warnings: Vec<(String, String)> = Vec::new();

    'group: for (group, indices) in &groups {
        let mut staged: Staged = BTreeMap::new();
        let mut group_drops: BTreeSet<usize> = BTreeSet::new();
        let mut group_warnings: Vec<(String, String)> = Vec::new();
        let files: BTreeSet<String> = indices
            .iter()
            .map(|&i| state.edits[i].path.clone())
            .collect();

        let refuse = |reason: String, out: &mut ReplayOutcome| {
            out.refusals.push(GroupRefusal {
                group: (*group).to_string(),
                files: files.clone(),
                reason,
            });
        };

        // Newest-first: chained re-redirects unwind through each step's
        // `new` -> `original` until the first run's insertion is removed.
        for &idx in indices.iter().rev() {
            let edit = state.edits[idx].clone();
            let (_, inverse) = classify(&edit.kind, &edit.action);
            if !matches!(
                inverse,
                Inverse::NoopDrop | Inverse::BunLockbMigrated | Inverse::Unsupported
            ) && !safe_rel_path(&edit.path)
            {
                refuse(
                    format!("ledger edit for {} has an unsafe path", edit.kind),
                    &mut outcome,
                );
                refused_groups.insert(group);
                continue 'group;
            }
            match inverse {
                Inverse::NoopDrop => {
                    // Removal of prior socket wiring — already pristine-ward.
                    group_drops.insert(idx);
                }
                Inverse::BunLockbMigrated => {
                    group_warnings.push((
                        "redirect_bun_lockb_unrestorable".into(),
                        "bun.lockb was migrated to a text bun.lock during the redirect and \
                         its binary content was not captured — restore bun.lockb from git \
                         history if the binary format is required"
                            .into(),
                    ));
                    group_drops.insert(idx);
                }
                Inverse::PerPurlOnly => {
                    refuse(
                        format!(
                            "{} is owned by the per-purl npm revert, which did not claim it \
                             (a prior per-purl refusal) — re-run `scan --mode hosted` to \
                             normalize, then roll back again",
                            edit.kind
                        ),
                        &mut outcome,
                    );
                    refused_groups.insert(group);
                    continue 'group;
                }
                Inverse::Unsupported => {
                    refuse(
                        format!(
                            "no hosted-redirect revert implementation for {} — re-run \
                             `scan --mode hosted` to normalize, or restore the file from \
                             version control",
                            edit.kind
                        ),
                        &mut outcome,
                    );
                    refused_groups.insert(group);
                    continue 'group;
                }
                Inverse::ReplaceFragment => {
                    let (Some(original), Some(new)) =
                        (str_payload(&edit.original), str_payload(&edit.new))
                    else {
                        refuse(
                            format!("{} edit is missing its recorded fragments", edit.kind),
                            &mut outcome,
                        );
                        refused_groups.insert(group);
                        continue 'group;
                    };
                    let content = match staged_read(&staged, project_root, &edit.path).await {
                        Ok(Some(c)) => c,
                        Ok(None) => {
                            refuse(
                                format!("{} no longer exists", edit.path),
                                &mut outcome,
                            );
                            refused_groups.insert(group);
                            continue 'group;
                        }
                        Err(e) => {
                            refuse(e, &mut outcome);
                            refused_groups.insert(group);
                            continue 'group;
                        }
                    };
                    // `new` before `original`: original may be a substring
                    // of new (Cargo.toml insert, maven version suffix).
                    if content.contains(new) {
                        if content.matches(new).count() > 1 {
                            refuse(
                                format!(
                                    "{}: the redirected fragment appears more than once — \
                                     ambiguous, refusing to guess",
                                    edit.path
                                ),
                                &mut outcome,
                            );
                            refused_groups.insert(group);
                            continue 'group;
                        }
                        staged.insert(
                            edit.path.clone(),
                            Some(content.replacen(new, original, 1)),
                        );
                        group_drops.insert(idx);
                    } else if content.contains(original) && !new.contains(original) {
                        // Already at the pre-edit state (an interrupted
                        // earlier revert, or a hand-fix) — nothing to do.
                        // The `!new.contains(original)` guard matters:
                        // several writers record an `original` that is a
                        // SUBSTRING of `new` (the Cargo.toml insert variant
                        // records the always-present table header), so its
                        // presence proves nothing about the inserted part —
                        // a drifted insert must refuse, not silently drop
                        // the edit as reverted.
                        group_drops.insert(idx);
                    } else {
                        refuse(
                            format!(
                                "{}: content matches neither the redirected nor the \
                                 original fragment for {} — the file drifted; re-run \
                                 `scan --mode hosted` to normalize",
                                edit.path, edit.kind
                            ),
                            &mut outcome,
                        );
                        refused_groups.insert(group);
                        continue 'group;
                    }
                }
                Inverse::RemoveAddedFragment => {
                    let Some(new) = str_payload(&edit.new) else {
                        refuse(
                            format!("{} edit is missing its recorded fragment", edit.kind),
                            &mut outcome,
                        );
                        refused_groups.insert(group);
                        continue 'group;
                    };
                    match staged_read(&staged, project_root, &edit.path).await {
                        // File gone entirely: the fragment is gone with it.
                        Ok(None) => {
                            group_drops.insert(idx);
                        }
                        Ok(Some(content)) => {
                            if content.contains(new) {
                                if content.matches(new).count() > 1 {
                                    refuse(
                                        format!(
                                            "{}: the added fragment appears more than once — \
                                             ambiguous, refusing to guess",
                                            edit.path
                                        ),
                                        &mut outcome,
                                    );
                                    refused_groups.insert(group);
                                    continue 'group;
                                }
                                staged.insert(
                                    edit.path.clone(),
                                    Some(remove_fragment_once(&content, new)),
                                );
                            }
                            // Absent fragment == already clean.
                            group_drops.insert(idx);
                        }
                        Err(e) => {
                            refuse(e, &mut outcome);
                            refused_groups.insert(group);
                            continue 'group;
                        }
                    }
                }
                Inverse::ReinsertRemoved => {
                    let Some(original) = str_payload(&edit.original) else {
                        refuse(
                            format!("{} edit is missing its recorded lines", edit.kind),
                            &mut outcome,
                        );
                        refused_groups.insert(group);
                        continue 'group;
                    };
                    let content = match staged_read(&staged, project_root, &edit.path).await {
                        Ok(c) => c.unwrap_or_default(),
                        Err(e) => {
                            refuse(e, &mut outcome);
                            refused_groups.insert(group);
                            continue 'group;
                        }
                    };
                    if content.contains(original) {
                        group_drops.insert(idx);
                    } else {
                        let mut restored = content;
                        if !restored.is_empty() && !restored.ends_with('\n') {
                            restored.push('\n');
                        }
                        restored.push_str(original);
                        restored.push('\n');
                        staged.insert(edit.path.clone(), Some(restored));
                        group_drops.insert(idx);
                    }
                }
                Inverse::PnpmTrust => {
                    let content = match staged_read(&staged, project_root, &edit.path).await {
                        Ok(c) => c,
                        Err(e) => {
                            refuse(e, &mut outcome);
                            refused_groups.insert(group);
                            continue 'group;
                        }
                    };
                    match (edit.action.as_str(), content) {
                        // Whatever created it is already gone.
                        (_, None) => {
                            group_drops.insert(idx);
                        }
                        ("created", Some(c)) if c == PNPM_TRUST_SCAFFOLD => {
                            staged.insert(edit.path.clone(), None);
                            group_drops.insert(idx);
                        }
                        // Scaffold grew user content — keep the file, drop
                        // only the line the redirect owns, and say so.
                        (_, Some(c)) => {
                            if c.contains(PNPM_TRUST_LINE) {
                                if c.matches(PNPM_TRUST_LINE).count() > 1 {
                                    refuse(
                                        format!(
                                            "{}: the `{PNPM_TRUST_LINE}` line appears more \
                                             than once — ambiguous, refusing to guess",
                                            edit.path
                                        ),
                                        &mut outcome,
                                    );
                                    refused_groups.insert(group);
                                    continue 'group;
                                }
                                staged.insert(
                                    edit.path.clone(),
                                    Some(remove_fragment_once(&c, PNPM_TRUST_LINE)),
                                );
                                if edit.action == "created" {
                                    group_warnings.push((
                                        "redirect_pnpm_trust_scaffold_modified".into(),
                                        format!(
                                            "{} was created by the hosted redirect but has \
                                             been modified since — kept the file and removed \
                                             only the `trustLockfile: true` line",
                                            edit.path
                                        ),
                                    ));
                                }
                            }
                            group_drops.insert(idx);
                        }
                    }
                }
            }
        }

        // Commit the group: flush staged files (unless dry-run), then mark
        // its edits for dropping. A flush error refuses the group late —
        // some files may already have landed (the same residual exposure
        // the per-purl reverts document) — and keeps its ledger entries.
        if !dry_run {
            for (rel, pending) in &staged {
                let path = project_root.join(rel);
                // FIFO/device guard on the write side too: writing to a
                // planted FIFO blocks forever. Refuse the group instead.
                if let Ok(meta) = tokio::fs::symlink_metadata(&path).await {
                    if !meta.is_file() {
                        refuse(format!("{rel} is not a regular file"), &mut outcome);
                        refused_groups.insert(group);
                        continue 'group;
                    }
                }
                let write_result = match pending {
                    Some(content) => tokio::fs::write(&path, content).await,
                    None => match tokio::fs::remove_file(&path).await {
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                        other => other,
                    },
                };
                if let Err(e) = write_result {
                    refuse(format!("write {rel}: {e}"), &mut outcome);
                    refused_groups.insert(group);
                    continue 'group;
                }
            }
        }
        outcome
            .reverted_files
            .extend(staged.keys().cloned());
        pending_warnings.extend(group_warnings);
        drop_indices.extend(group_drops);
    }

    outcome.warnings.append(&mut pending_warnings);

    if !dry_run {
        // Drop replayed edits (reverse index order keeps indices valid).
        for &idx in drop_indices.iter().rev() {
            state.edits.remove(idx);
            outcome.dropped_edits += 1;
        }
        // Drop each record whose every possible group ended clean.
        let record_purls: Vec<String> = state.records.keys().cloned().collect();
        for purl in record_purls {
            let held = groups_for_record_purl(&purl)
                .iter()
                .any(|g| refused_groups.contains(g));
            if !held {
                state.records.remove(&purl);
                outcome.dropped_records.push(purl);
            }
        }
    } else {
        outcome.dropped_edits = drop_indices.len();
        for purl in state.records.keys() {
            let held = groups_for_record_purl(purl)
                .iter()
                .any(|g| refused_groups.contains(g));
            if !held {
                outcome.dropped_records.push(purl.clone());
            }
        }
    }

    outcome
}

#[cfg(test)]
mod tests {
    use super::super::FileEdit;
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    fn edit(path: &str, kind: &str, action: &str, original: Option<&str>, new: Option<&str>) -> FileEdit {
        FileEdit {
            path: path.into(),
            kind: kind.into(),
            action: action.into(),
            key: Some("k".into()),
            original: original.map(|s| Value::String(s.into())),
            new: new.map(|s| Value::String(s.into())),
        }
    }

    fn state_with(edits: Vec<FileEdit>, record_purls: &[&str]) -> RedirectState {
        let mut state = RedirectState::new();
        state.edits = edits;
        for p in record_purls {
            state
                .records
                .insert((*p).to_string(), crate::manifest::schema::PatchRecord {
                    uuid: "u".into(),
                    exported_at: "now".into(),
                    files: Default::default(),
                    vulnerabilities: Default::default(),
                    description: String::new(),
                    license: String::new(),
                    tier: "free".into(),
                });
        }
        state
    }

    async fn write(root: &Path, rel: &str, content: &str) {
        let p = root.join(rel);
        if let Some(parent) = p.parent() {
            tokio::fs::create_dir_all(parent).await.unwrap();
        }
        tokio::fs::write(p, content).await.unwrap();
    }

    async fn read(root: &Path, rel: &str) -> String {
        tokio::fs::read_to_string(root.join(rel)).await.unwrap()
    }

    // ---------- ReplaceFragment ----------

    #[tokio::test]
    async fn rewritten_fragment_replays_to_original() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "requirements.txt", "left-pad @ https://patch.example/x.whl\n").await;
        let mut state = state_with(
            vec![edit(
                "requirements.txt",
                "redirect_requirements_line",
                "rewritten",
                Some("left-pad==1.3.0"),
                Some("left-pad @ https://patch.example/x.whl"),
            )],
            &["pkg:pypi/left-pad@1.3.0"],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted(), "{:?}", out.refusals);
        assert_eq!(read(dir.path(), "requirements.txt").await, "left-pad==1.3.0\n");
        assert!(state.edits.is_empty());
        assert!(state.records.is_empty());
        assert_eq!(out.dropped_records, vec!["pkg:pypi/left-pad@1.3.0"]);
    }

    #[tokio::test]
    async fn substring_original_checks_new_first() {
        // The maven version-suffix shape: original is a substring of new.
        let dir = TempDir::new().unwrap();
        write(dir.path(), "pom.xml", "<version>2.17.1-socket-abc</version>\n").await;
        let mut state = state_with(
            vec![edit(
                "pom.xml",
                "redirect_maven_dep_version",
                "rewritten",
                Some("2.17.1"),
                Some("2.17.1-socket-abc"),
            )],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted(), "{:?}", out.refusals);
        assert_eq!(read(dir.path(), "pom.xml").await, "<version>2.17.1</version>\n");
    }

    #[tokio::test]
    async fn drifted_fragment_refuses_the_whole_group_untouched() {
        let dir = TempDir::new().unwrap();
        // go.mod drifted; go.sum is revertable — but the golang group is
        // all-or-nothing, so BOTH files stay byte-identical.
        write(dir.path(), "go.mod", "module m\n").await;
        write(dir.path(), "go.sum", "gopatch.socket.dev/x v1 h1:a\n").await;
        let mut state = state_with(
            vec![
                edit(
                    "go.mod",
                    "redirect_golang_replace",
                    "added",
                    None,
                    Some("replace x => gopatch.socket.dev/x v1"),
                ),
                edit(
                    "go.mod",
                    "redirect_golang_replace",
                    "updated",
                    Some("replace x => gopatch.socket.dev/x v0"),
                    Some("replace x => WHAT-THE-FILE-NO-LONGER-HAS"),
                ),
                edit(
                    "go.sum",
                    "redirect_golang_gosum",
                    "added",
                    None,
                    Some("gopatch.socket.dev/x v1 h1:a"),
                ),
            ],
            &["pkg:golang/x@1"],
        );
        let before_mod = read(dir.path(), "go.mod").await;
        let before_sum = read(dir.path(), "go.sum").await;
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert_eq!(out.refusals.len(), 1);
        assert_eq!(out.refusals[0].group, "golang");
        assert_eq!(read(dir.path(), "go.mod").await, before_mod);
        assert_eq!(read(dir.path(), "go.sum").await, before_sum);
        assert_eq!(state.edits.len(), 3, "refused group keeps its edits");
        assert!(
            state.records.contains_key("pkg:golang/x@1"),
            "refused group keeps its records"
        );
    }

    #[tokio::test]
    async fn ambiguous_duplicate_fragment_refuses() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "composer.lock",
            "https://patch.example/a\nhttps://patch.example/a\n",
        )
        .await;
        let mut state = state_with(
            vec![edit(
                "composer.lock",
                "redirect_composer_dist",
                "rewritten",
                Some("https://upstream.example/a"),
                Some("https://patch.example/a"),
            )],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert_eq!(out.refusals.len(), 1);
        assert!(out.refusals[0].reason.contains("more than once"));
    }

    #[tokio::test]
    async fn already_original_content_is_a_noop_drop() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "composer.lock", "https://upstream.example/a\n").await;
        let mut state = state_with(
            vec![edit(
                "composer.lock",
                "redirect_composer_dist",
                "rewritten",
                Some("https://upstream.example/a"),
                Some("https://patch.example/a"),
            )],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted());
        assert!(state.edits.is_empty());
        assert!(out.reverted_files.is_empty(), "nothing was written");
    }

    // ---------- chained re-redirects ----------

    #[tokio::test]
    async fn chained_reredirect_unwinds_newest_first_to_pristine() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "go.mod", "module m\n\nreplace x => gopatch.socket.dev/x v2\n").await;
        let mut state = state_with(
            vec![
                edit(
                    "go.mod",
                    "redirect_golang_replace",
                    "added",
                    None,
                    Some("replace x => gopatch.socket.dev/x v1"),
                ),
                edit(
                    "go.mod",
                    "redirect_golang_replace",
                    "updated",
                    Some("replace x => gopatch.socket.dev/x v1"),
                    Some("replace x => gopatch.socket.dev/x v2"),
                ),
            ],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted(), "{:?}", out.refusals);
        assert_eq!(read(dir.path(), "go.mod").await, "module m\n");
    }

    // ---------- RemoveAddedFragment / ReinsertRemoved ----------

    #[tokio::test]
    async fn golang_round_trip_removes_added_and_reinserts_pruned() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "go.mod",
            "module m\n\nreplace x => gopatch.socket.dev/x v1\n",
        )
        .await;
        write(
            dir.path(),
            "go.sum",
            "gopatch.socket.dev/x v1 h1:a\ngopatch.socket.dev/x v1/go.mod h1:b\n",
        )
        .await;
        let mut state = state_with(
            vec![
                edit(
                    "go.mod",
                    "redirect_golang_replace",
                    "added",
                    None,
                    Some("replace x => gopatch.socket.dev/x v1"),
                ),
                edit(
                    "go.sum",
                    "redirect_golang_gosum",
                    "added",
                    None,
                    Some("gopatch.socket.dev/x v1 h1:a\ngopatch.socket.dev/x v1/go.mod h1:b"),
                ),
                edit(
                    "go.sum",
                    "redirect_golang_gosum_prune",
                    "removed",
                    Some("x v0.9 h1:orig\nx v0.9/go.mod h1:origmod"),
                    None,
                ),
                edit(
                    "go.mod",
                    "redirect_golang_stale_replace_removed",
                    "removed",
                    Some("replace x => gopatch.socket.dev/x v0"),
                    None,
                ),
            ],
            &["pkg:golang/x@0.9"],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted(), "{:?}", out.refusals);
        // The added replace line is gone (its blank separator too — the
        // fragment+newline heuristic), and NOT the stale socket directive.
        let go_mod = read(dir.path(), "go.mod").await;
        assert!(!go_mod.contains("gopatch.socket.dev"), "{go_mod}");
        // Pruned upstream sums are back; the fork's sums are gone.
        let go_sum = read(dir.path(), "go.sum").await;
        assert!(go_sum.contains("x v0.9 h1:orig"));
        assert!(!go_sum.contains("gopatch.socket.dev"));
        assert!(state.edits.is_empty());
        assert!(state.records.is_empty());
    }

    #[tokio::test]
    async fn reinsert_is_idempotent_when_lines_are_already_back() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "go.sum", "x v0.9 h1:orig\n").await;
        let mut state = state_with(
            vec![edit(
                "go.sum",
                "redirect_golang_gosum_prune",
                "removed",
                Some("x v0.9 h1:orig"),
                None,
            )],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted());
        assert_eq!(read(dir.path(), "go.sum").await, "x v0.9 h1:orig\n");
    }

    #[tokio::test]
    async fn gem_added_pin_removal_preserves_sibling_indentation() {
        // The gem writer records the DEPENDENCIES pin / CHECKSUMS line
        // STRIPPED of its two-space indent; removal must take the whole
        // line, never strand the indent onto the next line (which bundler
        // then misparses).
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "Gemfile.lock",
            "DEPENDENCIES\n  rack\n  rex (= 1.0.0)!\n  rspec\n",
        )
        .await;
        let mut state = state_with(
            vec![edit(
                "Gemfile.lock",
                "redirect_gemfile_lock_dependency_pin",
                "added",
                None,
                Some("rex (= 1.0.0)!"),
            )],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted(), "{:?}", out.refusals);
        assert_eq!(
            read(dir.path(), "Gemfile.lock").await,
            "DEPENDENCIES\n  rack\n  rspec\n",
            "sibling lines keep their exact indentation"
        );
    }

    #[tokio::test]
    async fn commented_out_added_fragment_removal_keeps_the_following_line() {
        // The user disabled the redirect by commenting the directive out.
        // Mid-line removal must not eat the line's newline — doing so
        // joins the surviving comment prefix onto the NEXT line and
        // comments out the `require` directive.
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "go.mod",
            "module m\n// replace x v1.0.0 => gopatch.socket.dev/x v1\nrequire y v1.0.0\n",
        )
        .await;
        let mut state = state_with(
            vec![edit(
                "go.mod",
                "redirect_golang_replace",
                "added",
                None,
                Some("replace x v1.0.0 => gopatch.socket.dev/x v1"),
            )],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted(), "{:?}", out.refusals);
        assert_eq!(
            read(dir.path(), "go.mod").await,
            "module m\n// \nrequire y v1.0.0\n",
            "the require directive must survive on its own line"
        );
    }

    #[tokio::test]
    async fn anchor_shaped_original_never_reads_as_already_reverted() {
        // The Cargo.toml insert variant records the always-present table
        // header as `original` and header+insert as `new`. With the insert
        // drifted, contains(original) is vacuously true — the edit must
        // REFUSE, not silently drop as already-reverted.
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "Cargo.toml",
            "[dependencies.cfg-if]\nregistry  =  \"socket-patch-u\"\n",
        )
        .await;
        let mut state = state_with(
            vec![edit(
                "Cargo.toml",
                "redirect_cargo_toml_dep",
                "rewritten",
                Some("[dependencies.cfg-if]"),
                Some("[dependencies.cfg-if]\nregistry = \"socket-patch-u\""),
            )],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert_eq!(out.refusals.len(), 1, "{out:?}");
        assert!(out.refusals[0].reason.contains("drifted"));
        assert_eq!(state.edits.len(), 1, "the edit must survive for a retry");
    }

    #[tokio::test]
    async fn gem_section_move_record_fails_closed() {
        // redirect_gemfile_lock_gem_source records only the bare URLs of a
        // SECTION MOVE — not enough to invert it. Must refuse, never swap
        // the URL and claim success.
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "Gemfile.lock",
            "GEM\n  remote: https://patch.example/\n  specs:\n    rex (1.0.0)\n",
        )
        .await;
        let mut state = state_with(
            vec![edit(
                "Gemfile.lock",
                "redirect_gemfile_lock_gem_source",
                "rewritten",
                Some("https://rubygems.org/"),
                Some("https://patch.example/"),
            )],
            &["pkg:gem/rex@1.0.0"],
        );
        let before = read(dir.path(), "Gemfile.lock").await;
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert_eq!(out.refusals.len(), 1);
        assert!(out.refusals[0]
            .reason
            .contains("no hosted-redirect revert implementation"));
        assert_eq!(read(dir.path(), "Gemfile.lock").await, before);
        assert!(state.records.contains_key("pkg:gem/rex@1.0.0"));
    }

    #[tokio::test]
    async fn gem_added_fragments_are_removed() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "Gemfile",
            "source 'https://rubygems.org'\nsource 'https://patch.example' do\n  gem 'rex'\nend\n",
        )
        .await;
        let mut state = state_with(
            vec![edit(
                "Gemfile",
                "redirect_gemfile_source_block",
                "added",
                None,
                Some("source 'https://patch.example' do\n  gem 'rex'\nend"),
            )],
            &["pkg:gem/rex@1.0.0"],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted(), "{:?}", out.refusals);
        assert_eq!(
            read(dir.path(), "Gemfile").await,
            "source 'https://rubygems.org'\n"
        );
        assert!(state.records.is_empty());
    }

    // ---------- unsupported / per-purl-only ----------

    #[tokio::test]
    async fn maven_structured_edits_refuse_and_keep_the_record() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "pom.xml", "<project/>\n").await;
        let mut state = state_with(
            vec![FileEdit {
                path: "pom.xml".into(),
                kind: "redirect_maven_repository".into(),
                action: "added".into(),
                key: Some("socket-patch".into()),
                original: None,
                new: Some(json!({ "id": "socket-patch", "url": "https://patch.example" })),
            }],
            &["pkg:maven/g/a@1"],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert_eq!(out.refusals.len(), 1);
        assert!(out.refusals[0]
            .reason
            .contains("no hosted-redirect revert implementation"));
        assert_eq!(state.edits.len(), 1);
        assert!(state.records.contains_key("pkg:maven/g/a@1"));
    }

    #[tokio::test]
    async fn unknown_kind_fails_closed() {
        let dir = TempDir::new().unwrap();
        let mut state = state_with(
            vec![edit("f", "redirect_future_thing", "rewritten", Some("a"), Some("b"))],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert_eq!(out.refusals.len(), 1);
        assert_eq!(out.refusals[0].group, "unknown");
        assert_eq!(state.edits.len(), 1);
    }

    #[tokio::test]
    async fn leftover_npm_json_edit_refuses_and_holds_every_npm_family_record() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "package-lock.json", "{}\n").await;
        write(dir.path(), "bun.lock", "\"pkg\": [\"https://patch.example/t.tgz\"]\n").await;
        let mut state = state_with(
            vec![
                FileEdit {
                    path: "package-lock.json".into(),
                    kind: "redirect_npm_lock_entry".into(),
                    action: "rewritten".into(),
                    key: Some("node_modules/a".into()),
                    original: Some(json!({ "resolved": "u", "integrity": "i" })),
                    new: Some(json!({ "resolved": "p", "integrity": "j" })),
                },
                edit(
                    "bun.lock",
                    "redirect_bun_lock_package",
                    "rewritten",
                    Some("\"pkg\": [\"https://upstream.example/t.tgz\"]"),
                    Some("\"pkg\": [\"https://patch.example/t.tgz\"]"),
                ),
            ],
            &["pkg:npm/a@1"],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        // The npm group refused; the bun group replayed.
        assert_eq!(out.refusals.len(), 1);
        assert_eq!(out.refusals[0].group, "npm");
        assert!(read(dir.path(), "bun.lock").await.contains("upstream.example"));
        // npm-family records are held while ANY npm-family group refused.
        assert!(state.records.contains_key("pkg:npm/a@1"));
        assert_eq!(state.edits.len(), 1, "only the refused npm edit remains");
    }

    // ---------- pnpm trust ----------

    #[tokio::test]
    async fn trust_scaffold_is_deleted_when_unmodified() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "pnpm-workspace.yaml", PNPM_TRUST_SCAFFOLD).await;
        let mut state = state_with(
            vec![FileEdit {
                path: "pnpm-workspace.yaml".into(),
                kind: "redirect_pnpm_workspace_trust".into(),
                action: "created".into(),
                key: Some("trustLockfile".into()),
                original: None,
                new: Some(json!("true")),
            }],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted(), "{:?}", out.refusals);
        assert!(!dir.path().join("pnpm-workspace.yaml").exists());
    }

    #[tokio::test]
    async fn modified_trust_scaffold_keeps_the_file_and_drops_the_line() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "pnpm-workspace.yaml",
            "packages:\n  - '.'\n  - 'packages/*'\ntrustLockfile: true\n",
        )
        .await;
        let mut state = state_with(
            vec![FileEdit {
                path: "pnpm-workspace.yaml".into(),
                kind: "redirect_pnpm_workspace_trust".into(),
                action: "created".into(),
                key: Some("trustLockfile".into()),
                original: None,
                new: Some(json!("true")),
            }],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted());
        assert_eq!(
            read(dir.path(), "pnpm-workspace.yaml").await,
            "packages:\n  - '.'\n  - 'packages/*'\n"
        );
        assert!(out
            .warnings
            .iter()
            .any(|(code, _)| code == "redirect_pnpm_trust_scaffold_modified"));
    }

    #[tokio::test]
    async fn appended_trust_line_is_removed_exactly() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "pnpm-workspace.yaml",
            "packages:\n  - 'apps/*'\ntrustLockfile: true\n",
        )
        .await;
        let mut state = state_with(
            vec![FileEdit {
                path: "pnpm-workspace.yaml".into(),
                kind: "redirect_pnpm_workspace_trust".into(),
                action: "added".into(),
                key: Some("trustLockfile".into()),
                original: None,
                new: Some(json!("true")),
            }],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted());
        assert_eq!(
            read(dir.path(), "pnpm-workspace.yaml").await,
            "packages:\n  - 'apps/*'\n"
        );
    }

    #[tokio::test]
    async fn duplicated_trust_line_refuses_instead_of_removing_the_wrong_copy() {
        // A commented-out copy of the trust line above the live one:
        // removing the FIRST occurrence would strip the comment's text and
        // leave the LIVE line active while claiming full revert. Must
        // refuse like the ReplaceFragment / RemoveAddedFragment ambiguity
        // guards.
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "pnpm-workspace.yaml",
            "packages:\n  - '.'\n# trustLockfile: true — added by socket\ntrustLockfile: true\n",
        )
        .await;
        let mut state = state_with(
            vec![FileEdit {
                path: "pnpm-workspace.yaml".into(),
                kind: "redirect_pnpm_workspace_trust".into(),
                action: "added".into(),
                key: Some("trustLockfile".into()),
                original: None,
                new: Some(json!("true")),
            }],
            &[],
        );
        let before = read(dir.path(), "pnpm-workspace.yaml").await;
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert_eq!(out.refusals.len(), 1, "{out:?}");
        assert_eq!(out.refusals[0].group, "pnpm");
        assert!(out.refusals[0].reason.contains("more than once"));
        assert_eq!(read(dir.path(), "pnpm-workspace.yaml").await, before);
        assert_eq!(state.edits.len(), 1, "the edit must survive for a retry");
    }

    #[tokio::test]
    async fn commented_out_trust_line_removal_keeps_the_following_line() {
        // Single (commented) occurrence: removal proceeds, but must not
        // eat the newline and comment out the key on the next line.
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "pnpm-workspace.yaml",
            "packages:\n  - '.'\n# trustLockfile: true\nshamefullyHoist: true\n",
        )
        .await;
        let mut state = state_with(
            vec![FileEdit {
                path: "pnpm-workspace.yaml".into(),
                kind: "redirect_pnpm_workspace_trust".into(),
                action: "added".into(),
                key: Some("trustLockfile".into()),
                original: None,
                new: Some(json!("true")),
            }],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted(), "{:?}", out.refusals);
        assert_eq!(
            read(dir.path(), "pnpm-workspace.yaml").await,
            "packages:\n  - '.'\n# \nshamefullyHoist: true\n",
            "the following key must survive on its own line"
        );
    }

    // ---------- dry-run ----------

    #[tokio::test]
    async fn dry_run_reports_without_touching_disk_or_ledger() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "requirements.txt", "left-pad @ https://patch.example/x.whl\n").await;
        let mut state = state_with(
            vec![edit(
                "requirements.txt",
                "redirect_requirements_line",
                "rewritten",
                Some("left-pad==1.3.0"),
                Some("left-pad @ https://patch.example/x.whl"),
            )],
            &["pkg:pypi/left-pad@1.3.0"],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, true).await;
        assert!(out.fully_reverted());
        assert_eq!(out.dropped_edits, 1);
        assert_eq!(out.dropped_records, vec!["pkg:pypi/left-pad@1.3.0"]);
        assert!(out.reverted_files.contains("requirements.txt"));
        // Disk and ledger untouched.
        assert!(read(dir.path(), "requirements.txt").await.contains("patch.example"));
        assert_eq!(state.edits.len(), 1);
        assert_eq!(state.records.len(), 1);
    }

    // ---------- safety ----------

    #[tokio::test]
    async fn unsafe_ledger_path_refuses() {
        let dir = TempDir::new().unwrap();
        for bad in ["/etc/passwd", "../outside", "a/../../b", "c:\\windows\\x"] {
            let mut state = state_with(
                vec![edit(bad, "redirect_requirements_line", "rewritten", Some("a"), Some("b"))],
                &[],
            );
            let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
            assert_eq!(out.refusals.len(), 1, "path {bad:?} must refuse");
            assert!(out.refusals[0].reason.contains("unsafe path"), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn missing_file_for_rewritten_edit_is_a_drift_refusal() {
        let dir = TempDir::new().unwrap();
        let mut state = state_with(
            vec![edit(
                "composer.lock",
                "redirect_composer_dist",
                "rewritten",
                Some("a"),
                Some("b"),
            )],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert_eq!(out.refusals.len(), 1);
        assert!(out.refusals[0].reason.contains("no longer exists"));
    }

    #[tokio::test]
    async fn bun_lockb_migration_warns_and_drops() {
        let dir = TempDir::new().unwrap();
        let mut state = state_with(
            vec![FileEdit {
                path: "bun.lockb".into(),
                kind: "redirect_bun_lockb_migrated".into(),
                action: "removed".into(),
                key: None,
                original: None,
                new: None,
            }],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted());
        assert!(out
            .warnings
            .iter()
            .any(|(code, _)| code == "redirect_bun_lockb_unrestorable"));
        assert!(state.edits.is_empty());
    }

    /// Every kind the hosted writers emit today must have a deliberate
    /// classification — a new writer kind landing without a replay arm
    /// falls to the "unknown" group, which fails closed at runtime; this
    /// pin makes the gap loud at test time instead.
    #[test]
    fn every_known_writer_kind_is_classified() {
        let known = [
            ("redirect_requirements_line", "rewritten"),
            ("redirect_uv_lock_wheel", "rewritten"),
            ("redirect_composer_dist", "rewritten"),
            ("redirect_cargo_toml_dep", "rewritten"),
            ("redirect_cargo_lock_entry", "rewritten"),
            ("redirect_cargo_registry", "rewritten"),
            ("redirect_cargo_registry", "added"),
            ("redirect_pnpm_resolution", "rewritten"),
            ("redirect_pnpm_workspace_trust", "created"),
            ("redirect_pnpm_workspace_trust", "added"),
            ("redirect_yarn_classic_entry", "rewritten"),
            ("redirect_yarn_berry_entry", "rewritten"),
            ("redirect_bun_lock_package", "rewritten"),
            ("redirect_bun_lockb_migrated", "removed"),
            ("redirect_gemfile_lock_dependency_pin", "rewritten"),
            ("redirect_gemfile_lock_dependency_pin", "added"),
            ("redirect_gemfile_lock_checksum", "rewritten"),
            ("redirect_gemfile_lock_checksum", "added"),
            ("redirect_gemfile_source_block", "rewritten"),
            ("redirect_gemfile_source_block", "added"),
            ("redirect_gemfile_lock_source_url", "rewritten"),
            ("redirect_gemfile_lock_gem_source", "rewritten"),
            ("redirect_gemfile_source_url", "rewritten"),
            ("redirect_golang_replace", "added"),
            ("redirect_golang_replace", "updated"),
            ("redirect_golang_gosum", "added"),
            ("redirect_golang_gosum_prune", "removed"),
            ("redirect_golang_stale_replace_removed", "removed"),
            ("redirect_golang_stale_gosum_removed", "removed"),
            ("redirect_npm_lock_entry", "rewritten"),
            ("redirect_npm_lock_dep", "rewritten"),
            ("redirect_maven_repository", "added"),
            ("redirect_maven_dep_management", "added"),
            ("redirect_maven_dep_version", "rewritten"),
            ("redirect_maven_config", "created"),
            ("redirect_maven_trusted_checksums", "created"),
            ("redirect_nuget_source", "rewritten"),
            ("redirect_nuget_lock", "rewritten"),
        ];
        for (kind, action) in known {
            let (group, _) = classify(kind, action);
            assert_ne!(
                group, "unknown",
                "writer kind {kind}/{action} has no replay classification"
            );
        }
    }
}
