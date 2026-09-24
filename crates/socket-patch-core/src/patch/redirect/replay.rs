//! Whole-ledger reverse replay of hosted-redirect edits.
//!
//! The per-purl reverts in [`super::takeover`] cover cargo, the
//! npm-family lock flavors, and golang (which reuses the golang inverses
//! here). Everything else the hosted rewriters touch —
//! gem, pypi, composer, bun, and the non-package rideshare edits
//! (such as the pnpm `trustLockfile` auto-config) —
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

use super::staged::{flush_staged, staged_read, Staged, StagedBytes};
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
    /// Like [`Inverse::ReplaceFragment`], but `new` legitimately occurs
    /// several times and stands for every occurrence (a cargo v1 lock's
    /// full-id dependency reference, named by several dependents).
    ReplaceEveryFragment,
    PipenvEntry,
    HatchDocument,
    /// action `added` with only `new` recorded: the redirect inserted the
    /// fragment into a pre-existing file, so the inverse removes it once
    /// (an absent fragment is the desired end state — no-op).
    RemoveAddedFragment,
    /// action `removed` with only `original` recorded: the redirect
    /// pruned go.sum lines of the upstream module that the pristine file
    /// needs back. Re-inserted at go's sorted position, so the file returns
    /// byte for byte.
    ReinsertRemoved,
    /// go.sum lines the redirect added (`new`, `\n`-joined): each is removed
    /// as a whole line, whatever the file's line endings.
    RemoveAddedLines,
    /// The appended cargo `[registries.…]` block (`redirect_cargo_registry`,
    /// action `added`): removed together with exactly the one blank
    /// separator the rewriter put before it — see
    /// [`remove_appended_cargo_block`].
    RemoveAppendedCargoBlock,
    /// Cleanup of PRIOR socket wiring performed during a redirect refresh
    /// (`redirect_golang_stale_*`). The removal already moved the file
    /// toward pristine; restoring it would re-create socket wiring, so
    /// the inverse is a no-op and the edit is simply dropped.
    NoopDrop,
    /// The pnpm `trustLockfile` auto-config (kind-specific: `created`
    /// deletes the scaffold, `added` removes exactly one line).
    PnpmTrust,
    /// The npm `.npmrc` `allow-remote=all` auto-config (kind-specific:
    /// `created` deletes the untouched file, `added` removes exactly one
    /// line — see [`super::npmrc`]). Grouped with the npm lock kinds so a
    /// surviving (refused) package-lock edit keeps the setting it needs.
    NpmrcAllowRemote,
    BunBinaryPackage,
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
        "redirect_pipenv_entry" => ("pypi", Inverse::PipenvEntry),
        "redirect_requirements_line"
        | "redirect_uv_lock_wheel"
        | "redirect_poetry_lock_package"
        | "redirect_pdm_lock_package" => ("pypi", Inverse::ReplaceFragment),
        "redirect_hatch_document" => ("pypi", Inverse::HatchDocument),
        "redirect_composer_dist" => ("composer", Inverse::ReplaceFragment),
        "redirect_cargo_toml_dep" | "redirect_cargo_lock_entry" => {
            ("cargo", Inverse::ReplaceFragment)
        }
        super::CARGO_LOCK_REFERENCE_KIND => ("cargo", Inverse::ReplaceEveryFragment),
        "redirect_cargo_registry" => (
            "cargo",
            if action == "added" {
                Inverse::RemoveAppendedCargoBlock
            } else {
                Inverse::ReplaceFragment
            },
        ),
        "redirect_pnpm_resolution" => ("pnpm", Inverse::ReplaceFragment),
        "redirect_pnpm_workspace_trust" => ("pnpm", Inverse::PnpmTrust),
        "redirect_yarn_classic_entry" | "redirect_yarn_berry_entry" => {
            ("yarn", Inverse::ReplaceFragment)
        }
        "redirect_bun_lockb_package" => ("bun", Inverse::BunBinaryPackage),
        "redirect_bun_lock_package" => ("bun", Inverse::ReplaceFragment),
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
        "redirect_golang_gosum" => ("golang", Inverse::RemoveAddedLines),
        "redirect_golang_gosum_prune" => ("golang", Inverse::ReinsertRemoved),
        "redirect_golang_stale_replace_removed" | "redirect_golang_stale_gosum_removed" => {
            ("golang", Inverse::NoopDrop)
        }
        "redirect_npm_lock_entry" | "redirect_npm_lock_dep" => ("npm", Inverse::PerPurlOnly),
        super::npmrc::NPMRC_ALLOW_REMOTE_EDIT_KIND => ("npm", Inverse::NpmrcAllowRemote),
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
    /// Advisory (code, detail) pairs, such as a modified trust scaffold.
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
pub(super) fn remove_fragment_once(content: &str, fragment: &str) -> String {
    // A CRLF file (its fragments recorded CRLF too) is inverted as LF and
    // written back CRLF, so the separator bookkeeping below sees real line
    // breaks instead of stranding a `\r` line.
    let crlf = content.matches("\r\n").count();
    if crlf > 0 && crlf == content.matches('\n').count() && content.contains(fragment) {
        return remove_fragment_once(
            &content.replace("\r\n", "\n"),
            &fragment.replace("\r\n", "\n"),
        )
        .replace('\n', "\r\n");
    }
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
    if start == line_start {
        if content[end..].starts_with("\r\n") {
            end += 2;
        } else if content[end..].starts_with('\n') {
            end += 1;
        }
    }
    if end >= content.len() {
        // EOF removal: collapse the (ambiguous) trailing separator run.
        let trimmed = content[..start].trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            return String::new();
        }
        let eol = crate::vendor::common::detect_eol(content);
        return format!("{trimmed}{eol}");
    }
    format!("{}{}", &content[..start], &content[end..])
}

/// Every line break in `text` is a CRLF (and there is at least one).
fn is_all_crlf(text: &str) -> bool {
    let crlf = text.matches("\r\n").count();
    crlf > 0 && crlf == text.matches('\n').count()
}

/// One fragment-edit inverse, tolerant of a line-ending conversion between
/// the scan and the revert (git `core.autocrlf` rewrites the committed
/// files but never the JSON-escaped fragments in the ledger).
#[derive(Debug, PartialEq)]
pub(super) enum FragmentRevert {
    /// `new` was found and put back to `original` (the file's own line
    /// endings kept).
    Reverted(String),
    /// `new` is gone but `original` is present: already unwound.
    AlreadyOriginal,
    /// Neither fragment is present.
    Drifted,
}

/// Replace `new` with `original` in `content` — once, or at `every`
/// occurrence — matching regardless of CRLF/LF: an all-CRLF file is
/// matched as LF and written back CRLF; any other file is matched with the
/// recorded fragments, then with their LF forms. `new` is looked for
/// before `original` (an `original` may be a substring of `new`).
pub(super) fn revert_fragment_eol(
    content: &str,
    new: &str,
    original: &str,
    every: bool,
) -> FragmentRevert {
    if is_all_crlf(content) {
        return match revert_fragment_eol(
            &content.replace("\r\n", "\n"),
            &new.replace("\r\n", "\n"),
            &original.replace("\r\n", "\n"),
            every,
        ) {
            FragmentRevert::Reverted(lf) => FragmentRevert::Reverted(lf.replace('\n', "\r\n")),
            other => other,
        };
    }
    let (lf_new, lf_original) = (new.replace("\r\n", "\n"), original.replace("\r\n", "\n"));
    for (n, o) in [(new, original), (lf_new.as_str(), lf_original.as_str())] {
        if content.contains(n) {
            return FragmentRevert::Reverted(if every {
                content.replace(n, o)
            } else {
                content.replacen(n, o, 1)
            });
        }
    }
    if content.contains(original) || content.contains(&lf_original) {
        FragmentRevert::AlreadyOriginal
    } else {
        FragmentRevert::Drifted
    }
}

/// Whether `content` holds `fragment`, ignoring CRLF/LF differences.
pub(super) fn contains_eol(content: &str, fragment: &str) -> bool {
    content.contains(fragment)
        || content
            .replace("\r\n", "\n")
            .contains(&fragment.replace("\r\n", "\n"))
}

/// Invert the cargo rewriter's append of a `[registries.…]` block: it wrote
/// `config + "\n" + block` (just `block` into an empty config) and records
/// `block` — or `"\n" + block` when the config lacked a final newline (the
/// extra newline it had to add first). Removing the recorded fragment plus
/// the one newline before it therefore restores the config's exact bytes:
/// a missing final newline or trailing blank lines included, and anything
/// the user appended after the block kept. An all-CRLF file is inverted as
/// LF and written back CRLF; a fragment recorded with the other line
/// endings (a checkout converted them) still matches. `None` when the
/// fragment is not in the file.
pub(super) fn remove_appended_cargo_block(content: &str, fragment: &str) -> Option<String> {
    if is_all_crlf(content) {
        return remove_appended_cargo_block(
            &content.replace("\r\n", "\n"),
            &fragment.replace("\r\n", "\n"),
        )
        .map(|lf| lf.replace('\n', "\r\n"));
    }
    let lf_fragment = fragment.replace("\r\n", "\n");
    let (pos, len) = match content.find(fragment) {
        Some(pos) => (pos, fragment.len()),
        None => (content.find(&lf_fragment)?, lf_fragment.len()),
    };
    let before = &content[..pos];
    let before = before
        .strip_suffix("\r\n")
        .or_else(|| before.strip_suffix('\n'))
        .unwrap_or(before);
    Some(format!("{before}{}", &content[pos + len..]))
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

    // Where a cargo `[registries.…]` block can still be referenced from:
    // the root manifest and lock, plus every manifest the ledger pinned.
    let mut cargo_probes: Vec<String> = vec!["Cargo.toml".to_string(), "Cargo.lock".to_string()];
    for edit in state
        .edits
        .iter()
        .filter(|e| e.kind == "redirect_cargo_toml_dep")
    {
        if !cargo_probes.contains(&edit.path) {
            cargo_probes.push(edit.path.clone());
        }
    }

    let mut drop_indices: BTreeSet<usize> = BTreeSet::new();
    let mut refused_groups: BTreeSet<&'static str> = BTreeSet::new();
    let mut pending_warnings: Vec<(String, String)> = Vec::new();

    'group: for (group, indices) in &groups {
        let mut staged: Staged = BTreeMap::new();
        let mut staged_bytes: StagedBytes = BTreeMap::new();
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
            let edit = &state.edits[idx];
            let (_, inverse) = classify(&edit.kind, &edit.action);
            if !matches!(inverse, Inverse::NoopDrop | Inverse::Unsupported)
                && !safe_rel_path(&edit.path)
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
                Inverse::BunBinaryPackage => {
                    let restored = async {
                        let content = match staged_bytes.get(&edit.path) {
                            Some(bytes) => bytes.clone(),
                            None => crate::utils::fs::read_regular_to_bytes(
                                &project_root.join(&edit.path),
                            )
                            .await
                            .map_err(|error| {
                                if error.kind() == std::io::ErrorKind::NotFound {
                                    format!("{} no longer exists", edit.path)
                                } else {
                                    format!("read {}: {error}", edit.path)
                                }
                            })?,
                        };
                        super::bun_binary::restore(&content, edit)
                    }
                    .await;
                    match restored {
                        Ok(bytes) => {
                            staged_bytes.insert(edit.path.clone(), bytes);
                            group_drops.insert(idx);
                        }
                        Err(reason) => {
                            refuse(reason, &mut outcome);
                            refused_groups.insert(group);
                            continue 'group;
                        }
                    }
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
                Inverse::PipenvEntry => {
                    let restored = match staged_read(&staged, project_root, &edit.path).await {
                        Ok(Some(content)) => super::pipenv::restore(&content, edit)
                            .map(|restored| (content, restored)),
                        Ok(None) => Err(format!("{} no longer exists", edit.path)),
                        Err(error) => Err(error),
                    };
                    match restored {
                        Ok((content, restored)) => {
                            // An already-unwound or retired entry returns the
                            // text unchanged: no write, no `editedFiles` credit
                            // (mirrors the ReplaceFragment already-original arm).
                            if restored != content {
                                staged.insert(edit.path.clone(), Some(restored));
                            }
                            group_drops.insert(idx);
                        }
                        Err(error) => {
                            refuse(error, &mut outcome);
                            refused_groups.insert(group);
                            continue 'group;
                        }
                    }
                }
                Inverse::ReplaceFragment
                | Inverse::ReplaceEveryFragment
                | Inverse::HatchDocument => {
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
                            refuse(format!("{} no longer exists", edit.path), &mut outcome);
                            refused_groups.insert(group);
                            continue 'group;
                        }
                        Err(e) => {
                            refuse(e, &mut outcome);
                            refused_groups.insert(group);
                            continue 'group;
                        }
                    };
                    if inverse == Inverse::HatchDocument {
                        match crate::vendor::restore_python_document(&content, original, new) {
                            Ok((restored, false)) => {
                                // Already at its original (the restore
                                // short-circuits on `live == original`): no
                                // write, no `editedFiles` credit; the ledger
                                // edit still retires (mirrors the PipenvEntry
                                // arm).
                                if restored != content {
                                    staged.insert(edit.path.clone(), Some(restored));
                                }
                                group_drops.insert(idx);
                            }
                            _ => {
                                refuse(
                                    format!("{}: Hatch configuration drifted", edit.path),
                                    &mut outcome,
                                );
                                refused_groups.insert(group);
                                continue 'group;
                            }
                        }
                        continue;
                    }
                    // yarn lock fragments are whole blocks recorded in the
                    // lock's on-disk line endings, and a `core.autocrlf`
                    // checkout on another OS re-spells the lock (never the
                    // committed ledger): when neither fragment matches
                    // verbatim, try both in the live file's uniform ending.
                    let respelled = (super::yarn_lock_fragment_kind(&edit.kind)
                        && !content.contains(new)
                        && !content.contains(original))
                    .then(|| {
                        crate::utils::line_endings::fragments_in_eol_of(&content, original, new)
                    })
                    .flatten();
                    let (original, new) = match &respelled {
                        Some((original, new)) => (original.as_str(), new.as_str()),
                        None => (original, new),
                    };
                    // `new` before `original`: original may be a substring
                    // of new (Cargo.toml insert, maven version suffix).
                    // cargo: matched regardless of a CRLF/LF conversion since
                    // the scan (a checkout's `core.autocrlf` rewrites the
                    // files, never the ledger's escaped fragments).
                    if *group == "cargo" {
                        let every = inverse == Inverse::ReplaceEveryFragment;
                        let lf = |t: &str| t.replace("\r\n", "\n");
                        if !every && lf(&content).matches(&lf(new)).count() > 1 {
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
                        match revert_fragment_eol(&content, new, original, every) {
                            FragmentRevert::Reverted(restored) => {
                                staged.insert(edit.path.clone(), Some(restored));
                                group_drops.insert(idx);
                            }
                            // Same substring guard as below.
                            FragmentRevert::AlreadyOriginal if !lf(new).contains(&lf(original)) => {
                                group_drops.insert(idx);
                            }
                            _ => {
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
                        continue;
                    }
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
                        staged.insert(edit.path.clone(), Some(content.replacen(new, original, 1)));
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
                        // bun only: Bun 1.1.39–1.3.9 re-save our URL 3-tuple
                        // WITHOUT its sha512 on any later lock re-save, so
                        // the recorded `new` is on disk as a digest-less
                        // 2-tuple — same key, spec and meta. That spelling
                        // is the recorded wiring, not drift: put `original`
                        // back over it. Anything else still refuses.
                        let healed = if edit.kind == "redirect_bun_lock_package" {
                            crate::vendor::bun_lock_text::restore_digestless_line(
                                &content, new, original,
                            )
                        } else {
                            Ok(None)
                        };
                        match healed {
                            Ok(Some(restored)) => {
                                staged.insert(edit.path.clone(), Some(restored));
                                group_drops.insert(idx);
                            }
                            Ok(None) => {
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
                            Err(ambiguous) => {
                                refuse(format!("{}: {ambiguous}", edit.path), &mut outcome);
                                refused_groups.insert(group);
                                continue 'group;
                            }
                        }
                    }
                }
                Inverse::RemoveAppendedCargoBlock => {
                    let Some(new) = str_payload(&edit.new) else {
                        refuse(
                            format!("{} edit is missing its recorded fragment", edit.kind),
                            &mut outcome,
                        );
                        refused_groups.insert(group);
                        continue 'group;
                    };
                    // A block something still references (a hand-pinned dep)
                    // stays: removing it would leave that pin naming an
                    // undefined registry. The reverse walk has already
                    // unwound this ledger's own references.
                    let reg = edit.key.as_deref().unwrap_or_default();
                    let index = new.split('"').nth(1).unwrap_or_default();
                    let mut referenced = false;
                    for probe in &cargo_probes {
                        if let Ok(Some(text)) = staged_read(&staged, project_root, probe).await {
                            if (!reg.is_empty() && text.contains(reg))
                                || (!index.is_empty() && text.contains(index))
                            {
                                referenced = true;
                                break;
                            }
                        }
                    }
                    if referenced {
                        group_drops.insert(idx);
                        continue;
                    }
                    match staged_read(&staged, project_root, &edit.path).await {
                        Ok(Some(content)) => {
                            // Absent fragment == already clean. A config the
                            // rewrite created ends empty and goes with it.
                            if let Some(restored) = remove_appended_cargo_block(&content, new) {
                                staged.insert(
                                    edit.path.clone(),
                                    (!restored.is_empty()).then_some(restored),
                                );
                            }
                            group_drops.insert(idx);
                        }
                        Ok(None) => {
                            group_drops.insert(idx);
                        }
                        Err(e) => {
                            refuse(e, &mut outcome);
                            refused_groups.insert(group);
                            continue 'group;
                        }
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
                    if let Some(restored) =
                        crate::vendor::go_sum_edit::reinsert_lines(&content, original)
                    {
                        staged.insert(edit.path.clone(), Some(restored));
                    }
                    group_drops.insert(idx);
                }
                Inverse::RemoveAddedLines => {
                    let Some(new) = str_payload(&edit.new) else {
                        refuse(
                            format!("{} edit is missing its recorded fragment", edit.kind),
                            &mut outcome,
                        );
                        refused_groups.insert(group);
                        continue 'group;
                    };
                    match staged_read(&staged, project_root, &edit.path).await {
                        Ok(Some(content)) => {
                            if new
                                .lines()
                                .filter(|l| !l.is_empty())
                                .any(|line| content.lines().filter(|l| l == &line).count() > 1)
                            {
                                refuse(
                                    format!(
                                        "{}: an added line appears more than once — \
                                         ambiguous, refusing to guess",
                                        edit.path
                                    ),
                                    &mut outcome,
                                );
                                refused_groups.insert(group);
                                continue 'group;
                            }
                            if let Some(removed) =
                                crate::vendor::go_sum_edit::remove_lines(&content, new)
                            {
                                staged.insert(edit.path.clone(), Some(removed));
                            }
                            group_drops.insert(idx);
                        }
                        // File gone entirely: the lines are gone with it.
                        Ok(None) => {
                            group_drops.insert(idx);
                        }
                        Err(e) => {
                            refuse(e, &mut outcome);
                            refused_groups.insert(group);
                            continue 'group;
                        }
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
                Inverse::NpmrcAllowRemote => {
                    // Refuse a symlinked / non-regular `.npmrc` while
                    // planning — never at flush time, after sibling files
                    // of the group may already have landed.
                    if !staged.contains_key(&edit.path) {
                        if let Ok(meta) =
                            tokio::fs::symlink_metadata(project_root.join(&edit.path)).await
                        {
                            if !meta.is_file() {
                                refuse(
                                    format!("{} is not a regular file", edit.path),
                                    &mut outcome,
                                );
                                refused_groups.insert(group);
                                continue 'group;
                            }
                        }
                    }
                    let content = match staged_read(&staged, project_root, &edit.path).await {
                        Ok(c) => c,
                        Err(e) => {
                            refuse(e, &mut outcome);
                            refused_groups.insert(group);
                            continue 'group;
                        }
                    };
                    match super::npmrc::unwind_npmrc_allow_remote(&edit.action, content.as_deref())
                    {
                        Ok(super::npmrc::NpmrcUnwind::Unchanged) => {}
                        Ok(super::npmrc::NpmrcUnwind::Delete) => {
                            staged.insert(edit.path.clone(), None);
                        }
                        Ok(super::npmrc::NpmrcUnwind::Write {
                            content,
                            modified_created,
                        }) => {
                            staged.insert(edit.path.clone(), Some(content));
                            if modified_created {
                                group_warnings.push(super::npmrc::npmrc_modified_warning());
                            }
                        }
                        Err(e) => {
                            refuse(e, &mut outcome);
                            refused_groups.insert(group);
                            continue 'group;
                        }
                    }
                    group_drops.insert(idx);
                }
            }
        }

        // Commit the group: flush staged files (unless dry-run) through the
        // shared guarded atomic writer, then mark its edits for dropping. A
        // flush error refuses the group late — some files may already have
        // landed (the same residual exposure the per-purl reverts document)
        // — and keeps its ledger entries.
        if !dry_run {
            if let Err(reason) = flush_staged(project_root, &staged, &staged_bytes).await {
                refuse(reason, &mut outcome);
                refused_groups.insert(group);
                continue 'group;
            }
        }
        outcome.reverted_files.extend(staged.keys().cloned());
        outcome.reverted_files.extend(staged_bytes.keys().cloned());
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

    fn edit(
        path: &str,
        kind: &str,
        action: &str,
        original: Option<&str>,
        new: Option<&str>,
    ) -> FileEdit {
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
            state.records.insert(
                (*p).to_string(),
                crate::manifest::schema::PatchRecord {
                    uuid: "u".into(),
                    exported_at: "now".into(),
                    files: Default::default(),
                    vulnerabilities: Default::default(),
                    description: String::new(),
                    license: String::new(),
                    tier: "free".into(),
                },
            );
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

    #[tokio::test]
    async fn hatch_documents_revert_after_checkout_newline_conversion() {
        let original = "[project]\ndependencies=[\"one==1\"]\n[tool.hatch.envs.default]\n";
        let files = [("pyproject.toml".to_owned(), original.to_owned())]
            .into_iter()
            .collect();
        let patched =
            crate::utils::hatch::rewrite(&files, "one", "1", "https://patch.test/one.whl")
                .unwrap()
                .remove("pyproject.toml")
                .unwrap();
        for drift in [false, true] {
            let dir = TempDir::new().unwrap();
            let live = if drift {
                patched.replace("one.whl", "changed.whl")
            } else {
                patched.replace('\n', "\r\n")
            };
            write(dir.path(), "pyproject.toml", &live).await;
            let mut state = state_with(
                vec![edit(
                    "pyproject.toml",
                    "redirect_hatch_document",
                    "rewritten",
                    Some(original),
                    Some(&patched),
                )],
                &["pkg:pypi/one@1"],
            );
            let outcome = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
            assert_eq!(outcome.fully_reverted(), !drift);
            if drift {
                assert_eq!(read(dir.path(), "pyproject.toml").await, live);
                assert_eq!(state.edits.len(), 1);
            } else {
                assert_eq!(
                    read(dir.path(), "pyproject.toml").await,
                    original.replace('\n', "\r\n")
                );
                assert!(state.edits.is_empty());
            }
        }
    }

    /// yarn lock edits replay across a `core.autocrlf` checkout switch: the
    /// ledger's fragments are the lock's on-disk bytes at redirect time (the
    /// berry and classic rewriters record CRLF blocks for a CRLF lock), the
    /// live lock may since be in the OTHER uniform ending — the revert lands
    /// on the original block in the live file's ending. A mixed live file
    /// proves nothing and refuses; a non-yarn kind keeps the verbatim-only
    /// contract.
    #[tokio::test]
    async fn yarn_edits_revert_across_a_checkout_line_ending_switch() {
        let head = "# yarn\n\n__metadata:\n  version: 8\n  cacheKey: 10c0\n\n";
        let original = "\"left-pad@npm:^1.3.0\":\n  version: 1.3.0\n  \
                        resolution: \"left-pad@npm:1.3.0\"\n  checksum: 10c0/aaaa\n  \
                        languageName: node\n  linkType: hard";
        let new = "\"left-pad@npm:^1.3.0\":\n  version: 1.3.0\n  \
                   resolution: \"left-pad@npm:1.3.0::__archiveUrl=http%3A%2F%2Fp.test%2Flp.tgz\"\n  \
                   checksum: 10c0/bbbb\n  languageName: node\n  linkType: hard";
        let spell = |text: &str, crlf: bool| {
            if crlf {
                text.replace('\n', "\r\n")
            } else {
                text.to_string()
            }
        };
        for kind in ["redirect_yarn_berry_entry", "redirect_yarn_classic_entry"] {
            for (recorded_crlf, live_crlf) in
                [(true, true), (true, false), (false, true), (false, false)]
            {
                let label = format!("{kind} recorded_crlf={recorded_crlf} live_crlf={live_crlf}");
                let dir = TempDir::new().unwrap();
                write(
                    dir.path(),
                    "yarn.lock",
                    &spell(&format!("{head}{new}\n"), live_crlf),
                )
                .await;
                let mut state = state_with(
                    vec![edit(
                        "yarn.lock",
                        kind,
                        "rewritten",
                        Some(&spell(original, recorded_crlf)),
                        Some(&spell(new, recorded_crlf)),
                    )],
                    &["pkg:npm/left-pad@1.3.0"],
                );
                let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
                assert!(out.fully_reverted(), "{label}: {:?}", out.refusals);
                assert_eq!(
                    read(dir.path(), "yarn.lock").await,
                    spell(&format!("{head}{original}\n"), live_crlf),
                    "{label}"
                );
                assert!(state.edits.is_empty(), "{label}");
            }
        }

        // A mixed live lock: refused whole, byte-untouched, edit kept.
        let dir = TempDir::new().unwrap();
        let mixed = format!("{}{}\n", spell(head, true), new);
        write(dir.path(), "yarn.lock", &mixed).await;
        let mut state = state_with(
            vec![edit(
                "yarn.lock",
                "redirect_yarn_berry_entry",
                "rewritten",
                Some(&spell(original, true)),
                Some(&spell(new, true)),
            )],
            &["pkg:npm/left-pad@1.3.0"],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(!out.fully_reverted(), "a mixed lock must refuse");
        assert_eq!(read(dir.path(), "yarn.lock").await, mixed);
        assert_eq!(state.edits.len(), 1);

        // A non-yarn line-oriented kind keeps the verbatim-only contract.
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "requirements.txt",
            "a==1\r\nleft-pad @ https://patch.example/x.whl\r\n",
        )
        .await;
        let mut state = state_with(
            vec![edit(
                "requirements.txt",
                "redirect_requirements_line",
                "rewritten",
                Some("a==1\nleft-pad==1.3.0"),
                Some("a==1\nleft-pad @ https://patch.example/x.whl"),
            )],
            &["pkg:pypi/left-pad@1.3.0"],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(
            !out.fully_reverted(),
            "only yarn blocks are respelled across line endings"
        );
    }

    // ---------- ReplaceFragment ----------

    #[tokio::test]
    async fn rewritten_fragment_replays_to_original() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "requirements.txt",
            "left-pad @ https://patch.example/x.whl\n",
        )
        .await;
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
        assert_eq!(
            read(dir.path(), "requirements.txt").await,
            "left-pad==1.3.0\n"
        );
        assert!(state.edits.is_empty());
        assert!(state.records.is_empty());
        assert_eq!(out.dropped_records, vec!["pkg:pypi/left-pad@1.3.0"]);
    }

    #[tokio::test]
    async fn substring_original_checks_new_first() {
        // The maven version-suffix shape: original is a substring of new.
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "pom.xml",
            "<version>2.17.1-socket-abc</version>\n",
        )
        .await;
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
        assert_eq!(
            read(dir.path(), "pom.xml").await,
            "<version>2.17.1</version>\n"
        );
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
        write(
            dir.path(),
            "go.mod",
            "module m\n\nreplace x => gopatch.socket.dev/x v2\n",
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

    // ---------- bun: digest-less re-saves (Bun 1.1.39–1.3.9, every text-lock release below 1.3.10) ----------

    const BUN_URL: &str =
        "https://patch.socket.dev/patch/npm/tok-1111/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/left-pad-1.3.0.tgz";
    const BUN_REGISTRY_LINE: &str =
        "    \"left-pad\": [\"left-pad@1.3.0\", \"\", {}, \"sha512-XI5M==\"],";

    fn bun_url_line(sha: &str) -> String {
        format!("    \"left-pad\": [\"left-pad@{BUN_URL}\", {{}}, \"{sha}\"],")
    }

    fn bun_digestless_line() -> String {
        format!("    \"left-pad\": [\"left-pad@{BUN_URL}\", {{}}],")
    }

    fn bun_lock(entry: &str) -> String {
        format!(
            "{{\n  \"lockfileVersion\": 1,\n  \"packages\": {{\n    \"abbrev\": [\"abbrev@1.1.1\", \
             \"\", {{}}, \"sha512-D==\"],\n\n{entry}\n  }}\n}}\n"
        )
    }

    fn bun_edit(original: &str, new: &str) -> FileEdit {
        edit(
            "bun.lock",
            "redirect_bun_lock_package",
            "rewritten",
            Some(original),
            Some(new),
        )
    }

    /// The live lock carries the digest-less 2-tuple Bun < 1.3.10 re-saved
    /// our URL 3-tuple as; the recorded `new` is the 3-tuple. That is the
    /// recorded wiring, not drift: the registry original comes back, the
    /// edit and record are consumed.
    #[tokio::test]
    async fn bun_digestless_live_line_replays_to_the_registry_original() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "bun.lock", &bun_lock(&bun_digestless_line())).await;
        let mut state = state_with(
            vec![bun_edit(BUN_REGISTRY_LINE, &bun_url_line("sha512-AAAA=="))],
            &["pkg:npm/left-pad@1.3.0"],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted(), "{:?}", out.refusals);
        assert_eq!(
            read(dir.path(), "bun.lock").await,
            bun_lock(BUN_REGISTRY_LINE),
            "the pristine registry line is restored, the decoy untouched"
        );
        assert!(state.edits.is_empty() && state.records.is_empty());
        assert_eq!(out.dropped_records, vec!["pkg:npm/left-pad@1.3.0"]);

        // CRLF lock (ledger recorded with `\r` on both fragments, as the
        // rewriter does): every line keeps its `\r\n`.
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "bun.lock",
            &bun_lock(&bun_digestless_line()).replace('\n', "\r\n"),
        )
        .await;
        let mut state = state_with(
            vec![bun_edit(
                &format!("{BUN_REGISTRY_LINE}\r"),
                &format!("{}\r", bun_url_line("sha512-AAAA==")),
            )],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted(), "{:?}", out.refusals);
        assert_eq!(
            read(dir.path(), "bun.lock").await,
            bun_lock(BUN_REGISTRY_LINE).replace('\n', "\r\n")
        );
    }

    /// The hosted rewriter HEALS a digest-less tuple and records that heal
    /// as a second edit for the same key (`original` = the 2-tuple). The
    /// chain unwinds newest-first: heal → 2-tuple, then the first edit
    /// recognises the 2-tuple as its digest-less `new` → registry line.
    /// Same end state when Bun has since dropped the digest AGAIN (the
    /// heal edit is then "already at its original" and simply drops).
    #[tokio::test]
    async fn bun_heal_chain_unwinds_to_the_registry_line() {
        let healed = bun_url_line("sha512-AAAA==");
        for live in [healed.clone(), bun_digestless_line()] {
            let dir = TempDir::new().unwrap();
            write(dir.path(), "bun.lock", &bun_lock(&live)).await;
            let mut state = state_with(
                vec![
                    bun_edit(BUN_REGISTRY_LINE, &healed),
                    bun_edit(&bun_digestless_line(), &healed),
                ],
                &["pkg:npm/left-pad@1.3.0"],
            );
            let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
            assert!(out.fully_reverted(), "live={live}: {:?}", out.refusals);
            assert_eq!(
                read(dir.path(), "bun.lock").await,
                bun_lock(BUN_REGISTRY_LINE),
                "live={live}: the chain must end at the pristine registry line"
            );
            assert!(state.edits.is_empty() && state.records.is_empty());
        }
    }

    /// The relaxation is exactly "our tuple minus its digest": another
    /// uuid/token in the URL, a re-laid meta object, a duplicate digest-less
    /// instance, or a non-bun edit kind over the same bytes all still
    /// refuse, leaving the file byte-identical.
    #[tokio::test]
    async fn bun_digestless_relaxation_is_narrow() {
        let recorded_new = bun_url_line("sha512-AAAA==");
        let other_uuid = bun_digestless_line().replace(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        );
        let other_meta = bun_digestless_line().replace("{}", "{ \"bin\": \"x\" }");
        for (live, kind, reason) in [
            (
                bun_lock(&other_uuid),
                "redirect_bun_lock_package",
                "neither the redirected nor the original",
            ),
            (
                bun_lock(&other_meta),
                "redirect_bun_lock_package",
                "neither the redirected nor the original",
            ),
            (
                bun_lock(&format!(
                    "{}\n{}",
                    bun_digestless_line(),
                    bun_digestless_line()
                )),
                "redirect_bun_lock_package",
                "more than once",
            ),
            (
                bun_lock(&bun_digestless_line()),
                "redirect_pnpm_resolution",
                "neither the redirected nor the original",
            ),
        ] {
            let dir = TempDir::new().unwrap();
            write(dir.path(), "bun.lock", &live).await;
            let mut state = state_with(
                vec![edit(
                    "bun.lock",
                    kind,
                    "rewritten",
                    Some(BUN_REGISTRY_LINE),
                    Some(&recorded_new),
                )],
                &["pkg:npm/left-pad@1.3.0"],
            );
            let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
            assert_eq!(
                out.refusals.len(),
                1,
                "{kind}: exactly one refusal expected, got {}",
                out.refusals.len()
            );
            assert!(
                out.refusals[0].reason.contains(reason),
                "{kind}: {}",
                out.refusals[0].reason
            );
            assert_eq!(read(dir.path(), "bun.lock").await, live, "file untouched");
            assert_eq!(state.edits.len(), 1, "refused edit kept");
            assert!(state.records.contains_key("pkg:npm/left-pad@1.3.0"));
        }
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

    /// The pruned pair goes back where `go mod tidy` writes it — module
    /// path, then SEMVER version (`v1.9.0/go.mod` before `v1.10.0`, though
    /// bytewise greater) — so go.sum is restored byte for byte.
    #[tokio::test]
    async fn reinsert_restores_the_go_sorted_position() {
        let pristine = "example.com/leaf v1.0.0 h1:L=\n\
                        example.com/leaf v1.0.0/go.mod h1:LM=\n\
                        example.com/lib v1.9.0/go.mod h1:N9=\n\
                        example.com/lib v1.10.0 h1:T=\n\
                        example.com/lib v1.10.0/go.mod h1:TM=\n\
                        example.com/zeta v0.1.0 h1:Z=\n";
        for eol in ["\n", "\r\n"] {
            let dir = TempDir::new().unwrap();
            let pruned = pristine
                .lines()
                .filter(|l| !l.starts_with("example.com/lib v1.10.0"))
                .map(|l| format!("{l}{eol}"))
                .collect::<String>();
            write(dir.path(), "go.sum", &pruned).await;
            let mut state = state_with(
                vec![edit(
                    "go.sum",
                    "redirect_golang_gosum_prune",
                    "removed",
                    Some("example.com/lib v1.10.0 h1:T=\nexample.com/lib v1.10.0/go.mod h1:TM="),
                    None,
                )],
                &[],
            );
            let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
            assert!(out.fully_reverted(), "{:?}", out.refusals);
            assert_eq!(
                read(dir.path(), "go.sum").await,
                pristine.replace('\n', eol),
                "eol {eol:?}"
            );
        }
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
            vec![edit(
                "f",
                "redirect_future_thing",
                "rewritten",
                Some("a"),
                Some("b"),
            )],
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
        write(
            dir.path(),
            "bun.lock",
            "\"pkg\": [\"https://patch.example/t.tgz\"]\n",
        )
        .await;
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
        assert!(read(dir.path(), "bun.lock")
            .await
            .contains("upstream.example"));
        // npm-family records are held while ANY npm-family group refused.
        assert!(state.records.contains_key("pkg:npm/a@1"));
        assert_eq!(state.edits.len(), 1, "only the refused npm edit remains");
    }

    // ---------- npm .npmrc allow-remote ----------

    fn npmrc_edit(action: &str) -> FileEdit {
        FileEdit {
            path: ".npmrc".into(),
            kind: "redirect_npmrc_allow_remote".into(),
            action: action.into(),
            key: Some("allow-remote".into()),
            original: None,
            new: Some(json!("all")),
        }
    }

    #[tokio::test]
    async fn npmrc_created_file_is_deleted_when_unmodified() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), ".npmrc", "allow-remote=all\n").await;
        let mut state = state_with(vec![npmrc_edit("created")], &[]);
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted(), "{:?}", out.refusals);
        assert!(!dir.path().join(".npmrc").exists());
        assert!(state.edits.is_empty());
    }

    #[tokio::test]
    async fn npmrc_appended_line_is_removed_exactly_and_user_edits_survive() {
        let dir = TempDir::new().unwrap();
        // The user added their own setting after our line (CRLF file).
        write(
            dir.path(),
            ".npmrc",
            "registry=https://r.example/\r\nallow-remote=all\r\nfund=false\r\n",
        )
        .await;
        let mut state = state_with(vec![npmrc_edit("added")], &[]);
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted(), "{:?}", out.refusals);
        assert_eq!(
            read(dir.path(), ".npmrc").await,
            "registry=https://r.example/\r\nfund=false\r\n"
        );
        assert!(out.warnings.is_empty(), "{:?}", out.warnings);
    }

    #[tokio::test]
    async fn npmrc_modified_created_file_keeps_the_file_and_warns() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), ".npmrc", "allow-remote=all\nfund=false\n").await;
        let mut state = state_with(vec![npmrc_edit("created")], &[]);
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted(), "{:?}", out.refusals);
        assert_eq!(read(dir.path(), ".npmrc").await, "fund=false\n");
        assert!(out
            .warnings
            .iter()
            .any(|(code, _)| code == "redirect_npmrc_allow_remote_modified"));
    }

    #[tokio::test]
    async fn npmrc_edit_is_kept_while_an_npm_lock_edit_refuses() {
        // A package-lock edit the per-purl revert failed to claim refuses
        // the npm group — and with it the `.npmrc` setting that lock needs.
        let dir = TempDir::new().unwrap();
        write(dir.path(), ".npmrc", "allow-remote=all\n").await;
        let mut state = state_with(
            vec![
                FileEdit {
                    path: "package-lock.json".into(),
                    kind: "redirect_npm_lock_entry".into(),
                    action: "rewritten".into(),
                    key: Some("node_modules/a".into()),
                    original: Some(json!({"resolved": "https://registry/a-1.tgz"})),
                    new: Some(json!({"resolved": "https://patch.example/a-1.tgz"})),
                },
                npmrc_edit("created"),
            ],
            &["pkg:npm/a@1"],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert_eq!(out.refusals.len(), 1, "{out:?}");
        assert_eq!(out.refusals[0].group, "npm");
        assert_eq!(read(dir.path(), ".npmrc").await, "allow-remote=all\n");
        assert_eq!(state.edits.len(), 2);
    }

    #[tokio::test]
    async fn npmrc_duplicate_line_refuses_and_dry_run_writes_nothing() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), ".npmrc", "allow-remote=all\nallow-remote=all\n").await;
        let mut state = state_with(vec![npmrc_edit("added")], &[]);
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert_eq!(out.refusals.len(), 1, "{out:?}");
        assert_eq!(state.edits.len(), 1);

        write(dir.path(), ".npmrc", "allow-remote=all\n").await;
        let mut state = state_with(vec![npmrc_edit("created")], &[]);
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, true).await;
        assert!(out.fully_reverted());
        assert!(out.reverted_files.contains(".npmrc"));
        assert_eq!(read(dir.path(), ".npmrc").await, "allow-remote=all\n");
    }

    /// The replay twin of the per-purl finding: a symlinked `.npmrc`
    /// refuses the npm group while planning (the link and its target are
    /// never written), and a section-scoped copy of the line no longer
    /// makes the unwind ambiguous.
    #[cfg(unix)]
    #[tokio::test]
    async fn npmrc_symlink_refuses_at_plan_time_and_section_copies_are_inert() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "shared.npmrc", "allow-remote=all\n").await;
        std::os::unix::fs::symlink("shared.npmrc", dir.path().join(".npmrc")).unwrap();
        let mut state = state_with(vec![npmrc_edit("created")], &[]);
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert_eq!(out.refusals.len(), 1, "{out:?}");
        assert!(
            out.refusals[0].reason.contains("not a regular file"),
            "{out:?}"
        );
        assert_eq!(state.edits.len(), 1);
        assert_eq!(read(dir.path(), "shared.npmrc").await, "allow-remote=all\n");

        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            ".npmrc",
            "allow-remote=all\n[sec]\nallow-remote=all\n",
        )
        .await;
        let mut state = state_with(vec![npmrc_edit("added")], &[]);
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted(), "{out:?}");
        assert_eq!(
            read(dir.path(), ".npmrc").await,
            "[sec]\nallow-remote=all\n"
        );
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
        write(
            dir.path(),
            "requirements.txt",
            "left-pad @ https://patch.example/x.whl\n",
        )
        .await;
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
        assert!(read(dir.path(), "requirements.txt")
            .await
            .contains("patch.example"));
        assert_eq!(state.edits.len(), 1);
        assert_eq!(state.records.len(), 1);
    }

    // ---------- safety ----------

    #[tokio::test]
    async fn unsafe_ledger_path_refuses() {
        let dir = TempDir::new().unwrap();
        for bad in ["/etc/passwd", "../outside", "a/../../b", "c:\\windows\\x"] {
            let mut state = state_with(
                vec![edit(
                    bad,
                    "redirect_requirements_line",
                    "rewritten",
                    Some("a"),
                    Some("b"),
                )],
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

    /// A FIFO squatting bun.lockb must refuse fast instead of wedging the
    /// replay (the same guard every other raw read in the engine has).
    #[cfg(unix)]
    #[tokio::test]
    async fn bun_lockb_fifo_squatting_the_path_refuses_the_group() {
        let dir = TempDir::new().unwrap();
        let fifo = dir.path().join("bun.lockb");
        let c_path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a valid NUL-terminated path; mkfifo has no other preconditions.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) }, 0);
        let mut state = state_with(
            vec![edit(
                "bun.lockb",
                "redirect_bun_lockb_package",
                "rewritten",
                None,
                None,
            )],
            &[],
        );
        let out = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            revert_remaining_redirect_edits(dir.path(), &mut state, false),
        )
        .await
        .expect("the FIFO guard must not wedge the replay");
        assert_eq!(out.refusals.len(), 1, "{:?}", out.warnings);
        assert!(
            out.refusals[0].reason.contains("bun.lockb"),
            "{}",
            out.refusals[0].reason
        );
        assert_eq!(state.edits.len(), 1);
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
            ("redirect_bun_lockb_package", "rewritten"),
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
            ("redirect_npmrc_allow_remote", "created"),
            ("redirect_npmrc_allow_remote", "added"),
            ("redirect_maven_repository", "added"),
            ("redirect_maven_dep_management", "added"),
            ("redirect_maven_dep_version", "rewritten"),
            ("redirect_maven_config", "created"),
            ("redirect_maven_trusted_checksums", "created"),
            ("redirect_nuget_source", "rewritten"),
            ("redirect_nuget_source", "added"),
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

    // ---------- payload corruption (tampered / partially-written ledger) ----------

    #[tokio::test]
    async fn replace_arm_missing_payload_refuses_and_keeps_the_edit() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "composer.lock", "https://patch.example/a\n").await;
        let mut state = state_with(
            vec![edit(
                "composer.lock",
                "redirect_composer_dist",
                "rewritten",
                None,
                Some("https://patch.example/a"),
            )],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert_eq!(out.refusals.len(), 1, "{out:?}");
        assert!(out.refusals[0]
            .reason
            .contains("missing its recorded fragments"));
        assert_eq!(state.edits.len(), 1, "the edit must survive for a retry");
        assert_eq!(
            read(dir.path(), "composer.lock").await,
            "https://patch.example/a\n"
        );
    }

    #[tokio::test]
    async fn replace_arm_non_string_payload_refuses() {
        // A hand-edited or corrupted ledger can carry a non-string Value
        // where the inverse table requires a fragment string — str_payload
        // must reject it, not coerce.
        let dir = TempDir::new().unwrap();
        write(dir.path(), "composer.lock", "https://patch.example/a\n").await;
        let mut state = state_with(
            vec![FileEdit {
                path: "composer.lock".into(),
                kind: "redirect_composer_dist".into(),
                action: "rewritten".into(),
                key: Some("k".into()),
                original: Some(json!(42)),
                new: Some(Value::String("https://patch.example/a".into())),
            }],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert_eq!(out.refusals.len(), 1, "{out:?}");
        assert!(out.refusals[0]
            .reason
            .contains("missing its recorded fragments"));
        assert_eq!(state.edits.len(), 1);
        assert_eq!(
            read(dir.path(), "composer.lock").await,
            "https://patch.example/a\n"
        );
    }

    #[tokio::test]
    async fn remove_added_arm_missing_payload_refuses() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "go.sum", "gopatch.socket.dev/x v1 h1:a\n").await;
        let mut state = state_with(
            vec![edit("go.sum", "redirect_golang_gosum", "added", None, None)],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert_eq!(out.refusals.len(), 1, "{out:?}");
        assert!(out.refusals[0]
            .reason
            .contains("missing its recorded fragment"));
        assert_eq!(state.edits.len(), 1);
        assert_eq!(
            read(dir.path(), "go.sum").await,
            "gopatch.socket.dev/x v1 h1:a\n"
        );
    }

    #[tokio::test]
    async fn reinsert_arm_missing_payload_refuses() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "go.sum", "x v1 h1:a\n").await;
        let mut state = state_with(
            vec![edit(
                "go.sum",
                "redirect_golang_gosum_prune",
                "removed",
                None,
                None,
            )],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert_eq!(out.refusals.len(), 1, "{out:?}");
        assert!(out.refusals[0]
            .reason
            .contains("missing its recorded lines"));
        assert_eq!(state.edits.len(), 1);
        assert_eq!(read(dir.path(), "go.sum").await, "x v1 h1:a\n");
    }

    // ---------- read failures (FIFO / directory squats) ----------

    #[tokio::test]
    async fn directory_squatting_a_lockfile_refuses_each_arm_fail_fast() {
        // A directory planted at the lockfile path makes open_regular_file
        // return InvalidInput (open + fstat) — the fail-fast posture the
        // module doc claims. Every per-arm read must refuse the group with
        // the read error and keep the ledger.
        #[allow(clippy::type_complexity)]
        let cases: [(&str, &str, &str, Option<&str>, Option<&str>); 4] = [
            (
                "composer.lock",
                "redirect_composer_dist",
                "rewritten",
                Some("https://upstream.example/a"),
                Some("https://patch.example/a"),
            ),
            (
                "go.sum",
                "redirect_golang_gosum",
                "added",
                None,
                Some("gopatch.socket.dev/x v1 h1:a"),
            ),
            (
                "go.sum",
                "redirect_golang_gosum_prune",
                "removed",
                Some("x v0.9 h1:o"),
                None,
            ),
            (
                "pnpm-workspace.yaml",
                "redirect_pnpm_workspace_trust",
                "added",
                None,
                Some("true"),
            ),
        ];
        for (path, kind, action, original, new) in cases {
            let dir = TempDir::new().unwrap();
            tokio::fs::create_dir_all(dir.path().join(path))
                .await
                .unwrap();
            let mut state = state_with(vec![edit(path, kind, action, original, new)], &[]);
            let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
            assert_eq!(
                out.refusals.len(),
                1,
                "{kind}/{action} must refuse: {out:?}"
            );
            assert!(
                out.refusals[0].reason.starts_with(&format!("read {path}:")),
                "{kind}/{action}: {}",
                out.refusals[0].reason
            );
            // The fstat guard's "not a regular file" text is unix-only: on
            // Windows, opening a directory fails at CreateFileW with
            // ERROR_ACCESS_DENIED before the guard runs. The refusal itself
            // (count, `read {path}:` prefix, kept ledger) is platform-neutral.
            #[cfg(unix)]
            assert!(
                out.refusals[0].reason.contains("not a regular file"),
                "{kind}/{action}: {}",
                out.refusals[0].reason
            );
            assert_eq!(state.edits.len(), 1, "{kind}/{action} must keep its edit");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_squatting_a_lockfile_refuses_instead_of_wedging() {
        use std::os::unix::ffi::OsStrExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("composer.lock");
        let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o644) }, 0);
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
        assert_eq!(out.refusals.len(), 1, "{out:?}");
        assert!(
            out.refusals[0].reason.starts_with("read composer.lock:"),
            "{}",
            out.refusals[0].reason
        );
        assert!(out.refusals[0].reason.contains("not a regular file"));
        assert_eq!(state.edits.len(), 1);
    }

    // ---------- RemoveAddedFragment already-clean edges ----------

    #[tokio::test]
    async fn added_fragment_with_file_gone_drops_without_recreating_it() {
        let dir = TempDir::new().unwrap();
        let mut state = state_with(
            vec![edit(
                "go.sum",
                "redirect_golang_gosum",
                "added",
                None,
                Some("gopatch.socket.dev/x v1 h1:a"),
            )],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted(), "{:?}", out.refusals);
        assert!(state.edits.is_empty());
        assert!(out.reverted_files.is_empty(), "nothing was written");
        assert!(
            !dir.path().join("go.sum").exists(),
            "the deleted file must not be recreated"
        );
    }

    #[tokio::test]
    async fn added_fragment_already_absent_is_a_noop_drop() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "go.mod", "module m\n").await;
        let mut state = state_with(
            vec![edit(
                "go.mod",
                "redirect_golang_replace",
                "added",
                None,
                Some("replace x => gopatch.socket.dev/x v1"),
            )],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted(), "{:?}", out.refusals);
        assert!(state.edits.is_empty());
        assert!(out.reverted_files.is_empty(), "nothing was written");
        assert_eq!(read(dir.path(), "go.mod").await, "module m\n");
    }

    #[tokio::test]
    async fn duplicated_added_fragment_refuses_instead_of_guessing() {
        // The RemoveAddedFragment twin of the ReplaceFragment ambiguity
        // guard: two occurrences of the recorded fragment mean removal
        // could hit the wrong one — refuse byte-untouched.
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "go.sum",
            "gopatch.socket.dev/x v1 h1:a\ngopatch.socket.dev/x v1 h1:a\n",
        )
        .await;
        let mut state = state_with(
            vec![edit(
                "go.sum",
                "redirect_golang_gosum",
                "added",
                None,
                Some("gopatch.socket.dev/x v1 h1:a"),
            )],
            &[],
        );
        let before = read(dir.path(), "go.sum").await;
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert_eq!(out.refusals.len(), 1, "{out:?}");
        assert_eq!(out.refusals[0].group, "golang");
        assert!(out.refusals[0].reason.contains("more than once"));
        assert_eq!(read(dir.path(), "go.sum").await, before);
        assert_eq!(state.edits.len(), 1, "the edit must survive for a retry");
    }

    // ---------- ReinsertRemoved edge shapes ----------

    #[tokio::test]
    async fn reinsert_into_unterminated_file_adds_a_separating_newline() {
        // A go.sum whose last line lost its trailing newline (hand-edited
        // or tool-truncated): the re-inserted pruned lines must not
        // concatenate onto it.
        let dir = TempDir::new().unwrap();
        write(dir.path(), "go.sum", "x v1 h1:abc").await;
        let mut state = state_with(
            vec![edit(
                "go.sum",
                "redirect_golang_gosum_prune",
                "removed",
                Some("y v0.9 h1:o"),
                None,
            )],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted(), "{:?}", out.refusals);
        assert_eq!(
            read(dir.path(), "go.sum").await,
            "x v1 h1:abc\ny v0.9 h1:o\n"
        );
    }

    #[tokio::test]
    async fn reinsert_recreates_a_deleted_gosum() {
        // The user deleted go.sum entirely; the pruned upstream lines must
        // still come back — the staged write lands on a nonexistent path
        // (the flush-side symlink_metadata Err edge) and creates the file.
        let dir = TempDir::new().unwrap();
        let mut state = state_with(
            vec![edit(
                "go.sum",
                "redirect_golang_gosum_prune",
                "removed",
                Some("y v0.9 h1:o"),
                None,
            )],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted(), "{:?}", out.refusals);
        assert!(out.reverted_files.contains("go.sum"));
        assert_eq!(read(dir.path(), "go.sum").await, "y v0.9 h1:o\n");
        assert!(state.edits.is_empty());
    }

    // ---------- pnpm trust already-clean edges ----------

    #[tokio::test]
    async fn trust_edit_with_workspace_file_gone_drops_without_recreating_it() {
        let dir = TempDir::new().unwrap();
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
        assert!(state.edits.is_empty());
        assert!(
            !dir.path().join("pnpm-workspace.yaml").exists(),
            "the deleted workspace file must not be recreated"
        );
        assert!(out.reverted_files.is_empty(), "nothing was written");
    }

    #[tokio::test]
    async fn trust_line_already_absent_leaves_the_file_untouched() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "pnpm-workspace.yaml",
            "packages:\n  - 'apps/*'\n",
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
        assert!(out.fully_reverted(), "{:?}", out.refusals);
        assert!(state.edits.is_empty());
        assert_eq!(
            read(dir.path(), "pnpm-workspace.yaml").await,
            "packages:\n  - 'apps/*'\n"
        );
        assert!(
            out.warnings.is_empty(),
            "no scaffold_modified warning: {:?}",
            out.warnings
        );
        assert!(out.reverted_files.is_empty(), "nothing was written");
    }

    // ---------- flush-side guards ----------

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_lockfile_reads_fine_but_refuses_at_flush() {
        // open_regular_file follows the symlink at read time (open+fstat),
        // but the flush-side symlink_metadata guard does not — a symlinked
        // lockfile must refuse fail-closed rather than write through the
        // link.
        let dir = TempDir::new().unwrap();
        write(dir.path(), "real.lock", "https://patch.example/a\n").await;
        std::os::unix::fs::symlink(
            dir.path().join("real.lock"),
            dir.path().join("composer.lock"),
        )
        .unwrap();
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
        assert_eq!(out.refusals.len(), 1, "{out:?}");
        assert_eq!(
            out.refusals[0].reason,
            "composer.lock is not a regular file"
        );
        assert_eq!(
            read(dir.path(), "real.lock").await,
            "https://patch.example/a\n",
            "the symlink target must stay byte-identical"
        );
        assert_eq!(state.edits.len(), 1, "the edit must survive for a retry");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn write_failure_at_flush_refuses_late_and_keeps_the_ledger() {
        // Root bypasses mode bits (CI containers) — skip there.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        write(dir.path(), "composer.lock", "https://patch.example/a\n").await;
        // The flush is an atomic stage + rename, so a read-only TARGET no
        // longer blocks it (rename needs only the parent): make the parent
        // directory read-only so the stage file cannot be created.
        let writable = std::fs::metadata(dir.path()).unwrap().permissions();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
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
        // Restore before asserting so the TempDir can clean up on failure.
        std::fs::set_permissions(dir.path(), writable).unwrap();
        assert_eq!(out.refusals.len(), 1, "{out:?}");
        assert!(
            out.refusals[0].reason.starts_with("write composer.lock:"),
            "{}",
            out.refusals[0].reason
        );
        assert_eq!(state.edits.len(), 1, "the edit must survive for a retry");
        assert_eq!(
            read(dir.path(), "composer.lock").await,
            "https://patch.example/a\n",
            "the redirected fragment must still be present"
        );
        let litter: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".socket-stage-"))
            .collect();
        assert!(litter.is_empty(), "no stage litter on failure: {litter:?}");
    }

    /// The text flush goes through the mode-preserving atomic writer: a
    /// `0600` lockfile keeps its bits across the revert (the plain writer
    /// would swap in a fresh umask-mode inode).
    #[cfg(unix)]
    #[tokio::test]
    async fn flush_keeps_the_lockfile_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        write(dir.path(), "composer.lock", "https://patch.example/a\n").await;
        let path = dir.path().join("composer.lock");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
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
        assert!(out.fully_reverted(), "{:?}", out.refusals);
        assert_eq!(
            read(dir.path(), "composer.lock").await,
            "https://upstream.example/a\n"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "the lockfile's mode must survive the atomic rewrite"
        );
    }

    /// A Hatch document already at its recorded original (an interrupted
    /// earlier revert, or a hand-fix) retires its ledger edit without a
    /// byte-identical rewrite or an `editedFiles` credit — the same rule the
    /// PipenvEntry and ReplaceFragment arms follow.
    #[tokio::test]
    async fn hatch_document_already_at_original_retires_without_a_write() {
        let original = "[project]\nname = \"app\"\ndependencies = [\"one==1\"]\n";
        let redirected =
            "[project]\nname = \"app\"\ndependencies = [\"one @ https://patch.example/one.whl\"]\n";
        let dir = TempDir::new().unwrap();
        write(dir.path(), "pyproject.toml", original).await;
        let mut state = state_with(
            vec![edit(
                "pyproject.toml",
                "redirect_hatch_document",
                "rewritten",
                Some(original),
                Some(redirected),
            )],
            &[],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted(), "{:?}", out.refusals);
        assert!(
            out.reverted_files.is_empty(),
            "nothing was written: {out:?}"
        );
        assert!(state.edits.is_empty(), "the edit still retires");
        assert_eq!(read(dir.path(), "pyproject.toml").await, original);
    }

    // ---------- record hold/drop per purl ecosystem ----------

    #[tokio::test]
    async fn cargo_and_composer_records_drop_when_their_groups_replay_clean() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "Cargo.lock",
            "source = \"sparse+https://patch.example/\"\n",
        )
        .await;
        write(dir.path(), "composer.lock", "https://patch.example/a\n").await;
        let mut state = state_with(
            vec![
                edit(
                    "Cargo.lock",
                    "redirect_cargo_lock_entry",
                    "rewritten",
                    Some("source = \"registry+https://github.com/rust-lang/crates.io-index\""),
                    Some("source = \"sparse+https://patch.example/\""),
                ),
                edit(
                    "composer.lock",
                    "redirect_composer_dist",
                    "rewritten",
                    Some("https://upstream.example/a"),
                    Some("https://patch.example/a"),
                ),
            ],
            &["pkg:cargo/cfg-if@1.0.0", "pkg:composer/a/b@1"],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert!(out.fully_reverted(), "{:?}", out.refusals);
        assert_eq!(
            out.dropped_records,
            vec!["pkg:cargo/cfg-if@1.0.0", "pkg:composer/a/b@1"]
        );
        assert!(state.records.is_empty());
        assert!(state.edits.is_empty());
    }

    #[tokio::test]
    async fn nuget_and_unknown_ecosystem_records_are_held_by_their_refusals() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "packages.lock.json", "{}\n").await;
        let mut state = state_with(
            vec![
                edit(
                    "packages.lock.json",
                    "redirect_nuget_lock",
                    "rewritten",
                    Some("a"),
                    Some("b"),
                ),
                edit(
                    "f",
                    "redirect_future_thing",
                    "rewritten",
                    Some("a"),
                    Some("b"),
                ),
            ],
            &["pkg:nuget/A@1", "pkg:hex/x@1"],
        );
        let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
        assert_eq!(out.refusals.len(), 2, "{out:?}");
        assert!(
            state.records.contains_key("pkg:nuget/A@1"),
            "a nuget record must be held while its Unsupported edits refuse"
        );
        assert!(
            state.records.contains_key("pkg:hex/x@1"),
            "an unknown-ecosystem record is tied to the reserved unknown group"
        );
        assert!(out.dropped_records.is_empty());
        assert_eq!(state.edits.len(), 2);
    }

    // ---------- remove_fragment_once unit pins ----------

    #[test]
    fn remove_fragment_once_keeps_crlf_separators_straight() {
        assert_eq!(
            remove_fragment_once("[net]\r\nretry = 2\r\n\r\nF\r\nG\r\n", "F\r\nG\r\n"),
            "[net]\r\nretry = 2\r\n"
        );
        assert_eq!(
            remove_fragment_once("a\r\n\r\nF\r\n\r\nb\r\n", "F\r\n"),
            "a\r\n\r\nb\r\n"
        );
    }

    #[test]
    fn remove_appended_cargo_block_inverts_exactly_what_was_appended() {
        let block = "[registries.r]\nindex = \"i\"\n";
        for (written, fragment, want) in [
            // Empty config: the block alone (a created file ends empty).
            (block.to_string(), block.to_string(), ""),
            // One separator after a config ending in newline(s).
            (format!("a\n\n{block}"), block.to_string(), "a\n"),
            (format!("a\n\n\n{block}"), block.to_string(), "a\n\n"),
            // No final newline: the added newline rides in the fragment.
            (format!("a\n\n{block}"), format!("\n{block}"), "a"),
            // The user appended after the block: kept.
            (
                format!("a\n\n{block}b = 1\n"),
                block.to_string(),
                "a\nb = 1\n",
            ),
            // CRLF file, and a CRLF-recorded fragment against an LF file.
            (
                format!("a\r\n\r\n{}", block.replace('\n', "\r\n")),
                block.replace('\n', "\r\n"),
                "a\r\n",
            ),
            (format!("a\n\n{block}"), block.replace('\n', "\r\n"), "a\n"),
            (
                format!("a\r\n\r\n{}", block.replace('\n', "\r\n")),
                block.to_string(),
                "a\r\n",
            ),
        ] {
            assert_eq!(
                remove_appended_cargo_block(&written, &fragment).as_deref(),
                Some(want),
                "{written:?}"
            );
        }
        assert_eq!(remove_appended_cargo_block("a\n", block), None);
    }

    #[test]
    fn remove_fragment_once_absent_fragment_is_identity() {
        // Defensive edge: callers check contains() first, so the not-found
        // arm must be a pure no-op if that invariant ever breaks.
        assert_eq!(remove_fragment_once("a\nb\n", "zzz"), "a\nb\n");
    }

    #[test]
    fn remove_fragment_once_sole_content_collapses_to_empty() {
        // EOF removal of the only content: the trailing-separator collapse
        // must yield an empty file, not a lone newline.
        assert_eq!(remove_fragment_once("F\n", "F"), "");
        assert_eq!(remove_fragment_once("\nF\n", "F"), "");
    }
    #[tokio::test]
    async fn pipenv_replay_restores_categories_and_refuses_drift_atomically() {
        use crate::patch::redirect::{rewrite_registry_redirect, DepOverride};
        let dep: DepOverride=serde_json::from_value(serde_json::json!({"ecosystem":"pypi","name":"urllib3","version":"1.26.18","patchUuid":"one","token":"token","artifactUrl":"https://patch.socket.dev/patch/pypi/urllib3/1.26.18/token/one/urllib3-1.26.18-py3-none-any.whl","integrity":{"sha256":"a".repeat(64)}})).unwrap();
        let original="{\"_meta\":{\"pipfile-spec\":6},\"default\":{\"urllib3\":{\"version\":\"==1.26.18\"}},\"tests\":{\"urllib3\":{\"version\":\"==1.26.18\"}}}";
        let result = rewrite_registry_redirect(
            &BTreeMap::from([("Pipfile.lock".into(), original.into())]),
            &[dep],
        );
        for drift in [false, true] {
            let dir = TempDir::new().unwrap();
            let text = result.files["Pipfile.lock"].clone();
            // Drift = the REFERENCE itself changed (its `#sha256=` pin here);
            // a hashes-only change next to an intact reference is what a
            // Pipenv relock does and rolls back (see pipenv::restore).
            let live = if drift {
                text.replacen("#sha256=", "#sha256=0", 1)
            } else {
                text
            };
            write(dir.path(), "Pipfile.lock", &live).await;
            let mut state = state_with(result.edits.clone(), &["pkg:pypi/urllib3@1.26.18"]);
            let before = state.edits.len();
            let preview = revert_remaining_redirect_edits(dir.path(), &mut state, true).await;
            assert_eq!(preview.fully_reverted(), !drift);
            assert_eq!(read(dir.path(), "Pipfile.lock").await, live);
            assert_eq!(state.edits.len(), before);
            let outcome = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
            assert_eq!(outcome.fully_reverted(), !drift);
            assert_eq!(
                read(dir.path(), "Pipfile.lock").await,
                if drift { live.as_str() } else { original }
            );
            assert_eq!(state.edits.is_empty(), !drift);
        }
    }
}
