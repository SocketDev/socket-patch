//! The hosted planner: repoint every instance of a patched `name@version`
//! across a project's pnpm lock set at its Socket-hosted tarball, as
//! resolution splices over the [`super::grammar`] entries (the redirect
//! rewriter's pnpm leg).

use std::borrow::Cow;
use std::collections::BTreeMap;

use serde_json::Value;

use crate::patch::redirect::{full_name, DepOverride, FileEdit, RewriteResult, RewriteWarning};

use super::grammar as pnpm;

/// Whether `entry` resolves to exactly `artifact_url` — the per-instance
/// residual-gate predicate.
fn pnpm_resolves_to(entry: &pnpm::Entry<'_>, artifact_url: &str) -> bool {
    pnpm::resolution(entry).is_some_and(|r| r.tarball() == Some(artifact_url))
}

/// One pnpm lock under rewrite. `text` is the lock as of the last
/// materialization; `pending` holds the resolution splices committed since,
/// in `text`'s byte coordinates, and `spliced` the entries they touch.
///
/// The logical (post-splice) lock is `text` with `pending` applied. Parsing
/// once and indexing is sound because a resolution splice never changes the
/// entry structure: the replaced range and its replacement are only
/// resolution-field material (6-space-indented `k: v` child lines of a block
/// resolution, or the `{…}` flow value after `    resolution:`), and no raw
/// newline can enter a value (`Resolution::rewrite` JSON-quotes whitespace).
/// So every column-0 line (the shrinkwrap-version sniff) and every entry
/// boundary line survives unchanged, and an entry no pending splice touched
/// has byte-identical key and body. An entry that WAS touched is re-read
/// only after materializing, so a later dep with the same name@version (a
/// duplicate override) sees the rewritten text exactly as before.
struct PnpmLockState<'f> {
    path: &'f String,
    text: Cow<'f, str>,
    early_shrinkwrap: bool,
    /// (key span, body span) per `packages:` entry, in file order.
    entries: Vec<(std::ops::Range<usize>, std::ops::Range<usize>)>,
    /// Entry indices sorted by normalized (unquoted, `/`-stripped) key.
    sorted: Vec<usize>,
    pending: Vec<(std::ops::Range<usize>, String)>,
    spliced: std::collections::HashSet<usize>,
    changed: bool,
}

impl<'f> PnpmLockState<'f> {
    fn new(path: &'f String, text: &'f str) -> Self {
        let mut state = PnpmLockState {
            path,
            text: Cow::Borrowed(text),
            early_shrinkwrap: pnpm::unsupported_early_shrinkwrap(text),
            entries: Vec::new(),
            sorted: Vec::new(),
            pending: Vec::new(),
            spliced: Default::default(),
            changed: false,
        };
        state.reindex();
        state
    }

    fn reindex(&mut self) {
        let text: &str = &self.text;
        let base = text.as_ptr() as usize;
        self.entries = pnpm::entries(text)
            .iter()
            .map(|e| {
                let key_start = e.key.as_ptr() as usize - base;
                (
                    key_start..key_start + e.key.len(),
                    e.offset..e.offset + e.body.len(),
                )
            })
            .collect();
        let mut sorted: Vec<usize> = (0..self.entries.len()).collect();
        sorted.sort_by(|&a, &b| self.norm_key(a).cmp(self.norm_key(b)).then(a.cmp(&b)));
        self.sorted = sorted;
    }

    fn entry(&self, i: usize) -> pnpm::Entry<'_> {
        let (key, body) = &self.entries[i];
        pnpm::Entry {
            key: &self.text[key.clone()],
            body: &self.text[body.clone()],
            offset: body.start,
        }
    }

    /// The key as [`pnpm::suffix`] compares it.
    fn norm_key(&self, i: usize) -> &str {
        let key = pnpm::unquote(&self.text[self.entries[i].0.clone()]);
        key.strip_prefix('/').unwrap_or(key)
    }

    /// Entries whose key names `fname@version` (any suffix), in file order —
    /// the same set a full [`pnpm::suffix`] scan of the logical lock yields.
    fn hits(&mut self, fname: &str, version: &str) -> Vec<usize> {
        let hits = self.lookup(fname, version);
        if hits.iter().any(|i| self.spliced.contains(i)) {
            self.materialize();
            return self.lookup(fname, version);
        }
        hits
    }

    fn lookup(&self, fname: &str, version: &str) -> Vec<usize> {
        let mut out = Vec::new();
        for sep in ['@', '/'] {
            let prefix = format!("{fname}{sep}{version}");
            let start = self
                .sorted
                .partition_point(|&i| self.norm_key(i) < prefix.as_str());
            out.extend(
                self.sorted[start..]
                    .iter()
                    .take_while(|&&i| self.norm_key(i).starts_with(prefix.as_str()))
                    .copied(),
            );
        }
        out.sort_unstable();
        out.dedup();
        out.retain(|&i| pnpm::suffix(self.entry(i).key, fname, version).is_some());
        out
    }

    /// Fold `pending` into `text` and re-parse.
    fn materialize(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        #[cfg(debug_assertions)]
        let keys_before: Vec<String> = (0..self.entries.len())
            .map(|i| self.entry(i).key.to_string())
            .collect();
        let mut pending = std::mem::take(&mut self.pending);
        pending.sort_by_key(|(range, _)| range.start);
        let mut out = String::with_capacity(self.text.len());
        let mut cursor = 0usize;
        for (range, replacement) in pending {
            out.push_str(&self.text[cursor..range.start]);
            out.push_str(&replacement);
            cursor = range.end;
        }
        out.push_str(&self.text[cursor..]);
        self.text = Cow::Owned(out);
        self.spliced.clear();
        self.reindex();
        #[cfg(debug_assertions)]
        debug_assert_eq!(
            keys_before,
            (0..self.entries.len())
                .map(|i| self.entry(i).key.to_string())
                .collect::<Vec<_>>(),
            "a resolution splice changed the pnpm entry structure"
        );
    }

    fn into_rewritten(mut self) -> Option<(&'f String, String)> {
        if !self.changed {
            return None;
        }
        self.materialize();
        Some((self.path, self.text.into_owned()))
    }
}

pub(crate) fn plan_hosted(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    let npm: Vec<&DepOverride> = overrides.iter().filter(|o| o.ecosystem == "npm").collect();
    // A pnpm lock lives at the project root or at any nested path (e.g. Rush
    // repos keep them under `common/config/rush/`); every such files-map key
    // is rewritten under the same grammar. Deterministic order: BTreeMap
    // iterates keys sorted, so goldens are stable across every lock in the set.
    let lock_keys: Vec<&String> = files
        .keys()
        .filter(|k| {
            matches!(
                k.rsplit('/').next(),
                Some("pnpm-lock.yaml" | "shrinkwrap.yaml")
            )
        })
        .collect();
    if npm.is_empty() || lock_keys.is_empty() {
        return;
    }
    // Each lock is parsed and indexed ONCE; splices accumulate per lock and
    // are applied in one pass at the end (see `PnpmLockState`).
    let mut locks: Vec<PnpmLockState> = lock_keys
        .iter()
        .map(|k| PnpmLockState::new(k, &files[*k]))
        .collect();
    for dep in &npm {
        let fname = full_name(dep);
        let hits: Vec<Vec<usize>> = locks
            .iter_mut()
            .map(|lock| lock.hits(&fname, &dep.version))
            .collect();
        let unsafe_locks: Vec<_> = locks
            .iter()
            .zip(&hits)
            .filter(|(lock, hits)| lock.early_shrinkwrap && !hits.is_empty())
            .map(|(lock, _)| lock.path.as_str())
            .collect();
        if !unsafe_locks.is_empty() {
            result.refused_pnpm_uuids.insert(dep.patch_uuid.clone());
            result.warnings.push(RewriteWarning {
                code: "redirect_pnpm_legacy_lockfile_unsupported".into(),
                detail: format!("{} uses early pnpm 1 shrinkwrapVersion 3 without a supported minor version. Those installers discard hosted tarball URLs; {fname}@{} was left unchanged in every lock. Upgrade to a tested pnpm release (1.43.1 or newer) and regenerate the lock, or use `scan --mode agent` for installed-file patching.", unsafe_locks.join(", "), dep.version),
            });
            continue;
        }
        let Some(sha512) = dep.integrity.sha512.clone() else {
            result.warnings.push(RewriteWarning {
                code: "redirect_pnpm_missing_sha512".into(),
                detail: format!("{fname}@{} has no sha512 integrity", dep.version),
            });
            continue;
        };
        // Every peer instance must be redirected, including nested peer
        // contexts and the block resolutions emitted by pnpm 1–5.
        let mut matched_any = false;
        // Per-lock rewrites are PLANNED first and committed only after the
        // residual gate below proves no instance of this dep escaped the
        // splice grammar in ANY lock — committing lock-by-lock as we go
        // would ship exactly the partial rewrite the gate exists to refuse.
        type Splice = (usize, std::ops::Range<usize>, String);
        let mut planned: Vec<(usize, Vec<Splice>, Vec<FileEdit>)> = Vec::new();
        let mut residuals: Vec<(&str, Vec<String>)> = Vec::new();
        for (idx, (lock, hits)) in locks.iter().zip(&hits).enumerate() {
            // (entry, byte range to replace, replacement text) per instance,
            // plus one FileEdit per instance keyed by the canonical instance
            // key — per-instance edits keep the revert ledger lossless when
            // several instances of one dep live in the same lock.
            let mut splices: Vec<Splice> = Vec::new();
            let mut instance_edits: Vec<FileEdit> = Vec::new();
            // Residual gate, judged per instance on its POST-splice body:
            // any instance of this exact name@version still resolving
            // somewhere other than the hosted artifact — in a spelling the
            // splice grammar cannot parse (e.g. an unbalanced peer suffix) —
            // makes this a partial rewrite. Shipping it would confirm and
            // VEX-attest the dep while dependents through the unmatched
            // instance keep installing the unpatched upstream tarball, so
            // the dep is refused instead.
            let mut leftover: Vec<String> = Vec::new();
            for &i in hits {
                let entry = lock.entry(i);
                let suffix = pnpm::suffix(entry.key, &fname, &dep.version)
                    .expect("hits only holds entries naming this dep");
                let resolution = if pnpm::supported_suffix(suffix) {
                    pnpm::resolution(&entry)
                } else {
                    None
                };
                let Some(resolution) = resolution else {
                    if !pnpm_resolves_to(&entry, &dep.artifact_url) {
                        leftover.push(entry.key.to_string());
                    }
                    continue;
                };
                matched_any = true;
                let original = &lock.text[resolution.range.clone()];
                let rebuilt = resolution.rewrite(&sha512, &dep.artifact_url);
                let rel =
                    resolution.range.start - entry.offset..resolution.range.end - entry.offset;
                let body = format!(
                    "{}{rebuilt}{}",
                    &entry.body[..rel.start],
                    &entry.body[rel.end..]
                );
                let after = pnpm::Entry {
                    key: entry.key,
                    body: &body,
                    offset: 0,
                };
                if !pnpm_resolves_to(&after, &dep.artifact_url) {
                    leftover.push(entry.key.to_string());
                }
                if rebuilt == original {
                    continue;
                }
                instance_edits.push(FileEdit {
                    path: lock.path.clone(),
                    kind: "redirect_pnpm_resolution".into(),
                    action: "rewritten".into(),
                    key: Some(format!("{fname}@{}{suffix}", dep.version)),
                    original: Some(Value::String(original.to_string())),
                    new: Some(Value::String(rebuilt.clone())),
                });
                splices.push((i, resolution.range, rebuilt));
            }
            if !leftover.is_empty() {
                residuals.push((lock.path.as_str(), leftover));
                continue;
            }
            if !splices.is_empty() {
                planned.push((idx, splices, instance_edits));
            }
        }
        // ANY residual anywhere refuses the dep across the WHOLE lock set —
        // nothing rewritten, nothing recorded, nothing confirmed: a rewrite
        // committed in one lock while another still resolves the dep
        // upstream would confirm the dep set-wide.
        if !residuals.is_empty() {
            result.refused_pnpm_uuids.insert(dep.patch_uuid.clone());
            for (lock_key, keys) in &residuals {
                result.warnings.push(RewriteWarning {
                    code: "redirect_pnpm_unsupported_lock_key".into(),
                    detail: format!(
                        "{fname}@{} still resolves through pnpm lock key(s) whose \
                         resolution the redirect grammar cannot repoint: {} in \
                         {lock_key}; the dep is left unredirected in EVERY lock \
                         (nothing rewritten, nothing confirmed) — regenerate the \
                         lock with a current pnpm (lockfileVersion 9) and re-run",
                        dep.version,
                        keys.join(", ")
                    ),
                });
            }
            continue;
        }
        for (idx, splices, mut instance_edits) in planned {
            let lock = &mut locks[idx];
            for (i, range, replacement) in splices {
                lock.spliced.insert(i);
                lock.pending.push((range, replacement));
            }
            lock.changed = true;
            result.edits.append(&mut instance_edits);
        }
        // The entry-not-found warning fires only when the dep matched in NO
        // pnpm lock across the whole set, not once per lock. A VENDORED dep
        // is named as such: `socket-patch vendor` removes the registry
        // resolution this grammar looks for (v9 respells the packages key
        // `<name>@file:.socket/vendor/…`; v5/v6 rekey it to a bare `file:`
        // key but keep the `<name>@<version>: file:…` overrides line), so
        // the generic not-locked wording would send users on a wild-goose
        // `pnpm install` when the real path is a mode switch. Fail-closed
        // either way: nothing is rewritten for the dep.
        if !matched_any {
            let v9_vendored_key = format!("{fname}@file:");
            let override_key = format!("{fname}@{}", dep.version);
            // Scanned over the post-splice text, so fold pending splices in.
            for lock in locks.iter_mut() {
                lock.materialize();
            }
            let vendored = locks.iter().any(|lock| {
                lock.text.lines().any(|line| {
                    let t = line.trim_start();
                    let t = t.strip_prefix('\'').unwrap_or(t);
                    // v9 packages/snapshots key (leading `/` in v6 spelling).
                    // The vendor backend always writes the RELATIVE
                    // `file:.socket/vendor/…` spelling here, so anchoring on
                    // it keeps a user's own `file:` dep of the same name
                    // from being misreported as vendored.
                    let key = t.strip_prefix('/').unwrap_or(t);
                    if key
                        .strip_prefix(&v9_vendored_key)
                        .is_some_and(|rest| rest.starts_with(".socket/vendor/"))
                    {
                        return true;
                    }
                    // overrides / root-dep line: `<name>@<version>: file:…`
                    // (pnpm <=8 absolutizes the value, so only the
                    // `.socket/vendor/` tail is stable enough to match).
                    t.strip_prefix(&override_key)
                        .map(|rest| rest.strip_prefix('\'').unwrap_or(rest))
                        .and_then(|rest| rest.strip_prefix(':'))
                        .is_some_and(|rest| {
                            rest.contains("file:") && rest.contains(".socket/vendor/")
                        })
                })
            });
            if vendored {
                result.warnings.push(RewriteWarning {
                    code: "redirect_pnpm_entry_vendored".into(),
                    detail: format!(
                        "{fname}@{} has no registry resolution because it is \
                         VENDORED (the lock resolves it to a \
                         file:.socket/vendor/… tarball); the hosted redirect \
                         does not apply — run `socket-patch vendor --revert` to \
                         restore the registry resolution, then re-run `scan \
                         --mode hosted`",
                        dep.version
                    ),
                });
            } else {
                result.warnings.push(RewriteWarning {
                    code: "redirect_pnpm_entry_not_found".into(),
                    detail: format!("no resolution for {fname}@{}", dep.version),
                });
            }
        }
    }
    for lock in locks {
        if let Some((key, content)) = lock.into_rewritten() {
            result.files.insert(key.clone(), content);
        }
    }
}

/// Test-only reference for the residual gate: every instance of this exact
/// name@version in `content` that does not resolve to `artifact_url`.
/// Production judges the same predicate inline, per instance, on each
/// indexed hit's post-splice body in `plan_hosted`; snapshots and
/// other versions do not participate in resolution.
#[cfg(test)]
pub(crate) fn pnpm_unrewritten_instances(
    content: &str,
    fname: &str,
    version: &str,
    artifact_url: &str,
) -> Vec<String> {
    pnpm::entries(content)
        .into_iter()
        .filter_map(|entry| {
            pnpm::suffix(entry.key, fname, version)?;
            (!pnpm_resolves_to(&entry, artifact_url)).then(|| entry.key.to_string())
        })
        .collect()
}
