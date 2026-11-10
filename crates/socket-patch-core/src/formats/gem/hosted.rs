//! The hosted planner's Bundler-lock leg: converge a redirected gem's source
//! attribution (its spec block moved into a patch-registry `GEM` section,
//! DEPENDENCIES source-pinned) as a line splice that keeps every line's own
//! `\r\n` / `\n` ending. Sections, remotes and DEPENDENCIES entries are
//! located with the parent's read model ([`super::parse`]); the splice
//! itself works on the lock's `split_inclusive('\n')` lines, which the
//! model's line numbers index.

use std::borrow::Cow;

use regex::Regex;
use serde_json::Value;

use super::Section;
use crate::patch::redirect::{gem_index_url_pattern, DepOverride, FileEdit, RewriteResult};

/// A lock line without its `\r?\n` ending (never more than one of each).
fn gem_lock_line_content(line: &str) -> &str {
    let line = line.strip_suffix('\n').unwrap_or(line);
    line.strip_suffix('\r').unwrap_or(line)
}

/// Move `GEM` section `sec_idx` (whose remote now reads `index_url`) to
/// where bundler writes it: before the first other section whose
/// identifier sorts after `index_url`, else after the last one. The section
/// moves whole, its lines keeping their own endings. Returns false (nothing
/// touched) when it already sits there.
fn place_gem_section_sorted<'a>(
    lines: &mut Vec<Cow<'a, str>>,
    sections: &[&Section<'_>],
    sec_idx: usize,
    index_url: &str,
    eol: &'a str,
) -> bool {
    let others = || (0..sections.len()).filter(|&k| k != sec_idx);
    let before = others().find(|&k| sections[k].identifier().as_str() > index_url);
    if before == others().find(|&k| k > sec_idx) {
        return false;
    }
    let range = sections[sec_idx].lines();
    let (start, end) = (range.start, range.end);
    let mut block: Vec<Cow<'a, str>> = lines.drain(start..end).collect();
    let n = block.len();
    // The moved section needs its own blank separator (and a final newline
    // if it was the file's last line).
    if let Some(last) = block.last_mut() {
        if !last.ends_with('\n') {
            last.to_mut().push_str(eol);
        }
        if !gem_lock_line_content(last).is_empty() {
            block.push(Cow::Borrowed(eol));
        }
    }
    let shifted = |at: usize| if at > start { at - n } else { at };
    let at = match before {
        Some(k) => shifted(sections[k].lines().start),
        None => {
            let last = others()
                .next_back()
                .expect("a section sorts before this one");
            shifted(sections[last].end)
        }
    };
    lines.splice(at..at, block);
    true
}

/// What a redirected gem's `DEPENDENCIES` entry reads once it is
/// source-pinned.
#[derive(Debug, Clone, Copy)]
pub(crate) enum DependencyPin<'a> {
    /// The manifest keeps the user's own declaration and gains a `source:`
    /// option, so the entry bundler wrote for it stays and gains the `!`
    /// (`rack (~> 2.2.3)` → `rack (~> 2.2.3)!`). A gem the manifest did not
    /// declare is added as `name (= <version>)!`, what bundler writes for
    /// the `gem "<name>", "<version>", source: …` line the rewriter adds.
    Keep,
    /// The `source … do` block of socket-patch 5.0 / 5.1, which declares
    /// `gem "<name>", "<version>"`: the entry reads `name (<requirement>)!`
    /// (`= <version>`, plus any gemspec development dependency bundler 2.7+
    /// merges in, see [`super::gemspec`]).
    Exact(&'a str),
}

/// Source-pin `dep`'s `DEPENDENCIES` entry in `lines` (the lock's
/// `split_inclusive('\n')` lines) as `pin` says, recording the edit.
/// Bundler keeps the section sorted by name, so a new entry goes before the
/// first one that sorts after it, and never past the section's blank
/// separator. Returns whether a line changed.
fn pin_dependency<'a>(
    lines: &mut Vec<Cow<'a, str>>,
    deps: &super::Dependencies<'_>,
    dep: &DepOverride,
    pin: DependencyPin<'_>,
    eol: &'a str,
    lock_name: &str,
    result: &mut RewriteResult,
) -> bool {
    let entry_idx = deps
        .entries
        .iter()
        .find(|entry| entry.name == dep.name)
        .map(|entry| entry.line_no - 1);
    let target = match (pin, entry_idx) {
        (DependencyPin::Exact(requirement), _) => format!("  {} ({requirement})!", dep.name),
        (DependencyPin::Keep, Some(k)) => {
            let entry = gem_lock_line_content(&lines[k]).trim_end();
            format!("{}!", entry.strip_suffix('!').unwrap_or(entry))
        }
        (DependencyPin::Keep, None) => format!("  {} (= {})!", dep.name, dep.version),
    };
    let new = Value::String(target.trim_start().to_string());
    match entry_idx {
        Some(k) if gem_lock_line_content(&lines[k]) == target => false,
        Some(k) => {
            let old = gem_lock_line_content(&lines[k]).trim_start().to_string();
            let ending = lines[k][gem_lock_line_content(&lines[k]).len()..].to_string();
            lines[k] = Cow::Owned(format!("{target}{ending}"));
            result.edits.push(FileEdit {
                path: lock_name.into(),
                kind: "redirect_gemfile_lock_dependency_pin".into(),
                action: "rewritten".into(),
                key: Some(dep.name.clone()),
                original: Some(Value::String(old)),
                new: Some(new),
            });
            true
        }
        None => {
            let next_entry = deps
                .entries
                .iter()
                .find(|entry| entry.name > dep.name.as_str())
                .map(|entry| entry.line_no - 1);
            let separator =
                (deps.line_no..deps.end).find(|&k| gem_lock_line_content(&lines[k]).is_empty());
            let at = next_entry
                .into_iter()
                .chain(separator)
                .min()
                .unwrap_or(deps.end);
            // After a last entry that ended the file without a line break:
            // that entry gets one, and the new last line stays without.
            if at > 0 && at == lines.len() && !lines[at - 1].ends_with('\n') {
                lines[at - 1].to_mut().push_str(eol);
                lines.insert(at, Cow::Owned(target));
            } else {
                lines.insert(at, Cow::Owned(format!("{target}{eol}")));
            }
            result.edits.push(FileEdit {
                path: lock_name.into(),
                kind: "redirect_gemfile_lock_dependency_pin".into(),
                action: "added".into(),
                key: Some(dep.name.clone()),
                original: None,
                new: Some(new),
            });
            true
        }
    }
}

/// Converge the lock's source attribution for one redirected dep so the
/// Gemfile + lock pair is what bundler >= 2.2 itself writes after an
/// install from the redirected Gemfile (verified byte for byte against
/// `bundle lock` on bundler 2.4.22, 2.5.23 and 4.0.15, and
/// frozen-installable on each): the dep's spec entry (+ its dependency
/// sublines) moves out of the upstream `GEM` section into a patch-registry
/// `GEM` section (`remote: <index-url>`), and DEPENDENCIES source-pins the
/// gem as `pin` says. Without this the pair is MIXED: the lock still
/// attributes the gem to the upstream remote, so a frozen install exits 16
/// and, on a `CHECKSUMS` lock, an unfrozen one exits 37 "mismatched
/// checksums".
///
/// Idempotent and rotation-aware: a section whose remote matches the
/// token-wildcard pattern is recognized as ours (never duplicated) and its
/// remote is refreshed under a rotated grant or superseding patch
/// (`redirect_gemfile_lock_source_url`, mirroring the Gemfile refresh); the
/// section then moves to bundler's sorted position if the new URL sorts
/// elsewhere (`redirect_gemfile_lock_section_order`).
///
/// `Ok` when the lock ends converged (already, or via edits recorded into
/// `result`); `Err` with the reason when the dep cannot be attributed
/// safely — spec entry absent or duplicated, a legacy multi-remote `GEM`
/// section, or no DEPENDENCIES section — in which case nothing is touched.
pub(crate) fn converge_gem_lock_source(
    lk: &mut String,
    dep: &DepOverride,
    index_url: &str,
    lock_name: &str,
    pin: DependencyPin<'_>,
    lock_changed: &mut bool,
    result: &mut RewriteResult,
) -> Result<(), String> {
    let eol = crate::utils::line_endings::terminator(lk);
    // Borrowed until edited: most of a large lock's lines are only moved.
    let mut lines: Vec<Cow<'_, str>> = lk.split_inclusive('\n').map(Cow::Borrowed).collect();
    // Locate: GEM sections, the dep's 4-space spec entry, DEPENDENCIES.
    let model = super::parse(lk);
    let sections: Vec<&Section<'_>> = model.gem_sections().collect();
    let spec_raw = format!("{} ({})", dep.name, dep.version);
    let spec_at: Vec<(usize, usize)> = sections // (section idx, line idx)
        .iter()
        .enumerate()
        .flat_map(|(k, section)| {
            section
                .specs
                .iter()
                .filter(|spec| spec.raw == spec_raw)
                .map(move |spec| (k, spec.line_no - 1))
        })
        .collect();
    let Some(deps) = &model.dependencies else {
        return Err("it has no DEPENDENCIES section".to_string());
    };
    let &[(sec_idx, spec_idx)] = spec_at.as_slice() else {
        return Err(if spec_at.is_empty() {
            format!("no GEM section lists `{spec_raw}`")
        } else {
            format!("more than one GEM section lists `{spec_raw}`")
        });
    };
    // Exclusive of the header.
    let deps_start = deps.line_no;
    if sections[sec_idx].remotes.len() != 1 {
        return Err(format!(
            "the GEM section that lists `{spec_raw}` names {} remotes (the one-section layout \
             of bundler < 2.2, which a later bundler rewrites on its next unfrozen install)",
            sections[sec_idx].remotes.len()
        ));
    }
    // Bundler always writes source sections before DEPENDENCIES — the pin
    // edit below runs first on that premise (its lines sit after the parsed
    // spec/remote/end indices, so they never shift). A hand-edited lock with
    // DEPENDENCIES before the dep's GEM section breaks the premise: the
    // transitive-dep pin INSERT would leave the spec-move splicing on stale
    // indices. Refuse it instead.
    if deps_start < sections[sec_idx].end {
        return Err(format!(
            "its DEPENDENCIES section comes before the GEM section that lists `{spec_raw}`"
        ));
    }
    let remote_idx = sections[sec_idx].remote_line_nos[0] - 1;
    let remote_url = sections[sec_idx].remotes[0].to_string();
    let socket_remote_re = Regex::new(&format!("^{}$", gem_index_url_pattern(dep, index_url)))
        .expect("anchored index-url pattern from the escaped URL is valid");
    let mut changed = false;

    // DEPENDENCIES pin first — its lines sit AFTER the GEM sections, so the
    // spec move below never invalidates these indices (and vice versa would).
    changed |= pin_dependency(&mut lines, deps, dep, pin, eol, lock_name, result);

    if socket_remote_re.is_match(&remote_url) {
        // Already ours. Rotated grant or superseding patch: refresh the
        // remote.
        if remote_url != index_url {
            refresh_remote_line(
                &mut lines, remote_idx, remote_url, index_url, dep, lock_name, result,
            );
            changed = true;
        }
        // The refreshed URL (a superseding patch uuid, a rotated grant) can
        // sort past a sibling `GEM` section, and bundler writes the sections
        // sorted by identifier — the same rule as the fresh insert below.
        // Re-place the whole section; a lock an earlier run left out of
        // order is healed the same way.
        if place_gem_section_sorted(&mut lines, &sections, sec_idx, index_url, eol) {
            result.edits.push(FileEdit {
                path: lock_name.into(),
                kind: "redirect_gemfile_lock_section_order".into(),
                action: "moved".into(),
                key: Some(dep.name.clone()),
                original: None,
                new: Some(Value::String(index_url.to_string())),
            });
            changed = true;
        }
    } else {
        // Move the spec (+ sublines) into a patch-registry section of its
        // own, inserted where bundler itself writes it: bundler emits the
        // rubygems `GEM` sections sorted by source identifier
        // (`SourceList#lock_rubygems_sources`: `sort_by(&:identifier)`, i.e.
        // by the section's remote URLs), so the new section goes before the
        // first `GEM` section whose remotes sort after the index URL, else
        // after the last one. A frozen install re-renders the lock, and
        // since bundler 4.0.19 (rubygems#9750, "fail instead of warning when
        // frozen mode can't update the lockfile") any difference is fatal:
        // "Your lockfile needs to be updated, but it can't be because frozen
        // mode is set". Appending after `https://rubygems.org/` when the
        // patch registry (`https://patch.socket.dev/…`) sorts first would break
        // every converged hosted pair under `BUNDLE_FROZEN` / deployment
        // mode (verified: 4.0.15 installs it, 4.0.21 refuses it).
        let mut last = spec_idx;
        while last + 1 < lines.len()
            && gem_lock_line_content(&lines[last + 1]).starts_with("      ")
        {
            last += 1;
        }
        let moved: Vec<Cow<'_, str>> = lines.drain(spec_idx..=last).collect();
        let n = moved.len();
        // Section bounds after the drain (every drained line sat inside
        // section `sec_idx`, which keeps its start).
        let bounds = |k: usize| -> (usize, usize) {
            let s = sections[k].lines();
            match k.cmp(&sec_idx) {
                std::cmp::Ordering::Less => (s.start, s.end),
                std::cmp::Ordering::Equal => (s.start, s.end - n),
                std::cmp::Ordering::Greater => (s.start - n, s.end - n),
            }
        };
        let insert_at = (0..sections.len())
            .find(|&k| sections[k].identifier().as_str() > index_url)
            .map(|k| bounds(k).0)
            .unwrap_or_else(|| bounds(sections.len() - 1).1);
        let mut block: Vec<Cow<'_, str>> = Vec::with_capacity(moved.len() + 4);
        block.push(Cow::Owned(format!("GEM{eol}")));
        block.push(Cow::Owned(format!("  remote: {index_url}{eol}")));
        block.push(Cow::Owned(format!("  specs:{eol}")));
        for line in moved {
            // Moved lines keep their own bytes; only a final line that lacked
            // a newline (EOF) gains the file's ending.
            if line.ends_with('\n') {
                block.push(line);
            } else {
                block.push(Cow::Owned(format!("{line}{eol}")));
            }
        }
        block.push(Cow::Borrowed(eol));
        lines.splice(insert_at..insert_at, block);
        result.edits.push(FileEdit {
            path: lock_name.into(),
            kind: "redirect_gemfile_lock_gem_source".into(),
            action: "rewritten".into(),
            key: Some(dep.name.clone()),
            original: Some(Value::String(remote_url)),
            new: Some(Value::String(index_url.to_string())),
        });
        changed = true;
    }

    if changed {
        let text = lines.concat();
        drop(lines);
        *lk = text;
        *lock_changed = true;
    }
    Ok(())
}

/// Keep a merged multi-remote `GEM` section (bundler ≤ 2.1, and locks that
/// started there) on the patch the Gemfile now names (#1688). Such a
/// section lists every rubygems remote, so the Socket remote a previous
/// run's prescribed `bundle install` added is attributed to a gem only
/// through the Gemfile's `source … do` block (`vex::discover::gem`, "Merged
/// sections"). When a superseding patch or rotated grant moves that block
/// from `prior_url` to `index_url`, the section's remote must move with it,
/// or discovery sees the block and the lock name different patches and the
/// scan refuses the new pin as unattributable on every run.
///
/// Refreshes only the shape a converged earlier redirect leaves: the dep's
/// spec listed once, in a merged section, which lists `prior_url` (the dep's
/// own block URL, so another gem's Socket remote is never taken) exactly
/// once, and a source-pinned (`!`) DEPENDENCIES entry. The remote keeps its
/// position (bundler orders a merged section's remotes by the Gemfile's
/// declarations, which the in-place Gemfile refresh keeps). Returns true
/// when the section's remote reads `index_url` (already, or via the
/// recorded `redirect_gemfile_lock_source_url` edit); false, touching
/// nothing, for any other shape.
pub(crate) fn refresh_merged_gem_lock_remote(
    lk: &mut String,
    dep: &DepOverride,
    prior_url: &str,
    index_url: &str,
    lock_name: &str,
    lock_changed: &mut bool,
    result: &mut RewriteResult,
) -> bool {
    let model = super::parse(lk);
    if !model.problems.is_empty() || !model.pinned.contains(dep.name.as_str()) {
        return false;
    }
    let spec_raw = format!("{} ({})", dep.name, dep.version);
    let holders: Vec<&Section<'_>> = model
        .gem_sections()
        .filter(|s| s.specs.iter().any(|spec| spec.raw == spec_raw))
        .collect();
    let [sec] = holders.as_slice() else {
        return false;
    };
    if sec.remotes.len() < 2 || sec.specs.iter().filter(|s| s.raw == spec_raw).count() != 1 {
        return false;
    }
    let ours: Vec<(usize, &str)> = sec
        .remotes
        .iter()
        .zip(&sec.remote_line_nos)
        .filter(|(remote, _)| super::same_remote(remote, prior_url))
        .map(|(remote, line_no)| (line_no - 1, *remote))
        .collect();
    let [(remote_idx, remote_url)] = ours.as_slice() else {
        return false;
    };
    if *remote_url != index_url {
        let (remote_idx, remote_url) = (*remote_idx, remote_url.to_string());
        let mut lines: Vec<Cow<'_, str>> = lk.split_inclusive('\n').map(Cow::Borrowed).collect();
        refresh_remote_line(
            &mut lines, remote_idx, remote_url, index_url, dep, lock_name, result,
        );
        let text = lines.concat();
        drop(lines);
        drop(model);
        *lk = text;
        *lock_changed = true;
    }
    true
}

/// Point the `remote:` line `idx` (reading `remote_url`) at `index_url`,
/// keeping its line ending, and record the `redirect_gemfile_lock_source_url`
/// edit a revert reads.
fn refresh_remote_line(
    lines: &mut [Cow<'_, str>],
    idx: usize,
    remote_url: String,
    index_url: &str,
    dep: &DepOverride,
    lock_name: &str,
    result: &mut RewriteResult,
) {
    let ending = lines[idx][gem_lock_line_content(&lines[idx]).len()..].to_string();
    lines[idx] = Cow::Owned(format!("  remote: {index_url}{ending}"));
    result.edits.push(FileEdit {
        path: lock_name.into(),
        kind: "redirect_gemfile_lock_source_url".into(),
        action: "rewritten".into(),
        key: Some(dep.name.clone()),
        original: Some(Value::String(remote_url)),
        new: Some(Value::String(index_url.to_string())),
    });
}

/// Whether the lock's `BUNDLED WITH` names a bundler older than 2.2 — the
/// era that writes one merged `GEM` section, where a refreshed merged
/// section is proven frozen-installable. False when it names none.
pub(crate) fn bundled_before_2_2(lock: &str) -> bool {
    bundled_with(lock).is_some_and(|version| version < (2, 2))
}

/// The `major.minor` of the bundler the lock's `BUNDLED WITH` names, and
/// the version as written.
fn bundled_with_version(lock: &str) -> Option<((u32, u32), &str)> {
    let mut lines = lock.lines().map(|l| l.trim_end_matches('\r'));
    let version = lines
        .by_ref()
        .find(|l| *l == "BUNDLED WITH")
        .and_then(|_| lines.next())
        .map(str::trim)?;
    let mut parts = version.split('.').map(|p| p.parse::<u32>());
    match (parts.next(), parts.next()) {
        (Some(Ok(major)), Some(Ok(minor))) => Some(((major, minor), version)),
        _ => None,
    }
}

fn bundled_with(lock: &str) -> Option<(u32, u32)> {
    bundled_with_version(lock).map(|(version, _)| version)
}

/// How the bundler that wrote a lock records the rubygems sources of a
/// project, which is also the only layout that bundler accepts under
/// frozen / deployment mode (verified on 1.17.2, 2.1.4, 2.4.22, 2.5.23 and
/// 4.0.15: 2.1 refuses the per-source layout with "The list of sources
/// changed", 2.5 and 4.0 refuse the merged one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LockLayout {
    /// Bundler >= 2.2: one `GEM` section per source, sorted by remote.
    PerSource,
    /// Bundler < 2.2: ONE `GEM` section whose `remote:` lines list every
    /// source, in the order the manifest declares them. The version, as
    /// the lock names it.
    Merged(String),
}

/// The layout the bundler that wrote `lock` uses, or `None` when the lock
/// does not say which bundler that was. A `CHECKSUMS` section is only
/// written by bundler >= 2.6; otherwise `BUNDLED WITH` decides; a lock
/// without either is still bundler >= 2.2's when it already holds several
/// single-remote `GEM` sections, which no older bundler writes.
pub(crate) fn lock_layout(lock: &str) -> Option<LockLayout> {
    let model = super::parse(lock);
    if model.has_checksums() {
        return Some(LockLayout::PerSource);
    }
    match bundled_with_version(lock) {
        Some((version, text)) if version < (2, 2) => Some(LockLayout::Merged(text.to_string())),
        Some(_) => Some(LockLayout::PerSource),
        None => {
            let sections: Vec<&Section<'_>> = model.gem_sections().collect();
            (sections.len() > 1 && sections.iter().all(|s| s.remotes.len() == 1))
                .then_some(LockLayout::PerSource)
        }
    }
}

/// Converge a bundler < 2.2 lock ([`LockLayout::Merged`]) for one
/// redirected dep: the patch registry joins the `remote:` lines of the
/// lock's one `GEM` section and DEPENDENCIES source-pins the gem as `pin`
/// says — what that bundler writes itself on an unfrozen install (verified
/// byte for byte on 1.17.2 and 2.1.4).
///
/// The remotes are ordered as the manifest declares its sources, and a
/// frozen install refuses any other order, so the new line's place is read
/// from `manifest_sources` ([`super::declarations::rubygems_sources`] of
/// the manifest as the rewrite leaves it). That reading is trusted only
/// when it also accounts for every remote the lock already lists, in the
/// lock's order; otherwise (a source the manifest computes, an
/// `eval_gemfile`, a stale lock) nothing is touched and the reason comes
/// back as `Err`. So does any lock shape that bundler does not write: no
/// or several `GEM` sections, the spec missing or listed twice, no
/// DEPENDENCIES section.
#[allow(clippy::too_many_arguments)]
pub(crate) fn merge_gem_lock_remote(
    lk: &mut String,
    dep: &DepOverride,
    index_url: &str,
    lock_name: &str,
    manifest_sources: &[String],
    pin: DependencyPin<'_>,
    lock_changed: &mut bool,
    result: &mut RewriteResult,
) -> Result<(), String> {
    let eol = crate::utils::line_endings::terminator(lk);
    let mut lines: Vec<Cow<'_, str>> = lk.split_inclusive('\n').map(Cow::Borrowed).collect();
    let model = super::parse(lk);
    if let Some(problem) = model.problems.first() {
        return Err(problem.clone());
    }
    let sections: Vec<&Section<'_>> = model.gem_sections().collect();
    let [section] = sections.as_slice() else {
        return Err(format!(
            "it has {} GEM sections where that bundler writes one",
            sections.len()
        ));
    };
    let spec_raw = format!("{} ({})", dep.name, dep.version);
    if section.specs.iter().filter(|s| s.raw == spec_raw).count() != 1 {
        return Err(format!(
            "its GEM section does not list {spec_raw} exactly once"
        ));
    }
    let Some(deps) = &model.dependencies else {
        return Err("it has no DEPENDENCIES section".to_string());
    };
    if deps.line_no < section.end || section.remotes.is_empty() {
        return Err("its sections are not in the order bundler writes them".to_string());
    }
    let same = super::same_remote;
    let listed = |url: &str| section.remotes.iter().any(|r| same(r, url));
    // The manifest's sources the lock should list once this gem is wired.
    let want: Vec<&str> = manifest_sources
        .iter()
        .map(String::as_str)
        .filter(|url| listed(url) || same(url, index_url))
        .collect();
    let Some(at) = want.iter().position(|url| same(url, index_url)) else {
        return Err(format!(
            "the manifest does not name {index_url} as a source"
        ));
    };
    let already = listed(index_url);
    let expected: Vec<&str> = want
        .iter()
        .copied()
        .filter(|url| already || !same(url, index_url))
        .collect();
    let agrees = expected.len() == section.remotes.len()
        && expected
            .iter()
            .zip(&section.remotes)
            .all(|(want, have)| same(want, have));
    if !agrees {
        return Err(
            "the remotes its GEM section lists are not the sources the manifest declares, in \
             that order (a source the manifest computes or loads from another file, or a lock \
             that is out of date)"
                .to_string(),
        );
    }
    // The DEPENDENCIES entry sits after the section, so editing it first
    // keeps the remote line numbers valid.
    let mut changed = pin_dependency(&mut lines, deps, dep, pin, eol, lock_name, result);
    if !already {
        let line = Cow::Owned(format!("  remote: {index_url}{eol}"));
        let before = match section.remote_line_nos.get(at) {
            Some(line_no) => line_no - 1,
            None => section.remote_line_nos[section.remote_line_nos.len() - 1],
        };
        lines.insert(before, line);
        result.edits.push(FileEdit {
            path: lock_name.into(),
            kind: "redirect_gemfile_lock_gem_source".into(),
            action: "added".into(),
            key: Some(dep.name.clone()),
            original: None,
            new: Some(Value::String(index_url.to_string())),
        });
        changed = true;
    }
    if changed {
        let text = lines.concat();
        drop(lines);
        drop(model);
        *lk = text;
        *lock_changed = true;
    }
    Ok(())
}

/// The byte span (line content, ending excluded) of the `CHECKSUMS` entry
/// for exactly `name (version)` — the platform-less spec the hosted planner
/// pins — read with the shared entry grammar
/// ([`super::split_checksum_entry`]): a 2-space entry inside the column-0
/// `CHECKSUMS` section, whatever digests it carries (bare, uppercase,
/// several algorithms). The first such entry; `None` when there is none.
/// CRLF endings stay outside the span.
pub(crate) fn checksum_entry_span(lock: &str, name: &str, version: &str) -> Option<(usize, usize)> {
    let mut offset = 0;
    let mut in_checksums = false;
    for line in lock.split_inclusive('\n') {
        let start = offset;
        offset += line.len();
        let content = gem_lock_line_content(line);
        if !content.is_empty() && !content.starts_with(' ') {
            in_checksums = content == "CHECKSUMS";
            continue;
        }
        let Some(entry) = content.strip_prefix("  ").filter(|e| !e.starts_with(' ')) else {
            continue;
        };
        if in_checksums
            && super::split_checksum_entry(entry)
                .is_some_and(|(n, token, _)| n == name && token == version)
        {
            return Some((start, start + content.len()));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patch::redirect::{Integrity, RegistryOverride, RegistryOverrideIdentifiers};

    const INDEX_URL: &str = "https://patch.test/gem/tok/uuid/";

    fn dep(name: &str, version: &str) -> DepOverride {
        DepOverride {
            ecosystem: "gem".into(),
            name: name.into(),
            namespace: None,
            version: version.into(),
            token: "tok".into(),
            patch_uuid: "uuid".into(),
            artifact_url: format!("https://patch.test/{name}-{version}.gem"),
            registry_override: Some(RegistryOverride {
                kind: "rubygems-compact-index".into(),
                index_url: INDEX_URL.into(),
                identifiers: RegistryOverrideIdentifiers {
                    name: name.into(),
                    version: version.into(),
                    ..Default::default()
                },
            }),
            integrity: Integrity::default(),
        }
    }

    /// `(converged, lock after, edit kinds/actions)` for one dep declared
    /// in a 5.0 / 5.1 `source … do` block (the exact pin).
    fn converge(lock: &str, dep: &DepOverride) -> (bool, String, Vec<String>) {
        let exact = format!("= {}", dep.version);
        converge_as(lock, dep, DependencyPin::Exact(&exact))
    }

    fn converge_as(
        lock: &str,
        dep: &DepOverride,
        pin: DependencyPin<'_>,
    ) -> (bool, String, Vec<String>) {
        let mut lk = lock.to_string();
        let mut changed = false;
        let mut result = RewriteResult::default();
        let ok = converge_gem_lock_source(
            &mut lk,
            dep,
            INDEX_URL,
            "Gemfile.lock",
            pin,
            &mut changed,
            &mut result,
        )
        .is_ok();
        assert_eq!(changed, lk != lock, "lock_changed must report a change");
        let edits = result
            .edits
            .iter()
            .map(|e| format!("{}:{}", e.kind, e.action))
            .collect();
        (ok, lk, edits)
    }

    const TWO_SOURCES: &str = "GEM
  remote: https://gems.mirror.example/
  specs:
    nokogiri (1.16.0)
      racc (~> 1.4)

GEM
  remote: https://rubygems.org/
  specs:
    racc (1.7.3)
    rails (7.0.0)
      racc

PLATFORMS
  ruby

DEPENDENCIES
  nokogiri!
  rails (~> 7.0)

BUNDLED WITH
   2.6.2
";

    /// A transitive gem in the SECOND `GEM` section: located through the
    /// shared reader's section spans, moved into a patch-registry section
    /// sorted between the two remotes, and pinned in DEPENDENCIES before the
    /// first entry that sorts after it. CRLF endings are kept line by line.
    #[test]
    fn transitive_gem_in_the_second_gem_section_converges() {
        let expected = "GEM
  remote: https://gems.mirror.example/
  specs:
    nokogiri (1.16.0)
      racc (~> 1.4)

GEM
  remote: https://patch.test/gem/tok/uuid/
  specs:
    racc (1.7.3)

GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.0)
      racc

PLATFORMS
  ruby

DEPENDENCIES
  nokogiri!
  racc (= 1.7.3)!
  rails (~> 7.0)

BUNDLED WITH
   2.6.2
";
        for crlf in [false, true] {
            let spell = |s: &str| {
                if crlf {
                    s.replace('\n', "\r\n")
                } else {
                    s.to_string()
                }
            };
            let (ok, out, edits) = converge(&spell(TWO_SOURCES), &dep("racc", "1.7.3"));
            assert!(ok);
            assert_eq!(out, spell(expected), "crlf={crlf}");
            assert_eq!(
                edits,
                [
                    "redirect_gemfile_lock_dependency_pin:added",
                    "redirect_gemfile_lock_gem_source:rewritten"
                ]
            );
            // Converged is a fixed point.
            let (ok, again, edits) = converge(&out, &dep("racc", "1.7.3"));
            assert!(ok && edits.is_empty(), "{edits:?}");
            assert_eq!(again, out);
        }
    }

    /// A direct gem's DEPENDENCIES entry is found by the shared name rule
    /// whatever its spelling and rewritten to the exact source pin; the spec
    /// moves with its dependency sublines.
    #[test]
    fn direct_gem_entry_spellings_are_rewritten_to_the_source_pin() {
        for entry in ["rails", "rails!", "rails (~> 7.0)", "rails (= 7.0.0)!"] {
            let lock = TWO_SOURCES.replace("  rails (~> 7.0)\n", &format!("  {entry}\n"));
            let (ok, out, edits) = converge(&lock, &dep("rails", "7.0.0"));
            assert!(ok, "{entry}");
            assert!(
                out.contains("DEPENDENCIES\n  nokogiri!\n  rails (= 7.0.0)!\n\n"),
                "{entry}: {out}"
            );
            assert!(
                out.contains(
                    "GEM\n  remote: https://patch.test/gem/tok/uuid/\n  specs:\n    rails (7.0.0)\n      racc\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    racc (1.7.3)\n\n"
                ),
                "{entry}: {out}"
            );
            let pin_edits = edits
                .iter()
                .filter(|e| e.starts_with("redirect_gemfile_lock_dependency_pin"))
                .count();
            assert_eq!(
                pin_edits,
                usize::from(entry != "rails (= 7.0.0)!"),
                "{entry}"
            );
        }
    }

    /// The inline `source:` form keeps the user's declaration, so the entry
    /// bundler wrote for it keeps its requirement and only gains the `!`
    /// (what `bundle lock` writes, verified on 2.5.23 and 4.0.15); a gem
    /// the manifest did not declare is added as an exact pin.
    #[test]
    fn kept_declarations_keep_their_dependencies_entry() {
        for (entry, want) in [
            ("rails", "rails!"),
            ("rails (~> 7.0)", "rails (~> 7.0)!"),
            ("rails (>= 7.0, < 8)", "rails (>= 7.0, < 8)!"),
            ("rails (= 7.0.0)", "rails (= 7.0.0)!"),
        ] {
            for eol in ["\n", "\r\n"] {
                let lock = TWO_SOURCES
                    .replace("  rails (~> 7.0)\n", &format!("  {entry}\n"))
                    .replace('\n', eol);
                let (ok, out, edits) =
                    converge_as(&lock, &dep("rails", "7.0.0"), DependencyPin::Keep);
                assert!(ok, "{entry}");
                assert!(
                    out.contains(&format!(
                        "DEPENDENCIES{eol}  nokogiri!{eol}  {want}{eol}{eol}"
                    )),
                    "{entry}: {out}"
                );
                assert_eq!(
                    edits,
                    [
                        "redirect_gemfile_lock_dependency_pin:rewritten",
                        "redirect_gemfile_lock_gem_source:rewritten"
                    ],
                    "{entry}"
                );
                let (ok, again, edits) =
                    converge_as(&out, &dep("rails", "7.0.0"), DependencyPin::Keep);
                assert!(ok && edits.is_empty() && again == out, "{entry}: {edits:?}");
            }
        }
        let (ok, out, _) = converge_as(TWO_SOURCES, &dep("racc", "1.7.3"), DependencyPin::Keep);
        assert!(ok);
        assert!(
            out.contains("DEPENDENCIES\n  nokogiri!\n  racc (= 1.7.3)!\n  rails (~> 7.0)\n\n"),
            "{out}"
        );
    }

    /// A lock says which layout its bundler writes: CHECKSUMS (>= 2.6),
    /// else BUNDLED WITH, else several single-remote sections (>= 2.2).
    #[test]
    fn lock_layout_reads_the_bundler_that_wrote_the_lock() {
        let lock = |tail: &str| {
            format!("GEM\n  remote: https://rubygems.org/\n  specs:\n    racc (1.7.3)\n\nDEPENDENCIES\n  racc\n{tail}")
        };
        let merged = |v: &str| Some(LockLayout::Merged(v.to_string()));
        assert_eq!(
            lock_layout(&lock("\nBUNDLED WITH\n   1.17.3\n")),
            merged("1.17.3")
        );
        assert_eq!(
            lock_layout(&lock("\nBUNDLED WITH\n   2.1.4\n")),
            merged("2.1.4")
        );
        for version in ["2.2.0", "2.5.23", "4.0.15"] {
            assert_eq!(
                lock_layout(&lock(&format!("\nBUNDLED WITH\n   {version}\n"))),
                Some(LockLayout::PerSource),
                "{version}"
            );
        }
        assert_eq!(
            lock_layout(&lock("\nCHECKSUMS\n  racc (1.7.3) sha256=00\n")),
            Some(LockLayout::PerSource)
        );
        assert_eq!(lock_layout(&lock("")), None);
        assert_eq!(
            lock_layout(&TWO_SOURCES.replace("\nBUNDLED WITH\n   2.6.2\n", "")),
            Some(LockLayout::PerSource)
        );
    }

    /// `(result, lock after, edit kinds/actions)` of the bundler < 2.2
    /// converge for one dep, the manifest naming `sources` in that order.
    fn merge(
        lock: &str,
        dep: &DepOverride,
        sources: &[&str],
        pin: DependencyPin<'_>,
    ) -> (Result<(), String>, String, Vec<String>) {
        let mut lk = lock.to_string();
        let mut changed = false;
        let mut result = RewriteResult::default();
        let sources: Vec<String> = sources.iter().map(|s| s.to_string()).collect();
        let out = merge_gem_lock_remote(
            &mut lk,
            dep,
            INDEX_URL,
            "Gemfile.lock",
            &sources,
            pin,
            &mut changed,
            &mut result,
        );
        assert_eq!(changed, lk != lock, "lock_changed must report a change");
        let edits = result
            .edits
            .iter()
            .map(|e| format!("{}:{}", e.kind, e.action))
            .collect();
        (out, lk, edits)
    }

    /// Bundler < 2.2 (what 1.17.2 and 2.1.4 write): the patch registry
    /// joins the one GEM section's remotes where the manifest declares it,
    /// and the entry gains the `!`. CRLF kept; converged is a fixed point.
    #[test]
    fn merged_lock_gains_the_remote_in_manifest_order() {
        const B: &str = "https://patch.test/gem/tok/other-uuid/";
        let lock = |remotes: &[&str], rails: &str| {
            let remotes: String = remotes.iter().map(|r| format!("  remote: {r}\n")).collect();
            format!(
                "GEM\n{remotes}  specs:\n    racc (1.7.3)\n    rails (7.0.0)\n      racc\n\n\
                 PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails{rails}\n\nBUNDLED WITH\n   2.1.4\n"
            )
        };
        let rails = dep("rails", "7.0.0");
        for eol in ["\n", "\r\n"] {
            let spell = |s: String| s.replace('\n', eol);
            // Declared after another gem's source: listed after it.
            let (out, text, edits) = merge(
                &spell(lock(&[UPSTREAM, B], " (~> 7.0)")),
                &rails,
                &["https://rubygems.org", B, INDEX_URL],
                DependencyPin::Keep,
            );
            assert_eq!(out, Ok(()));
            assert_eq!(text, spell(lock(&[UPSTREAM, B, INDEX_URL], " (~> 7.0)!")));
            assert_eq!(
                edits,
                [
                    "redirect_gemfile_lock_dependency_pin:rewritten",
                    "redirect_gemfile_lock_gem_source:added"
                ]
            );
            // Declared before it: listed before it.
            let (out, text, _) = merge(
                &spell(lock(&[UPSTREAM, B], "")),
                &rails,
                &["https://rubygems.org", INDEX_URL, B],
                DependencyPin::Keep,
            );
            assert_eq!(out, Ok(()));
            assert_eq!(text, spell(lock(&[UPSTREAM, INDEX_URL, B], "!")));
            let (out, again, edits) = merge(
                &text,
                &rails,
                &["https://rubygems.org", INDEX_URL, B],
                DependencyPin::Keep,
            );
            assert!(
                out.is_ok() && again == text && edits.is_empty(),
                "{edits:?}"
            );
        }
        // A transitive gem: its entry is added in name order.
        let (out, text, _) = merge(
            &lock(&[UPSTREAM], " (~> 7.0)"),
            &dep("racc", "1.7.3"),
            &["https://rubygems.org", INDEX_URL],
            DependencyPin::Keep,
        );
        assert_eq!(out, Ok(()));
        assert!(text.contains("  remote: https://rubygems.org/\n  remote: https://patch.test/gem/tok/uuid/\n  specs:"), "{text}");
        assert!(
            text.contains("DEPENDENCIES\n  racc (= 1.7.3)!\n  rails (~> 7.0)\n\n"),
            "{text}"
        );
    }

    /// A remote list the manifest does not account for, in the lock's
    /// order, is never extended: a frozen install would refuse the result.
    #[test]
    fn merged_lock_the_manifest_does_not_explain_is_refused() {
        const B: &str = "https://patch.test/gem/tok/other-uuid/";
        let lock = |remotes: &[&str]| {
            let remotes: String = remotes.iter().map(|r| format!("  remote: {r}\n")).collect();
            format!(
                "GEM\n{remotes}  specs:\n    rails (7.0.0)\n\nDEPENDENCIES\n  rails\n\nBUNDLED WITH\n   1.17.3\n"
            )
        };
        let rails = dep("rails", "7.0.0");
        let cases: [(&str, String, &[&str]); 5] = [
            (
                "a lock remote the manifest does not name",
                lock(&[UPSTREAM, B]),
                &["https://rubygems.org", INDEX_URL],
            ),
            (
                "the lock's remotes in another order",
                lock(&[B, UPSTREAM]),
                &["https://rubygems.org", B, INDEX_URL],
            ),
            (
                "the manifest does not name the patch registry",
                lock(&[UPSTREAM]),
                &["https://rubygems.org"],
            ),
            (
                "the spec is not locked",
                lock(&[UPSTREAM]).replace("rails (7.0.0)", "rails (7.0.1)"),
                &["https://rubygems.org", INDEX_URL],
            ),
            (
                "two GEM sections",
                format!("GEM\n  remote: {B}\n  specs:\n\n{}", lock(&[UPSTREAM])),
                &["https://rubygems.org", INDEX_URL],
            ),
        ];
        for (label, lock, sources) in &cases {
            let (out, text, edits) = merge(lock, &rails, sources, DependencyPin::Keep);
            assert!(out.is_err(), "{label}");
            assert_eq!(&text, lock, "{label}");
            assert!(edits.is_empty(), "{label}: {edits:?}");
        }
    }

    /// An already-converged section under a superseding patch: the remote is
    /// refreshed on its own line and the section re-placed where bundler
    /// sorts it.
    #[test]
    fn owned_section_is_refreshed_and_re_sorted() {
        let lock = "GEM
  remote: https://gems.mirror.example/
  specs:
    nokogiri (1.16.0)

GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.0)

GEM
  remote: https://patch.test/gem/tok/old/
  specs:
    racc (1.7.3)

DEPENDENCIES
  racc (= 1.7.3)!
  rails
";
        let (ok, out, edits) = converge(lock, &dep("racc", "1.7.3"));
        assert!(ok);
        assert_eq!(
            out,
            "GEM
  remote: https://gems.mirror.example/
  specs:
    nokogiri (1.16.0)

GEM
  remote: https://patch.test/gem/tok/uuid/
  specs:
    racc (1.7.3)

GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.0)

DEPENDENCIES
  racc (= 1.7.3)!
  rails
"
        );
        assert_eq!(
            edits,
            [
                "redirect_gemfile_lock_source_url:rewritten",
                "redirect_gemfile_lock_section_order:moved"
            ]
        );
    }

    /// DEPENDENCIES before the dep's `GEM` section, a duplicated spec, a
    /// multi-remote section and a missing DEPENDENCIES section are refused
    /// untouched.
    #[test]
    fn unsafe_shapes_are_refused_untouched() {
        let locks = [
            "DEPENDENCIES\n  racc\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    racc (1.7.3)\n",
            "GEM\n  remote: https://a.example/\n  specs:\n    racc (1.7.3)\n\nGEM\n  remote: https://b.example/\n  specs:\n    racc (1.7.3)\n\nDEPENDENCIES\n  racc\n",
            "GEM\n  remote: https://a.example/\n  remote: https://b.example/\n  specs:\n    racc (1.7.3)\n\nDEPENDENCIES\n  racc\n",
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    racc (1.7.3)\n",
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    racc (1.7.4)\n\nDEPENDENCIES\n  racc\n",
        ];
        for lock in locks {
            let (ok, out, edits) = converge(lock, &dep("racc", "1.7.3"));
            assert!(!ok, "{lock}");
            assert_eq!(out, lock);
            assert!(edits.is_empty());
        }
    }

    /// A lock without a final newline: the unterminated DEPENDENCIES entry
    /// is rewritten in place and stays unterminated.
    #[test]
    fn unterminated_last_dependency_is_rewritten_in_place() {
        let lock = "GEM\n  remote: https://rubygems.org/\n  specs:\n    racc (1.7.3)\n\nDEPENDENCIES\n  racc";
        let (ok, out, _) = converge(lock, &dep("racc", "1.7.3"));
        assert!(ok);
        assert_eq!(
            out,
            "GEM\n  remote: https://patch.test/gem/tok/uuid/\n  specs:\n    racc (1.7.3)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n\nDEPENDENCIES\n  racc (= 1.7.3)!"
        );
    }

    /// `(refreshed, lock after, edit kinds)` for
    /// [`refresh_merged_gem_lock_remote`] from the dep's block URL `prior`.
    fn refresh(lock: &str, dep: &DepOverride, prior: &str) -> (bool, String, Vec<String>) {
        let mut lk = lock.to_string();
        let mut changed = false;
        let mut result = RewriteResult::default();
        let ok = refresh_merged_gem_lock_remote(
            &mut lk,
            dep,
            prior,
            INDEX_URL,
            "Gemfile.lock",
            &mut changed,
            &mut result,
        );
        assert_eq!(changed, lk != lock, "lock_changed must report a change");
        let edits = result
            .edits
            .iter()
            .map(|e| format!("{}:{}", e.kind, e.action))
            .collect();
        (ok, lk, edits)
    }

    /// A bundler ≤ 2.1 merged section an earlier redirect converged:
    /// `remotes` listed in order, `rails` source-pinned when `bang`, and
    /// `extra` sections before PLATFORMS.
    fn merged(remotes: &[&str], bang: &str, extra: &str) -> String {
        let remotes: String = remotes.iter().map(|r| format!("  remote: {r}\n")).collect();
        format!(
            "GEM\n{remotes}  specs:\n    racc (1.7.3)\n    rails (7.0.0)\n      racc\n\n{extra}\
             PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (= 7.0.0){bang}\n\nBUNDLED WITH\n   2.1.4\n"
        )
    }

    const UPSTREAM: &str = "https://rubygems.org/";
    const OLD: &str = "https://patch.test/gem/tok/older-uuid/";

    /// #1688: the merged section's remote for the dep's own block moves to
    /// the new index URL in place (an earlier patch uuid or grant token),
    /// CRLF kept; a lock already on the URL is refreshed with no edit.
    #[test]
    fn merged_section_socket_remote_follows_the_new_index_url() {
        for old in [OLD, "https://patch.test/gem/old-tok/uuid/"] {
            for eol in ["\n", "\r\n"] {
                let lock = merged(&[UPSTREAM, old], "!", "").replace('\n', eol);
                let (ok, out, edits) = refresh(&lock, &dep("rails", "7.0.0"), old);
                assert!(ok, "{old}");
                assert_eq!(out, lock.replace(old, INDEX_URL), "{old} {eol:?}");
                assert_eq!(edits, vec!["redirect_gemfile_lock_source_url:rewritten"]);
            }
        }
        let current = merged(&[UPSTREAM, INDEX_URL], "!", "");
        assert_eq!(
            refresh(&current, &dep("rails", "7.0.0"), INDEX_URL),
            (true, current.clone(), vec![])
        );
    }

    /// Every other shape is left alone (false, no edit): a remote that is
    /// not the dep's own block URL (another gem's Socket remote, or none),
    /// a gem not source-pinned, a single-remote section, a spec listed in
    /// two sections, or a version the lock does not list.
    #[test]
    fn merged_section_refresh_refuses_other_shapes() {
        let other_gem = "https://patch.test/gem/tok/other-gem-uuid/";
        let second = "GEM\n  remote: https://gems.mirror.example/\n  specs:\n    rails (7.0.0)\n\n";
        let rails = dep("rails", "7.0.0");
        let cases = [
            (
                "another gem's Socket remote",
                merged(&[UPSTREAM, other_gem], "!", ""),
                &rails,
            ),
            (
                "no Socket remote",
                merged(&[UPSTREAM, "https://gems.mirror.example/"], "!", ""),
                &rails,
            ),
            (
                "not source-pinned",
                merged(&[UPSTREAM, OLD], "", ""),
                &rails,
            ),
            ("single remote", merged(&[OLD], "!", ""), &rails),
            (
                "spec in two sections",
                merged(&[UPSTREAM, OLD], "!", second),
                &rails,
            ),
            (
                "unlocked version",
                merged(&[UPSTREAM, OLD], "!", ""),
                &dep("rails", "7.1.0"),
            ),
        ];
        for (label, lock, dep) in &cases {
            assert!(
                super::super::parse(lock).problems.is_empty(),
                "{label}: the fixture must be a valid lock"
            );
            let (ok, out, edits) = refresh(lock, dep, OLD);
            assert!(!ok, "{label}");
            assert_eq!(&out, lock, "{label}");
            assert!(edits.is_empty(), "{label}: {edits:?}");
        }
    }

    /// Only a lock bundler < 2.2 wrote counts as the merged era.
    #[test]
    fn bundled_before_2_2_reads_the_bundled_with_version() {
        for (version, want) in [
            ("1.17.3", true),
            ("2.1.4", true),
            ("2.2.0", false),
            ("2.5.23", false),
            ("4.0.18", false),
            ("garbage", false),
        ] {
            let lock = format!("DEPENDENCIES\n  rails\n\nBUNDLED WITH\n   {version}\n");
            assert_eq!(bundled_before_2_2(&lock), want, "{version}");
            assert_eq!(
                bundled_before_2_2(&lock.replace('\n', "\r\n")),
                want,
                "{version} CRLF"
            );
        }
        assert!(!bundled_before_2_2("DEPENDENCIES\n  rails\n"));
    }
}
