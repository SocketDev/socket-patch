//! The hosted planner's Bundler-lock leg: converge a redirected gem's source
//! attribution (its spec block moved into a patch-registry `GEM` section,
//! DEPENDENCIES source-pinned) as a line splice that keeps every line's own
//! `\r\n` / `\n` ending. Sections, remotes and DEPENDENCIES entries are
//! located with the parent's read model ([`super::parse`]); the splice
//! itself works on the lock's `split_inclusive('\n')` lines, which the
//! model's line numbers index.

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
fn place_gem_section_sorted(
    lines: &mut Vec<String>,
    sections: &[&Section<'_>],
    sec_idx: usize,
    index_url: &str,
    eol: &str,
) -> bool {
    let others = || (0..sections.len()).filter(|&k| k != sec_idx);
    let before = others().find(|&k| sections[k].identifier().as_str() > index_url);
    if before == others().find(|&k| k > sec_idx) {
        return false;
    }
    let range = sections[sec_idx].lines();
    let (start, end) = (range.start, range.end);
    let mut block: Vec<String> = lines.drain(start..end).collect();
    let n = block.len();
    // The moved section needs its own blank separator (and a final newline
    // if it was the file's last line).
    if let Some(last) = block.last_mut() {
        if !last.ends_with('\n') {
            last.push_str(eol);
        }
        if !gem_lock_line_content(last).is_empty() {
            block.push(eol.to_string());
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

/// Converge the lock's source attribution for one redirected dep so the
/// Gemfile + lock pair is what bundler itself would write after an install
/// from the redirected Gemfile (verified frozen-installable on bundler 4):
/// the dep's spec entry (+ its dependency sublines) moves out of the
/// upstream `GEM` section into a patch-registry `GEM` section
/// (`remote: <index-url>`), and DEPENDENCIES pins `<name> (= <version>)!`
/// (bundler's source-pin spelling for a block-scoped exact-version gem) —
/// added in sorted position when the dep was transitive. Without this the
/// CHECKSUMS pin leaves a MIXED state bundler refuses: the lock still
/// attributes the gem to the upstream remote, so the prescribed unfrozen
/// install exits 37 "mismatched checksums" and a frozen install exits 16.
///
/// Idempotent and rotation-aware: a section whose remote matches the
/// token-wildcard pattern is recognized as ours (never duplicated) and its
/// remote is refreshed under a rotated grant or superseding patch
/// (`redirect_gemfile_lock_source_url`, mirroring the Gemfile refresh); the
/// section then moves to bundler's sorted position if the new URL sorts
/// elsewhere (`redirect_gemfile_lock_section_order`).
///
/// Returns true when the lock ends converged (already, or via edits recorded
/// into `result`); false when the dep cannot be attributed safely — spec
/// entry absent or duplicated, a legacy multi-remote `GEM` section, or no
/// DEPENDENCIES section — in which case nothing is touched and the caller
/// surfaces the frozen-install caveat.
pub(crate) fn converge_gem_lock_source(
    lk: &mut String,
    dep: &DepOverride,
    index_url: &str,
    lock_name: &str,
    lock_changed: &mut bool,
    result: &mut RewriteResult,
) -> bool {
    let eol = crate::utils::line_endings::terminator(lk);
    let mut lines: Vec<String> = lk.split_inclusive('\n').map(str::to_string).collect();
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
    let (&[(sec_idx, spec_idx)], Some(deps)) = (spec_at.as_slice(), &model.dependencies) else {
        return false;
    };
    // Exclusive of the header.
    let (deps_start, deps_end) = (deps.line_no, deps.end);
    if sections[sec_idx].remotes.len() != 1 {
        return false;
    }
    // Bundler always writes source sections before DEPENDENCIES — the pin
    // edit below runs first on that premise (its lines sit after the parsed
    // spec/remote/end indices, so they never shift). A hand-edited lock with
    // DEPENDENCIES before the dep's GEM section breaks the premise: the
    // transitive-dep pin INSERT would leave the spec-move splicing on stale
    // indices. Fail soft to the mixed state instead.
    if deps_start < sections[sec_idx].end {
        return false;
    }
    let remote_idx = sections[sec_idx].remote_line_nos[0] - 1;
    let remote_url = sections[sec_idx].remotes[0].to_string();
    let socket_remote_re = Regex::new(&format!("^{}$", gem_index_url_pattern(dep, index_url)))
        .expect("anchored index-url pattern from the escaped URL is valid");
    let mut changed = false;

    // DEPENDENCIES pin first — its lines sit AFTER the GEM sections, so the
    // spec move below never invalidates these indices (and vice versa would).
    let target = format!("  {} (= {})!", dep.name, dep.version);
    let entry_idx = deps
        .entries
        .iter()
        .find(|entry| entry.name == dep.name)
        .map(|entry| entry.line_no - 1);
    match entry_idx {
        Some(k) if gem_lock_line_content(&lines[k]) == target => {}
        Some(k) => {
            let old = gem_lock_line_content(&lines[k]).trim_start().to_string();
            let ending = lines[k][gem_lock_line_content(&lines[k]).len()..].to_string();
            lines[k] = format!("{target}{ending}");
            result.edits.push(FileEdit {
                path: lock_name.into(),
                kind: "redirect_gemfile_lock_dependency_pin".into(),
                action: "rewritten".into(),
                key: Some(dep.name.clone()),
                original: Some(Value::String(old)),
                new: Some(Value::String(target.trim_start().to_string())),
            });
            changed = true;
        }
        None => {
            // Transitive dep: bundler keeps DEPENDENCIES sorted by name, so
            // it goes before the first entry that sorts after it, and never
            // past the section's blank separator.
            let next_entry = deps
                .entries
                .iter()
                .find(|entry| entry.name > dep.name.as_str())
                .map(|entry| entry.line_no - 1);
            let separator =
                (deps_start..deps_end).find(|&k| gem_lock_line_content(&lines[k]).is_empty());
            let at = next_entry
                .into_iter()
                .chain(separator)
                .min()
                .unwrap_or(deps_end);
            lines.insert(at, format!("{target}{eol}"));
            result.edits.push(FileEdit {
                path: lock_name.into(),
                kind: "redirect_gemfile_lock_dependency_pin".into(),
                action: "added".into(),
                key: Some(dep.name.clone()),
                original: None,
                new: Some(Value::String(target.trim_start().to_string())),
            });
            changed = true;
        }
    }

    if socket_remote_re.is_match(&remote_url) {
        // Already ours. Rotated grant or superseding patch: refresh the
        // remote.
        if remote_url != index_url {
            let ending =
                lines[remote_idx][gem_lock_line_content(&lines[remote_idx]).len()..].to_string();
            lines[remote_idx] = format!("  remote: {index_url}{ending}");
            result.edits.push(FileEdit {
                path: lock_name.into(),
                kind: "redirect_gemfile_lock_source_url".into(),
                action: "rewritten".into(),
                key: Some(dep.name.clone()),
                original: Some(Value::String(remote_url)),
                new: Some(Value::String(index_url.to_string())),
            });
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
        let moved: Vec<String> = lines.drain(spec_idx..=last).collect();
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
        let mut block: Vec<String> = Vec::with_capacity(moved.len() + 4);
        block.push(format!("GEM{eol}"));
        block.push(format!("  remote: {index_url}{eol}"));
        block.push(format!("  specs:{eol}"));
        for line in moved {
            // Moved lines keep their own bytes; only a final line that lacked
            // a newline (EOF) gains the file's ending.
            if line.ends_with('\n') {
                block.push(line);
            } else {
                block.push(format!("{line}{eol}"));
            }
        }
        block.push(eol.to_string());
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
        *lk = lines.concat();
        *lock_changed = true;
    }
    true
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

    /// `(converged, lock after, edit kinds/actions)` for one dep.
    fn converge(lock: &str, dep: &DepOverride) -> (bool, String, Vec<String>) {
        let mut lk = lock.to_string();
        let mut changed = false;
        let mut result = RewriteResult::default();
        let ok = converge_gem_lock_source(
            &mut lk,
            dep,
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
}
