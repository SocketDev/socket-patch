//! The hosted planner's Bundler-lock leg: converge a redirected gem's source
//! attribution (its spec block moved into a patch-registry `GEM` section,
//! DEPENDENCIES source-pinned) as a line splice that keeps every line's own
//! `\r\n` / `\n` ending. The read model in the parent keeps no spans or
//! endings, which is why this walker is separate from it.

use regex::Regex;
use serde_json::Value;

use crate::patch::redirect::{gem_index_url_pattern, DepOverride, FileEdit, RewriteResult};

/// A lock line without its `\r?\n` ending (never more than one of each).
fn gem_lock_line_content(line: &str) -> &str {
    let line = line.strip_suffix('\n').unwrap_or(line);
    line.strip_suffix('\r').unwrap_or(line)
}

/// The gem name of a 2-space DEPENDENCIES entry (`  rails`, `  rails!`,
/// `  rails (= 7.0.0)!`) — the text before any constraint, sans source pin.
fn gem_lock_dependency_name(entry: &str) -> &str {
    let entry = entry.trim_start();
    let entry = entry.split(" (").next().unwrap_or(entry);
    entry.trim_end_matches('!')
}

/// One parsed `GEM` section of a Gemfile.lock: its header line index, its
/// `remote:` lines (index + URL) and the exclusive end index — the start of
/// the next column-0 header (trailing blank separator included) or EOF.
struct GemLockSection {
    start: usize,
    remotes: Vec<(usize, String)>,
    end: usize,
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
/// remote is refreshed in place under a rotated grant
/// (`redirect_gemfile_lock_source_url`, mirroring the Gemfile refresh).
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
    let is_header = |c: &str| !c.is_empty() && !c.starts_with(' ');

    // Parse: GEM sections, the dep's 4-space spec entry, DEPENDENCIES range.
    let spec_content = format!("    {} ({})", dep.name, dep.version);
    let mut sections: Vec<GemLockSection> = Vec::new();
    let mut spec_at: Vec<(usize, usize)> = Vec::new(); // (section idx, line idx)
    let mut deps_range: Option<(usize, usize)> = None; // exclusive of header
    let mut i = 0;
    while i < lines.len() {
        let c = gem_lock_line_content(&lines[i]);
        if !is_header(c) {
            i += 1;
            continue;
        }
        let header_is_gem = c == "GEM";
        let start = i;
        let mut remotes = Vec::new();
        let mut j = i + 1;
        while j < lines.len() && !is_header(gem_lock_line_content(&lines[j])) {
            let cj = gem_lock_line_content(&lines[j]);
            if header_is_gem {
                if let Some(url) = cj.strip_prefix("  remote: ") {
                    remotes.push((j, url.to_string()));
                }
                if cj == spec_content {
                    spec_at.push((sections.len(), j));
                }
            }
            j += 1;
        }
        if header_is_gem {
            sections.push(GemLockSection {
                start,
                remotes,
                end: j,
            });
        } else if c == "DEPENDENCIES" {
            deps_range = Some((start + 1, j));
        }
        i = j;
    }

    let spec_pos = if spec_at.len() == 1 {
        Some(spec_at[0])
    } else {
        None
    };
    let (Some((sec_idx, spec_idx)), Some((deps_start, deps_end))) = (spec_pos, deps_range) else {
        return false;
    };
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
    let (remote_idx, remote_url) = sections[sec_idx].remotes[0].clone();
    let socket_remote_re = Regex::new(&format!("^{}$", gem_index_url_pattern(dep, index_url)))
        .expect("anchored index-url pattern from the escaped URL is valid");
    let mut changed = false;

    // DEPENDENCIES pin first — its lines sit AFTER the GEM sections, so the
    // spec move below never invalidates these indices (and vice versa would).
    let target = format!("  {} (= {})!", dep.name, dep.version);
    let is_entry = |c: &str| c.starts_with("  ") && !c.starts_with("   ");
    let entry_idx = (deps_start..deps_end).find(|&k| {
        let ck = gem_lock_line_content(&lines[k]);
        is_entry(ck) && gem_lock_dependency_name(ck) == dep.name
    });
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
            // Transitive dep: bundler keeps DEPENDENCIES sorted by name.
            let mut at = deps_end;
            for (k, line) in lines.iter().enumerate().take(deps_end).skip(deps_start) {
                let ck = gem_lock_line_content(line);
                if ck.is_empty()
                    || (is_entry(ck) && gem_lock_dependency_name(ck) > dep.name.as_str())
                {
                    at = k;
                    break;
                }
            }
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
        // Already ours. Rotated grant: refresh the remote in place.
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
            let s = &sections[k];
            match k.cmp(&sec_idx) {
                std::cmp::Ordering::Less => (s.start, s.end),
                std::cmp::Ordering::Equal => (s.start, s.end - n),
                std::cmp::Ordering::Greater => (s.start - n, s.end - n),
            }
        };
        let identifier = |k: usize| -> String {
            sections[k]
                .remotes
                .iter()
                .map(|(_, url)| url.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let insert_at = (0..sections.len())
            .find(|&k| identifier(k).as_str() > index_url)
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
