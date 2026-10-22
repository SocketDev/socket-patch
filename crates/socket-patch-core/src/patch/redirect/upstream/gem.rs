//! RubyGems upstream restore: a hosted gem goes back to the upstream `GEM`
//! section of `Gemfile.lock` / `gems.locked`, and the `source "<patch
//! registry>" do … end` block the hosted rewriter (`rewrite_gem`) put into
//! `Gemfile` / `gems.rb` is undone. Discovery records only the lock; the
//! manifest is its bundler sibling ([`bundler_manifest_for`]).
//!
//! The lock states a hosted gem can be in, and what each restore does:
//!
//! * **Converged** (bundler ≥ 2.2 after the rewrite or an unfrozen install;
//!   the rewriter writes it itself in the `CHECKSUMS` era): the gem's spec
//!   (+ its dependency sub-lines) sits in a `GEM` section of its own whose
//!   single remote is the patch registry. The section is deleted and the
//!   spec moves back, in name order, into the upstream `GEM` section: the
//!   one remaining non-Socket single-remote section, or — when there are
//!   several — the one naming the manifest's global `source`, else the
//!   rubygems.org one; anything else is ambiguous and refused.
//! * **Merged** (bundler ≤ 2.1 writes every rubygems source into ONE `GEM`
//!   section): the Socket `remote:` line is dropped from it.
//! * **Mixed** (bundler < 2.6: the rewriter edits only the manifest and the
//!   lock still records the upstream source; see `redirect_gem_frozen_install`):
//!   discovery finds no pin for it (no lock wiring), so it is only unwound
//!   when a caller hands in a pin for it — the manifest block alone is then
//!   undone, and the untouched lock says exactly how the gem was declared.
//!
//! In every state a `CHECKSUMS` entry is re-pinned to the upstream sha256
//! from the rubygems.org compact index (`info/<name>`, what bundler itself
//! records; other upstream remotes are refused: their index may need
//! credentials and is not the default registry), and the `DEPENDENCIES`
//! source pin (`name (= v)!`) loses its `!` — unless the declaration comes
//! back inside the user's own `source … do` block, where bundler writes the
//! `!` itself ([`in_source_block`], #1056).
//!
//! What the rewrite discards is NOT derivable, so the restore picks the
//! installable reading and documents it:
//!
//! * the original declaration's version constraint (`"~> 7.0"`, or none),
//!   quote style, parenthesized form and comment: the gem comes back as
//!   `gem "<name>", "<version>"[, <options>]` — the exact pin the lock
//!   records as `name (= version)`, so the pair stays frozen-installable
//!   (the mixed state keeps the lock's own constraint instead);
//! * the blank lines and indentation the rewriter's `^\s*gem` match
//!   swallowed before the declaration: see [`declaration_prefix`];
//! * whether the gem was declared at all. The rewriter APPENDS a block for a
//!   transitive gem and adds its `DEPENDENCIES` entry, but a direct gem on
//!   the manifest's last line produces the same bytes. The block and entry
//!   are removed only when that is provable: an option-less block the
//!   rewriter could not have written in place (a blank line before it —
//!   the in-place match swallows every blank line before the declaration,
//!   and the append always writes one; it goes with the block) that
//!   another locked spec depends on. Otherwise the gem is kept as a
//!   direct pin: a stray exact pin installs the same bytes, while dropping
//!   a real declaration would stop `Bundler.require` loading the gem.
//! * a `CHECKSUMS` entry the rewriter ADDED is only recognizable next to
//!   bundler's own bare entry for the gem (then it is dropped); otherwise it
//!   is re-pinned in place.

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;

use super::{Ctx, FormatResult, HostedPin, UpstreamClient, View};
use crate::formats::gem::{
    bundler_manifest_for, parse_spec, same_remote, split_checksum_entry, BUNDLER_LOCKS,
};
use crate::utils::line_endings::{to_lf, LineEndings};
use crate::vendor::gem::{gem_declaration_any, quoted_literal};

/// The default upstream `GEM` remote.
const RUBYGEMS_REMOTE: &str = "https://rubygems.org/";

// ── lock model (LF text, split on `\n`) ─────────────────────────────────────

fn is_header(line: &str) -> bool {
    !line.is_empty() && !line.starts_with(' ')
}

/// Exactly `n` spaces of indent, then content.
fn indented(line: &str, n: usize) -> Option<&str> {
    let rest = line.get(n..)?;
    (line[..n].bytes().all(|b| b == b' ') && !rest.starts_with(' ') && !rest.is_empty())
        .then_some(rest)
}

/// One 4-space spec entry and its 6-space dependency sub-lines.
struct Entry {
    line: usize,
    /// The last sub-line (== `line` when it has none).
    last: usize,
    name: String,
    version: String,
    platform: bool,
}

/// One `GEM` section: `[start, end)` runs from its header to the next
/// header (its trailing blank separator included).
struct GemSec {
    start: usize,
    end: usize,
    remotes: Vec<(usize, String)>,
    specs_line: Option<usize>,
    entries: Vec<Entry>,
}

/// `[start, end)` of every section, with its header.
fn section_ranges<'l>(lines: &[&'l str]) -> Vec<(&'l str, usize, usize)> {
    let mut out: Vec<(&str, usize, usize)> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if is_header(line) {
            if let Some(last) = out.last_mut() {
                last.2 = i;
            }
            out.push((line.trim_end(), i, lines.len()));
        }
    }
    out
}

fn gem_sections(lines: &[&str]) -> Vec<GemSec> {
    let mut out = Vec::new();
    for (header, start, end) in section_ranges(lines) {
        if header != "GEM" {
            continue;
        }
        let mut sec = GemSec {
            start,
            end,
            remotes: Vec::new(),
            specs_line: None,
            entries: Vec::new(),
        };
        for (k, line) in lines.iter().enumerate().take(end).skip(start + 1) {
            if let Some(key) = indented(line, 2) {
                if let Some(url) = key.strip_prefix("remote:") {
                    sec.remotes.push((k, url.trim().to_string()));
                } else if key.trim_end() == "specs:" {
                    sec.specs_line = Some(k);
                }
            } else if let Some(entry) = indented(line, 4).filter(|_| sec.specs_line.is_some()) {
                let spec = parse_spec(entry.trim_end());
                sec.entries.push(Entry {
                    line: k,
                    last: k,
                    name: spec.map(|s| s.name).unwrap_or(entry).to_string(),
                    version: spec.map(|s| s.version).unwrap_or_default().to_string(),
                    platform: spec.is_none_or(|s| s.platform.is_some()),
                });
            } else if line.starts_with("      ") {
                if let Some(e) = sec.entries.last_mut() {
                    e.last = k;
                }
            }
        }
        out.push(sec);
    }
    out
}

/// The line range of the column-0 section `header`, header excluded.
fn named_section(lines: &[&str], header: &str) -> Option<(usize, usize)> {
    section_ranges(lines)
        .into_iter()
        .find(|(h, _, _)| *h == header)
        .map(|(_, s, e)| (s + 1, e))
}

/// The `DEPENDENCIES` entry of `name`: its line and trimmed text.
fn dependency_line<'l>(lines: &[&'l str], name: &str) -> Option<(usize, &'l str)> {
    let (s, e) = named_section(lines, "DEPENDENCIES")?;
    (s..e).find_map(|k| {
        let entry = indented(lines[k], 2)?.trim_end();
        let dep = entry.split([' ', '(']).next()?.trim_end_matches('!');
        (dep == name).then_some((k, entry))
    })
}

/// Whether another locked spec depends on `name` (a 6-space sub-line).
fn is_subdependency(lines: &[&str], name: &str) -> bool {
    lines
        .iter()
        .any(|l| indented(l, 6).is_some_and(|d| d.split([' ', '(']).next() == Some(name)))
}

/// How the lock wires patch `uuid`.
enum Wiring {
    /// A `GEM` section of its own (index into the sections).
    Own(usize),
    /// One `remote:` line (the line index) of a multi-remote section.
    Merged(usize, usize),
}

fn wiring(secs: &[GemSec], uuid: &str, ctx: &Ctx<'_>) -> Result<Option<Wiring>, String> {
    let hits: Vec<(usize, usize)> = secs
        .iter()
        .enumerate()
        .flat_map(|(i, s)| {
            s.remotes
                .iter()
                .filter(|(_, r)| ctx.hosted_uuid(r).as_deref() == Some(uuid))
                .map(move |(k, _)| (i, *k))
        })
        .collect();
    match hits.as_slice() {
        [] => Ok(None),
        [(i, k)] if secs[*i].remotes.len() > 1 => Ok(Some(Wiring::Merged(*i, *k))),
        [(i, _)] => Ok(Some(Wiring::Own(*i))),
        _ => Err("several GEM remotes name the patch".to_string()),
    }
}

/// The upstream section a spec moves back to (module docs).
fn choose_upstream(
    secs: &[GemSec],
    own: usize,
    globals: &[String],
    ctx: &Ctx<'_>,
) -> Result<usize, String> {
    let candidates: Vec<usize> = (0..secs.len())
        .filter(|&i| {
            i != own
                && secs[i].remotes.len() == 1
                && ctx.hosted_uuid(&secs[i].remotes[0].1).is_none()
        })
        .collect();
    let remote = |i: &usize| secs[*i].remotes[0].1.as_str();
    match candidates.as_slice() {
        [] => Err("the lock has no upstream GEM section to move it back to".to_string()),
        [one] => Ok(*one),
        _ => {
            let single = |keep: &dyn Fn(&usize) -> bool| match candidates
                .iter()
                .filter(|i| keep(i))
                .collect::<Vec<_>>()
                .as_slice()
            {
                [one] => Some(**one),
                _ => None,
            };
            if let Some(one) = single(&|i| globals.iter().any(|g| same_remote(g, remote(i))))
                .or_else(|| single(&|i| same_remote(remote(i), RUBYGEMS_REMOTE)))
            {
                return Ok(one);
            }
            Err(format!(
                "the lock has {} upstream GEM sections and none is singled out by the \
                 manifest's global source or rubygems.org",
                candidates.len()
            ))
        }
    }
}

/// The line after which a spec named `name-version` sorts into `sec`
/// (bundler writes specs sorted by full name).
fn insertion_point(sec: &GemSec, full_name: &str) -> Option<usize> {
    let pred = sec.entries.iter().rfind(|e| {
        let full = if e.version.is_empty() {
            e.name.clone()
        } else {
            format!("{}-{}", e.name, e.version)
        };
        full.as_str() < full_name
    });
    pred.map(|e| e.last).or(sec.specs_line)
}

/// A lock restore step's outcome.
enum LockEdit {
    /// The `CHECKSUMS` entry must be re-pinned from `remote` first.
    NeedsSha {
        remote: Option<String>,
    },
    Done(String),
}

/// One pin's coordinates.
struct Gem<'p> {
    uuid: &'p str,
    name: String,
    version: String,
}

/// What the restore does to the gem's `DEPENDENCIES` entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DepEntry {
    /// Drop the `!` source pin the rewriter added (module docs).
    Unpin,
    /// Keep the entry as is: the restored declaration sits in a user
    /// `source … do` block, which bundler records with a `!` (#1056).
    Keep,
    /// Drop the entry: the rewriter added it for a transitive gem.
    Drop,
}

/// Restore `gem` in the LF lock text (module docs); `dep` says what becomes
/// of its `DEPENDENCIES` entry.
fn lock_edit(
    lock: &str,
    gem: &Gem<'_>,
    globals: &[String],
    dep: DepEntry,
    sha: Option<&str>,
    ctx: &Ctx<'_>,
) -> Result<LockEdit, String> {
    let lines: Vec<&str> = lock.split('\n').collect();
    let secs = gem_sections(&lines);
    let wiring = wiring(&secs, gem.uuid, ctx)?;
    let mut drop: BTreeSet<usize> = BTreeSet::new();
    let mut replace: BTreeMap<usize, String> = BTreeMap::new();
    let mut insert_after: BTreeMap<usize, Vec<&str>> = BTreeMap::new();
    let is_ours = |e: &Entry| e.name == gem.name && e.version == gem.version && !e.platform;
    let checksum_remote = match &wiring {
        Some(Wiring::Own(si)) => {
            let sec = &secs[*si];
            let entry = match sec.entries.as_slice() {
                [e] if is_ours(e) => e,
                _ => {
                    return Err(format!(
                        "its Socket GEM section does not lock exactly {} ({})",
                        gem.name, gem.version
                    ))
                }
            };
            let up = choose_upstream(&secs, *si, globals, ctx)?;
            let at = insertion_point(&secs[up], &format!("{}-{}", gem.name, gem.version))
                .ok_or("the upstream GEM section has no `specs:` list")?;
            drop.extend(sec.start..sec.end);
            insert_after.insert(at, lines[entry.line..=entry.last].to_vec());
            Some(secs[up].remotes[0].1.clone())
        }
        Some(Wiring::Merged(si, line)) => {
            let sec = &secs[*si];
            if !sec.entries.iter().any(is_ours) {
                return Err(format!(
                    "its merged GEM section does not lock {} ({})",
                    gem.name, gem.version
                ));
            }
            drop.insert(*line);
            let rest: Vec<&String> = sec
                .remotes
                .iter()
                .filter(|(k, _)| k != line)
                .map(|(_, r)| r)
                .collect();
            match rest.as_slice() {
                [one] => Some((*one).clone()),
                _ => None,
            }
        }
        None => {
            let holders: Vec<&GemSec> = secs
                .iter()
                .filter(|s| s.entries.iter().any(is_ours))
                .collect();
            match holders.as_slice() {
                [s] if s.remotes.len() == 1 => Some(s.remotes[0].1.clone()),
                _ => None,
            }
        }
    };
    if wiring.is_some() {
        if let Some((k, entry)) = dependency_line(&lines, &gem.name) {
            match dep {
                DepEntry::Drop => {
                    drop.insert(k);
                }
                DepEntry::Unpin => {
                    if let Some(unpinned) = entry.strip_suffix('!') {
                        replace.insert(k, format!("  {unpinned}"));
                    }
                }
                DepEntry::Keep => {}
            }
        }
    }
    if let Some((s, e)) = named_section(&lines, "CHECKSUMS") {
        let mut with_sha = Vec::new();
        let mut bare = false;
        for (k, line) in lines.iter().enumerate().take(e).skip(s) {
            let Some(entry) = indented(line, 2) else {
                continue;
            };
            let Some((name, token, tail)) = split_checksum_entry(entry.trim_end()) else {
                continue;
            };
            if name != gem.name || token != gem.version {
                continue;
            }
            if tail.contains("sha256=") {
                with_sha.push(k);
            } else {
                bare = true;
            }
        }
        match with_sha.as_slice() {
            [] => {}
            [k] if bare => {
                drop.insert(*k);
            }
            [k] => {
                let Some(sha) = sha else {
                    return Ok(LockEdit::NeedsSha {
                        remote: checksum_remote,
                    });
                };
                let re = Regex::new(r"sha256=[0-9A-Fa-f]*").expect("static sha256 regex is valid");
                replace.insert(
                    *k,
                    re.replace(lines[*k], format!("sha256={sha}")).into_owned(),
                );
            }
            _ => return Err("CHECKSUMS pins it more than once".to_string()),
        }
    }
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    for (k, line) in lines.iter().enumerate() {
        if !drop.contains(&k) {
            out.push(replace.get(&k).cloned().unwrap_or_else(|| line.to_string()));
        }
        if let Some(block) = insert_after.get(&k) {
            out.extend(block.iter().map(|l| l.to_string()));
        }
    }
    Ok(LockEdit::Done(out.join("\n")))
}

// ── manifest (Gemfile / gems.rb) ────────────────────────────────────────────

/// The rewriter's `source "<index>" do\n  gem "n", "v"[, opts]\nend` block.
struct Block {
    start: usize,
    /// Past the `end` line's line break.
    end: usize,
    opts: Option<String>,
    /// Whether a line break followed `end` (the declaration's own).
    eol: bool,
}

fn find_block(
    text: &str,
    gem: &Gem<'_>,
    rel: &str,
    ctx: &Ctx<'_>,
) -> Result<Option<Block>, String> {
    let hits: Vec<Block> = socket_blocks(text, gem, ctx)
        .into_iter()
        .filter(|(_, uuid)| uuid == gem.uuid)
        .map(|(b, _)| b)
        .collect();
    let rest_mentions = |b: Option<&Block>| mentions_outside(text, b, gem.uuid);
    match hits.as_slice() {
        [] if rest_mentions(None) => Err(format!(
            "{rel} wires it in a shape other than the source block socket-patch writes"
        )),
        [] => Ok(None),
        [_] if rest_mentions(hits.first()) => Err(format!(
            "{rel} names the patch outside the source block socket-patch writes"
        )),
        [_] => Ok(hits.into_iter().next()),
        _ => Err(format!("{rel} declares it in several Socket source blocks")),
    }
}

/// Every rewriter-shaped `source "<patch registry>" do` block for `gem`'s
/// name and version, with the hosted patch uuid its index names.
fn socket_blocks(text: &str, gem: &Gem<'_>, ctx: &Ctx<'_>) -> Vec<(Block, String)> {
    let re = Regex::new(&format!(
        r#"(?m)^source "([^"\r\n]*)" do\r?\n  gem "{}", "{}"(?:, ([^\r\n]*))?\r?\nend(\r?\n|\z)"#,
        regex::escape(&gem.name),
        regex::escape(&gem.version)
    ))
    .expect("source-block regex from escaped coordinates is valid");
    re.captures_iter(text)
        .filter_map(|c| {
            let uuid = ctx.hosted_uuid(&c[1])?;
            let m = c.get(0).expect("group 0 is the whole match");
            let block = Block {
                start: m.start(),
                end: m.end(),
                opts: c.get(2).map(|o| o.as_str().to_string()),
                eol: !c[3].is_empty(),
            };
            Some((block, uuid))
        })
        .collect()
}

/// Whether `text` names `uuid` anywhere but inside `block`.
fn mentions_outside(text: &str, block: Option<&Block>, uuid: &str) -> bool {
    match block {
        Some(b) => text[..b.start].contains(uuid) || text[b.end..].contains(uuid),
        None => text.contains(uuid),
    }
}

/// The block a superseding hosted re-scan left for `gem` (#1626): on a lock
/// with no `CHECKSUMS` section that scan moves only the manifest's block to
/// the new patch's uuid, so until a `bundle install` the lock pins `gem`'s
/// uuid while the manifest's block names another patch of the same name
/// and version. Restoring the lock alone would leave that block behind,
/// and the next unfrozen install would re-patch. Returns the block and the
/// superseding patch's uuid.
fn superseded_block(
    text: &str,
    gem: &Gem<'_>,
    rel: &str,
    ctx: &Ctx<'_>,
) -> Result<Option<(Block, String)>, String> {
    let hits: Vec<(Block, String)> = socket_blocks(text, gem, ctx)
        .into_iter()
        .filter(|(_, uuid)| uuid != gem.uuid)
        .collect();
    match hits.as_slice() {
        [] => Ok(None),
        [(b, uuid)] if mentions_outside(text, Some(b), uuid) => Err(format!(
            "{rel} names the superseding patch {uuid} outside the source block socket-patch writes"
        )),
        [_] => Ok(hits.into_iter().next()),
        _ => Err(format!(
            "{rel} declares it in several superseding Socket source blocks"
        )),
    }
}

/// The line before byte `at` (without its line break); `None` at the start.
fn line_before(text: &str, at: usize) -> Option<&str> {
    let before = text[..at].strip_suffix('\n')?;
    let before = before.strip_suffix('\r').unwrap_or(before);
    Some(&before[before.rfind('\n').map_or(0, |i| i + 1)..])
}

fn indent_of(line: &str) -> &str {
    &line[..line.len() - line.trim_start().len()]
}

/// Whether the rewriter can only have APPENDED `block` (a transitive gem):
/// its in-place rewrite swallows every blank line before the declaration,
/// so a blank line right before the block rules it out.
fn provably_appended(text: &str, block: &Block) -> bool {
    line_before(text, block.start).is_some_and(|l| l.trim().is_empty())
}

/// The blank line + indent to put before a declaration restored in place of
/// `block`. The rewriter's `^\s*gem` match swallowed whatever whitespace
/// preceded the original line, which no file records, so this re-derives the
/// conventional layout from the neighbors: right after the line that opens
/// the enclosing block (`group … do`), that line's indent + 2; right after
/// another declaration or a comment, the neighbor's indent and no blank
/// line; before another declaration, one blank line and that declaration's
/// indent; anywhere else inside a block (after an `end` or a statement,
/// #1476), the enclosing block's indent + 2 and no blank line; anywhere
/// else at the top level (after `source`, `ruby`, `end`, …) one blank line.
fn declaration_prefix(text: &str, block: &Block, eol: &str) -> String {
    let Some(prev) = line_before(text, block.start) else {
        return String::new();
    };
    let trimmed = prev.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let stack = block_stack(text, block.start);
    let enclosing = stack.last().map(|f| indent_of(&text[f.line..]));
    if let Some(indent) = enclosing.filter(|_| {
        stack
            .last()
            .is_some_and(|f| f.opener == line_before_start(text, block.start))
    }) {
        return format!("{indent}  ");
    }
    if trimmed.starts_with('#') || gem_declaration_any(trimmed).is_some() {
        return indent_of(prev).to_string();
    }
    let next = text[block.end..].split('\n').next().unwrap_or_default();
    if gem_declaration_any(next.trim()).is_some() {
        return format!("{eol}{}", indent_of(next));
    }
    match enclosing {
        Some(indent) => format!("{indent}  "),
        None => eol.to_string(),
    }
}

/// Whether byte `at` of the manifest sits inside a `source "<url>" do`
/// or `source("<url>") { … }` block (at any depth: a `group … do` nested
/// in it keeps the source), however many lines the opener spans (#1509).
/// Bundler records a dependency declared there with a `!` source pin in the
/// lock's `DEPENDENCIES`, whichever URL the block names (#1056).
fn in_source_block(text: &str, at: usize) -> bool {
    block_stack(text, at).iter().any(|f| f.source)
}

/// A Ruby construct still open at some point of the manifest.
struct Frame {
    /// A `source … do` or `source(…) {` block (anything else Ruby closes
    /// with `end` or `}`: `group … do`, `if`, `case`, `def`, a hash, … is
    /// not).
    source: bool,
    /// Byte offset of the start of the line its statement began on.
    line: usize,
    /// Byte offset of the start of the line holding its opener (the `do`,
    /// `{` or keyword), below `line` when the statement spans lines.
    opener: usize,
}

/// The Ruby constructs still open at byte `at` (a line start) of the
/// manifest, outermost first. A word-level count over each line's code:
/// a construct opened and closed on one line nets out, and a keyword opens
/// one wherever it starts an expression (`v = if …`, `require: case …`,
/// #1476), not only at the start of a line, so its `end` never closes an
/// enclosing block. A `{` opens one that its `}` closes (a brace block or
/// a hash). A statement runs on while a `(` or `[` is open, so a `source(`
/// whose arguments span lines still owns the `do` or `{` that follows its
/// `)` (#1509). A `source` call counts wherever it starts an expression,
/// as a keyword does (`x = 1; source "…" do`, `… then source "…" do`,
/// #1531). String, `%w[]`, regexp and backtick literals, comments,
/// `=begin` … `=end` blocks and heredoc bodies are not code.
fn block_stack(text: &str, at: usize) -> Vec<Frame> {
    let mut open: Vec<Frame> = Vec::new();
    let mut block_comment = false;
    // Pending heredoc terminators: (identifier, may be indented).
    let mut heredocs: std::collections::VecDeque<(String, bool)> = Default::default();
    // A string or `%`-literal still open at the end of the last line.
    let mut literal: Option<Literal> = None;
    // The code the last line left unfinished (a trailing `,`, `\`, `=`,
    // …): only its end matters, to tell what a keyword follows.
    let mut carried = String::new();
    // Open `(`, `[` and hash `{` of the statement.
    let mut depth = 0usize;
    // Each open `{`: a hash (counted in `depth`) or a block (a frame).
    let mut braces: Vec<bool> = Vec::new();
    // A `source` call whose block has not opened yet: the number of brace
    // blocks open around it (a `}` closing one of them ends the call, and
    // only a `do` or `{` at that level is its block).
    let mut source_pending: Option<usize> = None;
    // The `source(` call's argument list: (it is open, it has closed or
    // there is none).
    let mut source_call = (false, true);
    let mut statement_line = 0;
    let mut start = 0;
    for raw in text[..at].split_inclusive('\n') {
        let line_start = start;
        start += raw.len();
        let line = raw.trim_end_matches(['\n', '\r']);
        // `=begin` / `=end` start at column 0 and are followed by
        // whitespace or the end of the line (Ruby's own rule).
        let marker = |word: &str| {
            line.strip_prefix(word)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
        };
        if block_comment {
            block_comment = !marker("=end");
            continue;
        }
        if let Some((id, indented)) = heredocs.front() {
            let body = if *indented { line.trim_start() } else { line };
            if body == id {
                heredocs.pop_front();
            }
            continue;
        }
        if literal.is_none() && marker("=begin") {
            block_comment = true;
            continue;
        }
        // An open bracket carries only a `source` statement on to its
        // block opener: elsewhere a bracket the masker missed (one in an
        // interpolation) must not swallow the rest of the file.
        let continues =
            literal.is_some() || !carried.is_empty() || (depth > 0 && source_pending.is_some());
        let masked = masked_ruby_code(line, &mut literal);
        heredocs.extend(heredoc_openers(line, &masked));
        let masked = masked.trim();
        if !continues {
            depth = 0;
            statement_line = line_start;
            source_pending = None;
            source_call = (false, true);
        }
        for (n, statement) in masked.split(';').enumerate() {
            let lead = if n == 0 { carried.as_str() } else { "" };
            // A top-level `;` starts a new statement, unless it sits in a
            // brace block of the `source` call's own arguments.
            if n > 0 && depth == 0 && source_pending.is_none_or(|level| braces.len() <= level) {
                statement_line = line_start;
                source_pending = None;
                source_call = (false, true);
            }
            // A `while`/`until`/`for` takes its optional `do` as part of
            // the loop, not as a block of its own.
            let mut loop_do = false;
            // The word after `def` is the method's name (`def begin`).
            let mut method_name = false;
            // The last token closed the `source(…)` argument list.
            let mut after_source_call = false;
            for (word, start, end) in ruby_tokens(statement) {
                let closed_source_call = std::mem::take(&mut after_source_call);
                if is_ident_byte(word.as_bytes()[0]) && std::mem::take(&mut method_name) {
                    continue;
                }
                let expression = || starts_expression(&format!("{lead} {}", &statement[..start]));
                let (opens, source) = match word {
                    // One in a brace block of an outer call's arguments
                    // does not replace that call.
                    "source" if depth == 0 && source_pending.is_none() && expression() => {
                        if let Some(parenthesized) = source_call_args(&statement[end..]) {
                            source_pending = Some(braces.len());
                            source_call = (false, !parenthesized);
                        }
                        (false, false)
                    }
                    "(" | "[" => {
                        if depth == 0 && !source_call.1 {
                            source_call.0 = true;
                        }
                        depth += 1;
                        (false, false)
                    }
                    ")" | "]" => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 && std::mem::take(&mut source_call.0) {
                            source_call.1 = true;
                            after_source_call = true;
                        }
                        (false, false)
                    }
                    // A hash literal, part of the statement.
                    "{" if expression() && !statement[..start].trim_end().ends_with("->") => {
                        braces.push(true);
                        depth += 1;
                        (false, false)
                    }
                    // A brace block binds to the call before it, so only
                    // the one right after `source(…)` is the source's.
                    "{" => {
                        braces.push(false);
                        (
                            true,
                            closed_source_call
                                && take_source(&mut source_pending, braces.len() - 1),
                        )
                    }
                    "}" => {
                        match braces.pop() {
                            Some(true) => depth = depth.saturating_sub(1),
                            Some(false) => {
                                open.pop();
                                // A `source` call inside the block ends with it.
                                if source_pending.is_some_and(|level| braces.len() < level) {
                                    source_pending = None;
                                }
                            }
                            None => {}
                        }
                        (false, false)
                    }
                    "do" => {
                        let opens = !std::mem::take(&mut loop_do);
                        (
                            opens,
                            opens && depth == 0 && take_source(&mut source_pending, braces.len()),
                        )
                    }
                    "if" | "unless" => (expression(), false),
                    "while" | "until" => {
                        let opens = expression();
                        loop_do |= opens;
                        (opens, false)
                    }
                    "for" => {
                        loop_do = true;
                        (true, false)
                    }
                    "def" => {
                        method_name = true;
                        (!endless_def(&statement[end..]), false)
                    }
                    "case" | "begin" | "class" | "module" => (true, false),
                    "end" => {
                        open.pop();
                        (false, false)
                    }
                    _ => (false, false),
                };
                if opens {
                    open.push(Frame {
                        source,
                        line: statement_line,
                        opener: line_start,
                    });
                }
            }
        }
        // A line ending mid-expression; one that only leaves a bracket open
        // starts a fresh expression on the next line.
        let unfinished = literal.is_some()
            || masked.ends_with(['\\', ',', '(', '[', '+', '-', '*', '='])
            || masked.ends_with("||")
            || masked.ends_with("&&");
        carried = if unfinished {
            let tail = masked.rsplit(';').next().unwrap_or_default();
            tail.trim_end_matches('\\').trim().to_string()
        } else {
            String::new()
        };
    }
    open
}

/// Whether the pending `source` call (see [`block_stack`]) sits at brace
/// level `level`, in which case the block opening there is its block.
fn take_source(pending: &mut Option<usize>, level: usize) -> bool {
    pending.take_if(|l| *l == level).is_some()
}

/// Whether `rest`, what follows the word `source` that starts an
/// expression, makes it a call with arguments, and whether those are in
/// parentheses (`source(…)`). `source = …` assigns a local variable.
fn source_call_args(rest: &str) -> Option<bool> {
    if rest.starts_with('(') {
        return Some(true);
    }
    let args = rest.strip_prefix([' ', '\t'])?.trim_start();
    (!args.is_empty() && !args.starts_with('=')).then_some(false)
}

/// [`ruby_words`] and the brackets (`(`, `)`, `[`, `]`, `{`, `}`) of a
/// masked code line, in order, with their byte range.
fn ruby_tokens(code: &str) -> impl Iterator<Item = (&str, usize, usize)> {
    let mut words = ruby_words(code).peekable();
    let mut brackets = code
        .match_indices(['(', ')', '[', ']', '{', '}'])
        .map(|(at, b)| (b, at, at + 1))
        .peekable();
    std::iter::from_fn(move || match (words.peek(), brackets.peek()) {
        (Some(w), Some(b)) if b.1 < w.1 => brackets.next(),
        (Some(_), _) => words.next(),
        (None, _) => brackets.next(),
    })
}

/// The keyword-like words of a masked code line, with their byte range: a
/// symbol (`:if`), method call (`.class`) or variable sigil is a name, and
/// so are a predicate or bang (`begin?`) and a hash label (`if:`).
fn ruby_words(code: &str) -> impl Iterator<Item = (&str, usize, usize)> {
    let bytes = code.as_bytes();
    let mut i = 0;
    std::iter::from_fn(move || {
        while i < bytes.len() {
            if !is_ident_byte(bytes[i]) {
                i += 1;
                continue;
            }
            let start = i;
            while i < bytes.len() && is_ident_byte(bytes[i]) {
                i += 1;
            }
            let prev_ok = start == 0 || !matches!(bytes[start - 1], b':' | b'.' | b'@' | b'$');
            let next_ok = match bytes.get(i) {
                Some(b'?' | b'!') => false,
                Some(b':') => bytes.get(i + 1) == Some(&b':'),
                _ => true,
            };
            if prev_ok && next_ok {
                return Some((&code[start..i], start, i));
            }
        }
        None
    })
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || !b.is_ascii()
}

/// Whether a keyword or literal after `before` (the masked code before it
/// in its statement) starts an expression, as opposed to modifying the
/// statement before it (`gem "x" if cond`, `x.save! if y`) or dividing.
fn starts_expression(before: &str) -> bool {
    let before = before.trim_end();
    let Some(last) = before.bytes().next_back() else {
        return true;
    };
    match last {
        b'=' | b'(' | b'[' | b'{' | b',' | b';' | b'|' | b'&' | b'>' | b'<' | b'+' | b'-'
        | b'*' | b'~' => true,
        // A unary `!`, not a bang method (`x.save! if y`).
        b'!' => before.len() == 1 || !is_ident_byte(before.as_bytes()[before.len() - 2]),
        // A label (`require: if …`) or a ternary's `:`, not `Foo::`.
        b':' => !before.ends_with("::"),
        // A ternary's `?`, not a predicate (`x.empty? if y`).
        b'?' => before[..before.len() - 1].ends_with(char::is_whitespace),
        b if is_ident_byte(b) => {
            let word_start = before
                .bytes()
                .rposition(|b| !is_ident_byte(b))
                .map_or(0, |i| i + 1);
            let called = word_start > 0
                && matches!(before.as_bytes()[word_start - 1], b'.' | b':' | b'@' | b'$');
            !called
                && matches!(
                    &before[word_start..],
                    "then"
                        | "else"
                        | "elsif"
                        | "do"
                        | "begin"
                        | "ensure"
                        | "and"
                        | "or"
                        | "not"
                        | "when"
                        | "in"
                        | "if"
                        | "unless"
                        | "while"
                        | "until"
                        | "case"
                )
        }
        _ => false,
    }
}

/// Whether `rest` (what follows `def`) is an endless method (`def x = 1`,
/// `def x(a = f()) = a`, `def ==(o) = …`), which Ruby closes without an
/// `end`. A setter (`def x=(v)`) is not.
fn endless_def(rest: &str) -> bool {
    let rest = rest.trim_start();
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let name_len = if rest.starts_with(ident) {
        // `x`, `self.x`, `x?`, `x!`.
        let len = rest
            .find(|c: char| !(ident(c) || c == '.'))
            .unwrap_or(rest.len());
        len + usize::from(rest[len..].starts_with(['?', '!']))
    } else {
        // An operator method: `==`, `<=>`, `[]=`, `+@`, ….
        rest.find(|c: char| !"[]=!<>+-*/%~^&|@".contains(c))
            .unwrap_or(rest.len())
    };
    if name_len == 0 {
        return false;
    }
    let mut tail = &rest[name_len..];
    if tail.starts_with('(') {
        let mut depth = 0usize;
        let Some(close) = tail.find(|c: char| {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
            depth == 0
        }) else {
            return false;
        };
        tail = &tail[close + 1..];
    } else if !tail.starts_with([' ', '\t']) {
        return false;
    }
    tail.trim_start()
        .strip_prefix('=')
        .is_some_and(|t| !t.starts_with(['=', '~', '>']))
}

/// A string or `%`-literal left open at the end of a line.
#[derive(Clone, Copy)]
struct Literal {
    open: u8,
    close: u8,
    /// Nesting of `open` inside a bracketed literal (`%w[a [b] c]`).
    depth: usize,
}

/// `line` up to its `#` comment, with the contents of every string,
/// character literal, backtick, `%`-literal (`%w[…]`, `%i(…)`, `%q{…}`, …) and regexp literal
/// masked as `x`, byte for byte, so a keyword or `#` inside one never counts
/// as code. The delimiters stay. A string or `%`-literal still open at the
/// end of the line is carried in `literal` to mask the next line from its
/// start.
fn masked_ruby_code(line: &str, literal: &mut Option<Literal>) -> String {
    let bytes = line.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    if let Some(lit) = literal.take() {
        match mask_literal(bytes, &mut out, 0, lit) {
            Ok(end) => i = end + 1,
            Err(lit) => {
                *literal = Some(lit);
                i = bytes.len();
            }
        }
    }
    while i < bytes.len() {
        let b = bytes[i];
        let before = std::str::from_utf8(&out[..i]).unwrap_or_default();
        let (lit, body) = match b {
            b'#' => {
                out.truncate(i);
                break;
            }
            // A character literal (`?(`, `?}`, `?\n`): its character is
            // not code.
            b'?' if starts_expression(before) => {
                let len = match bytes.get(i + 1) {
                    Some(b'\\') => 2,
                    Some(c) if c.is_ascii_punctuation() => 1,
                    _ => 0,
                };
                let next = bytes.get(i + 1 + len).copied();
                if len > 0 && !next.is_some_and(is_ident_byte) {
                    out[i + 1..(i + 1 + len).min(bytes.len())].fill(b'x');
                }
                i += 1 + len;
                continue;
            }
            b'"' | b'\'' | b'`' => (
                Literal {
                    open: b,
                    close: b,
                    depth: 0,
                },
                i + 1,
            ),
            b'/' if starts_expression(before) => (
                Literal {
                    open: b,
                    close: b,
                    depth: 0,
                },
                i + 1,
            ),
            b'%' if starts_expression(before) => {
                let mut j = i + 1;
                if bytes.get(j).is_some_and(|c| b"wWiIqQrsx".contains(c)) {
                    j += 1;
                }
                match bytes.get(j) {
                    Some(&open) if open.is_ascii_punctuation() => {
                        let close = match open {
                            b'(' => b')',
                            b'[' => b']',
                            b'{' => b'}',
                            b'<' => b'>',
                            _ => open,
                        };
                        (
                            Literal {
                                open,
                                close,
                                depth: 0,
                            },
                            j + 1,
                        )
                    }
                    _ => {
                        i += 1;
                        continue;
                    }
                }
            }
            _ => {
                i += 1;
                continue;
            }
        };
        match mask_literal(bytes, &mut out, body, lit) {
            Ok(end) => i = end + 1,
            // An unclosed `/` was a division after all.
            Err(_) if b == b'/' => {
                out[body..].copy_from_slice(&bytes[body..]);
                i += 1;
            }
            Err(lit) => {
                *literal = Some(lit);
                break;
            }
        }
    }
    // The delimiters are ASCII, so a masked run never cuts a multi-byte
    // character: the result is still UTF-8.
    String::from_utf8(out).unwrap_or_default()
}

/// Masks `lit`'s body in `out` from byte `from` of `bytes`: `Ok` with the
/// closing delimiter's index, or `Err` with the literal still open at the
/// end of the line.
fn mask_literal(
    bytes: &[u8],
    out: &mut [u8],
    from: usize,
    mut lit: Literal,
) -> Result<usize, Literal> {
    let mut j = from;
    while j < bytes.len() {
        let c = bytes[j];
        if c == b'\\' {
            out[j] = b'x';
            if let Some(next) = out.get_mut(j + 1) {
                *next = b'x';
            }
            j += 2;
            continue;
        }
        if c == lit.close && lit.depth == 0 {
            return Ok(j);
        }
        if lit.open != lit.close && c == lit.open {
            lit.depth += 1;
        } else if lit.open != lit.close && c == lit.close {
            lit.depth -= 1;
        }
        out[j] = b'x';
        j += 1;
    }
    Err(lit)
}

/// The heredocs a line opens (`<<~EOS`, `<<-"EOS"`, `x = <<EOS`), in
/// order, as (terminator, may be indented). `masked` is `line` through
/// [`masked_ruby_code`], so an opener inside a literal or comment does not
/// count, and neither does an append (`list << x`, `a<<B`, `class <<self`):
/// a bare `<<NAME` must start an expression.
fn heredoc_openers(line: &str, masked: &str) -> Vec<(String, bool)> {
    let bytes = masked.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(at) = masked[i..].find("<<").map(|p| p + i) {
        i = at + 2;
        if at > 0 && (is_ident_byte(bytes[at - 1]) || matches!(bytes[at - 1], b')' | b']' | b'}')) {
            continue;
        }
        let mut j = at + 2;
        let indented = matches!(bytes.get(j), Some(b'~' | b'-'));
        if indented {
            j += 1;
        }
        let id = match bytes.get(j) {
            Some(&q @ (b'"' | b'\'' | b'`')) => masked[j + 1..]
                .find(q as char)
                .map(|end| &line[j + 1..j + 1 + end]),
            Some(&b)
                if (b.is_ascii_alphabetic() || b == b'_')
                    && (indented || starts_expression(&masked[..at])) =>
            {
                let len = masked[j..]
                    .bytes()
                    .position(|b| !is_ident_byte(b))
                    .unwrap_or(masked.len() - j);
                Some(&line[j..j + len])
            }
            _ => None,
        };
        if let Some(id) = id.filter(|id| !id.is_empty()) {
            out.push((id.to_string(), indented));
            i = j + 1;
        }
    }
    out
}

/// How the gem comes back into the manifest.
enum Decl {
    /// Gone: the block was the rewriter's append for a transitive gem.
    Transitive,
    /// `gem "<name>"<args>[, <opts>]`; `args` is the version constraint list
    /// (`, "7.0.0"`).
    Direct(String),
}

/// Byte offset of the start of the line before byte `at` (`at` itself at
/// the start of the text).
fn line_before_start(text: &str, at: usize) -> usize {
    match text[..at].strip_suffix('\n') {
        Some(before) => before.rfind('\n').map_or(0, |i| i + 1),
        None => at,
    }
}

fn restore_manifest(text: &str, block: &Block, gem: &Gem<'_>, decl: &Decl) -> String {
    let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut start = block.start;
    let replacement = match decl {
        // The append's own blank separator goes with it.
        Decl::Transitive => {
            if provably_appended(text, block) {
                start = line_before_start(text, block.start);
            }
            String::new()
        }
        Decl::Direct(args) => {
            let opts = block
                .opts
                .as_deref()
                .map(|o| format!(", {o}"))
                .unwrap_or_default();
            format!(
                "{}gem \"{}\"{args}{opts}{}",
                if provably_appended(text, block) {
                    String::new()
                } else {
                    declaration_prefix(text, block, eol)
                },
                gem.name,
                if block.eol { eol } else { "" }
            )
        }
    };
    format!("{}{replacement}{}", &text[..start], &text[block.end..])
}

/// The manifest's global `source "<url>"` declarations (no block).
fn global_sources(manifest: &str) -> Vec<String> {
    manifest
        .lines()
        .filter_map(|l| {
            let rest = l.trim().strip_prefix("source")?.trim_start();
            let (rest, paren) = match rest.strip_prefix('(') {
                Some(r) => (r.trim_start(), true),
                None => (rest, false),
            };
            let (_, url, tail) = quoted_literal(rest)?;
            let tail = tail.trim_start();
            let tail = if paren { tail.strip_prefix(')')? } else { tail };
            let code = tail.split('#').next().unwrap_or_default().trim();
            code.is_empty().then(|| url.to_string())
        })
        .collect()
}

/// The version-constraint args of a `DEPENDENCIES` entry (`rails (~> 7.0,
/// >= 7.0.1)` → `, "~> 7.0", ">= 7.0.1"`).
fn constraint_args(entry: &str) -> String {
    let entry = entry.trim_end_matches('!');
    let Some((_, rest)) = entry.split_once(" (") else {
        return String::new();
    };
    rest.trim_end_matches(')')
        .split(", ")
        .filter(|c| !c.is_empty())
        .map(|c| format!(", \"{c}\""))
        .collect()
}

pub(crate) async fn restore(
    view: &mut View<'_>,
    pins: &[&HostedPin],
    files: &[String],
    ctx: &Ctx<'_>,
) -> FormatResult {
    let mut result = FormatResult::default();
    for lock_rel in BUNDLER_LOCKS {
        let manifest_rel = bundler_manifest_for(lock_rel);
        if !files.iter().any(|f| f == lock_rel || f == manifest_rel) {
            continue;
        }
        let (lock_raw, manifest_raw) =
            match (view.read(lock_rel).await, view.read(manifest_rel).await) {
                (Ok(l), Ok(m)) => (l, m),
                (Err(e), _) | (_, Err(e)) => {
                    for pin in pins {
                        result.refuse(&pin.uuid, e.clone());
                    }
                    continue;
                }
            };
        let endings = lock_raw.as_deref().map(LineEndings::of);
        let mut lock: Option<String> = lock_raw.as_deref().map(|t| to_lf(t).into_owned());
        let mut manifest = manifest_raw.clone();
        let globals = manifest.as_deref().map(global_sources).unwrap_or_default();
        let handled_before = result.handled.clone();
        // Pins the lock wires go first, so one whose superseding patch's
        // manifest block is also a pin here undoes that block itself
        // (#1626), and the block's own pin then has nothing left to do.
        let lock_wires = |uuid: &str| {
            lock.as_deref().is_some_and(|l| {
                let lines: Vec<&str> = l.split('\n').collect();
                matches!(wiring(&gem_sections(&lines), uuid, ctx), Ok(Some(_)))
            })
        };
        let mut ordered: Vec<&&HostedPin> = pins.iter().collect();
        ordered.sort_by_key(|p| !lock_wires(&p.uuid));
        let mut undone: Vec<String> = Vec::new();
        for pin in ordered {
            if result.refused.contains_key(&pin.uuid) {
                continue;
            }
            if undone.contains(&pin.uuid) {
                result.handled.insert(pin.uuid.clone());
                continue;
            }
            let Some((name, version)) = pin.name_version() else {
                result.refuse(&pin.uuid, format!("{} is not a gem purl", pin.purl));
                continue;
            };
            let gem = Gem {
                uuid: &pin.uuid,
                name,
                version,
            };
            match restore_one(
                &gem,
                lock.as_deref(),
                manifest.as_deref(),
                manifest_rel,
                &globals,
                ctx,
            )
            .await
            {
                Ok(None) => {}
                Ok(Some((next_lock, next_manifest, superseded))) => {
                    if endings == Some(LineEndings::Mixed) && next_lock != lock {
                        result.refuse(
                            &pin.uuid,
                            format!("{lock_rel} mixes CRLF and LF line endings"),
                        );
                        continue;
                    }
                    lock = next_lock;
                    manifest = next_manifest;
                    result.handled.insert(pin.uuid.clone());
                    undone.extend(superseded);
                }
                Err(why) => result.refuse(&pin.uuid, why),
            }
        }
        // The pins this pair restored, each judged once against its own
        // restored lock (a superseding pin shares its archive with the pin
        // that undid it).
        for pin in pins {
            if !result.handled.contains(&pin.uuid)
                || handled_before.contains(&pin.uuid)
                || result.refused.contains_key(&pin.uuid)
                || undone.contains(&pin.uuid)
            {
                continue;
            }
            let Some((name, version)) = pin.name_version() else {
                continue;
            };
            if let Some(warning) = stale_cache_warning(
                view.root(),
                &pin.purl,
                &name,
                &version,
                lock.as_deref(),
                ctx.client,
            )
            .await
            {
                result.warnings.push(warning);
            }
        }
        if let (Some(next), Some(endings)) = (lock, endings) {
            let next = endings.restore(&next).into_owned();
            if lock_raw.as_deref() != Some(next.as_str()) {
                view.write(lock_rel, next);
            }
        }
        if manifest != manifest_raw {
            if let Some(next) = manifest {
                view.write(manifest_rel, next);
            }
        }
    }
    result
}

/// The warning code for a patched archive left in Bundler's cache dir by
/// an unwind (the restore-side counterpart of scan's
/// `redirect_gem_stale_install`).
pub(crate) const STALE_CACHE: &str = "upstream_gem_stale_cache";

/// The `CHECKSUMS` sha256 the lock pins for `name (version)`, if any.
fn lock_checksum(lock: &str, name: &str, version: &str) -> Option<String> {
    let lines: Vec<&str> = lock.split('\n').collect();
    let (s, e) = named_section(&lines, "CHECKSUMS")?;
    lines[s..e].iter().find_map(|line| {
        let entry = indented(line, 2)?.trim_end();
        let (n, token, tail) = split_checksum_entry(entry)?;
        if n != name || token != version {
            return None;
        }
        tail.split_whitespace()
            .find_map(|tok| tok.strip_prefix("sha256="))
            .map(str::to_ascii_lowercase)
    })
}

/// A restored gem whose `<name>-<version>.gem` still sits in Bundler's
/// cache dir (`cache_path`, default `vendor/cache`) and is not proven to
/// be the upstream archive: bundler installs from that dir before
/// fetching, so the archive a `bundle cache` took while the hosted pin was
/// live keeps installing the patched bytes (bundler < 2.6, frozen) or
/// fails every install against the restored upstream checksum (#1260).
/// The upstream sha is the restored lock's `CHECKSUMS` entry, else the
/// rubygems.org compact index (already fetched when the restore re-pinned
/// `CHECKSUMS`). Read-only, like scan's guard: the file is named, never
/// deleted.
async fn stale_cache_warning(
    root: &std::path::Path,
    purl: &str,
    name: &str,
    version: &str,
    lock: Option<&str>,
    client: &UpstreamClient,
) -> Option<(&'static str, String)> {
    let cache_dir = crate::crawlers::ruby_crawler::bundler_app_cache_dir(root).await;
    let archive = cache_dir.join(format!("{name}-{version}.gem"));
    if !archive.is_file() {
        return None;
    }
    let got = crate::vendor::file_sha256_hex(&archive).await;
    let upstream = match lock.and_then(|l| lock_checksum(l, name, version)) {
        Some(sha) => Ok(sha),
        None => client.rubygems_sha256(name, version).await,
    };
    let fix = "delete it, then run `bundle cache` to cache the upstream gem in its place \
               (or `bundle install` if the project does not commit its cache)";
    let detail = match (got, upstream) {
        (Some(got), Ok(want)) if got.eq_ignore_ascii_case(&want) => return None,
        (Some(_), Ok(_)) => format!(
            "{purl} is back on its upstream registry entry, but Bundler's cache dir still \
             holds a non-upstream (patched) archive at {path}; bundler installs from that \
             dir first, so installs fail on the upstream checksum or keep the patched \
             bytes: {fix}",
            path = archive.display(),
        ),
        (_, why) => format!(
            "{purl} is back on its upstream registry entry, but Bundler's cache dir holds \
             {path}, which could not be checked against the upstream sha256{why}; if it \
             was cached while the hosted patch was live, bundler keeps installing it: \
             {fix}",
            path = archive.display(),
            why = match why {
                Err(e) => format!(" ({e})"),
                Ok(_) => " (the archive is unreadable)".to_string(),
            },
        ),
    };
    Some((STALE_CACHE, detail))
}

/// [`STALE_CACHE`] for a gem a vendored unwind (`remove`, `rollback`,
/// `vendor --revert`, `scan --prune`, `vendor`'s reconcile) put back on its
/// upstream `GEM` entry at `root` (#1594). The archive a `bundle cache`
/// took while a hosted pin was live survives a hosted → vendored takeover
/// (the path source shadows it), so once the vendored copy is unwired
/// bundler installs from it again. Judged like the hosted restore's check,
/// against the lock's `CHECKSUMS` entry, else the rubygems.org compact
/// index (unless `offline`). A gem locked from another remote with no
/// `CHECKSUMS` sha can't be judged, and is most likely a private gem cached
/// on purpose: no warning.
pub(super) async fn unwound_stale_cache(
    root: &std::path::Path,
    purl: &str,
    offline: bool,
) -> Option<(&'static str, String)> {
    let (_, name, version) = crate::utils::purl::purl_parts(purl)?;
    let mut lock = None;
    for file in BUNDLER_LOCKS {
        // Guarded: a FIFO or device squatting the lock path must not block.
        if let Ok(text) = crate::utils::fs::read_regular_to_string(&root.join(file)).await {
            lock = Some(text);
            break;
        }
    }
    if let Some(text) = &lock {
        if lock_checksum(text, &name, &version).is_none() && !rubygems_locked(text, &name, &version)
        {
            return None;
        }
    }
    let client = UpstreamClient::new(offline);
    stale_cache_warning(root, purl, &name, &version, lock.as_deref(), &client).await
}

/// Whether `lock` resolves `name (version)` from a `GEM` section whose
/// remote is rubygems.org (or the `SOCKET_RUBYGEMS_URL` stand-in).
fn rubygems_locked(lock: &str, name: &str, version: &str) -> bool {
    let lines: Vec<&str> = lock.split('\n').collect();
    let base = super::rubygems_base();
    gem_sections(&lines).iter().any(|sec| {
        sec.entries
            .iter()
            .any(|e| e.name == name && e.version == version && !e.platform)
            && sec
                .remotes
                .iter()
                .any(|(_, r)| same_remote(r, RUBYGEMS_REMOTE) || same_remote(r, &base))
    })
}

/// Restore one gem in a lock + manifest pair: `Ok(None)` when neither wires
/// it, else the next `(lock, manifest)` texts and the uuid of a superseding
/// patch whose block was undone with it ([`superseded_block`]).
async fn restore_one(
    gem: &Gem<'_>,
    lock: Option<&str>,
    manifest: Option<&str>,
    manifest_rel: &str,
    globals: &[String],
    ctx: &Ctx<'_>,
) -> Result<Option<RestoredPair>, String> {
    let mut block = match manifest {
        Some(text) => find_block(text, gem, manifest_rel, ctx)?,
        None => None,
    };
    let lines: Vec<&str> = lock.map(|l| l.split('\n').collect()).unwrap_or_default();
    let wired = match lock {
        Some(_) => wiring(&gem_sections(&lines), gem.uuid, ctx)?.is_some(),
        None => false,
    };
    let mut superseded = None;
    if wired && block.is_none() {
        if let Some((b, uuid)) = manifest
            .map(|text| superseded_block(text, gem, manifest_rel, ctx))
            .transpose()?
            .flatten()
        {
            block = Some(b);
            superseded = Some(uuid);
        }
    }
    if !wired && block.is_none() {
        return Ok(None);
    }
    // The other side of #1626: the manifest's block is this (superseding)
    // patch's, but the lock still pins the gem to an earlier Socket patch.
    // Undoing the block alone would leave the lock on that patch, so only
    // the earlier patch's pin (which undoes both) can restore the pair.
    if !wired {
        if let Some(earlier) = earlier_lock_pin(&lines, gem, ctx) {
            return Err(format!(
                "the lock still pins it to the earlier Socket patch {earlier} (a superseding \
                 re-scan moved only {manifest_rel}); restore that patch's pin, or run \
                 `bundle install` first so the lock follows {manifest_rel}"
            ));
        }
    }
    let decl = if wired {
        let transitive = block.as_ref().is_some_and(|b| {
            b.opts.is_none()
                && manifest.is_some_and(|m| provably_appended(m, b))
                && is_subdependency(&lines, &gem.name)
        });
        if transitive {
            Decl::Transitive
        } else {
            Decl::Direct(format!(", \"{}\"", gem.version))
        }
    } else if lock.is_some() {
        // Mixed state: the lock was never touched, so its DEPENDENCIES say
        // how (and whether) the manifest declared the gem.
        match dependency_line(&lines, &gem.name) {
            Some((_, entry)) => Decl::Direct(constraint_args(entry)),
            None => Decl::Transitive,
        }
    } else {
        Decl::Direct(format!(", \"{}\"", gem.version))
    };
    // The restored declaration goes back where the block is: a user
    // `source … do` block around it keeps the `!` bundler wrote for it.
    let dep = match (&decl, &block, manifest) {
        (Decl::Transitive, _, _) => DepEntry::Drop,
        (Decl::Direct(_), Some(b), Some(text)) if in_source_block(text, b.start) => DepEntry::Keep,
        (Decl::Direct(_), _, _) => DepEntry::Unpin,
    };
    let next_lock = match lock {
        None => None,
        Some(text) => Some(match lock_edit(text, gem, globals, dep, None, ctx)? {
            LockEdit::Done(next) => next,
            LockEdit::NeedsSha { remote } => {
                let remote = remote.ok_or("its upstream GEM remote is ambiguous")?;
                if !same_remote(&remote, RUBYGEMS_REMOTE) {
                    return Err(format!(
                        "its upstream GEM remote {remote} is not rubygems.org, so its CHECKSUMS \
                         sha256 cannot be re-derived"
                    ));
                }
                let sha = ctx
                    .client
                    .rubygems_sha256(&gem.name, &gem.version)
                    .await
                    .map_err(|why| format!("{} {}: {why}", gem.name, gem.version))?;
                match lock_edit(text, gem, globals, dep, Some(&sha), ctx)? {
                    LockEdit::Done(next) => next,
                    LockEdit::NeedsSha { .. } => unreachable!("a sha was supplied"),
                }
            }
        }),
    };
    let next_manifest = match (manifest, &block) {
        (Some(text), Some(b)) => Some(restore_manifest(text, b, gem, &decl)),
        _ => manifest.map(str::to_string),
    };
    Ok(Some((next_lock, next_manifest, superseded)))
}

/// What [`restore_one`] gives back: the next lock and manifest texts, and
/// the superseding patch whose block it undid.
type RestoredPair = (Option<String>, Option<String>, Option<String>);

/// Another Socket patch's uuid whose own lock section locks `gem`'s name
/// and version (the lock side of an unconverged superseding re-scan). Only
/// a single-remote section says which patch serves a spec: a merged
/// section (bundler < 2.2) lists every remote's specs together, so another
/// gem's Socket remote there says nothing about this gem.
fn earlier_lock_pin(lines: &[&str], gem: &Gem<'_>, ctx: &Ctx<'_>) -> Option<String> {
    gem_sections(lines).iter().find_map(|s| {
        let [(_, remote)] = s.remotes.as_slice() else {
            return None;
        };
        if !s
            .entries
            .iter()
            .any(|e| e.name == gem.name && e.version == gem.version)
        {
            return None;
        }
        ctx.hosted_uuid(remote).filter(|uuid| uuid != gem.uuid)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "77777777-7777-7777-7777-777777777777";
    const IDX: &str = "https://patch.socket.dev/patch-registry/gem/11111111-1111-1111-1111-111111111111/77777777-7777-7777-7777-777777777777/";

    fn ctx_with<'a>(client: &'a super::super::UpstreamClient) -> Ctx<'a> {
        Ctx {
            client,
            origins: &[],
            bun_lockb: false,
        }
    }

    fn gem() -> Gem<'static> {
        Gem {
            uuid: UUID,
            name: "rails".into(),
            version: "7.0.0".into(),
        }
    }

    fn done(e: LockEdit) -> String {
        match e {
            LockEdit::Done(t) => t,
            LockEdit::NeedsSha { .. } => panic!("unexpected sha request"),
        }
    }

    #[test]
    fn converged_section_moves_back_in_name_order() {
        let client = super::super::UpstreamClient::new(true);
        let ctx = ctx_with(&client);
        let hosted = format!(
            "GEM\n  remote: {IDX}\n  specs:\n    rails (7.0.0)\n      rack (>= 2)\n\nGEM\n  \
             remote: https://rubygems.org/\n  specs:\n    puma (6.0.0)\n    rack (3.0.0)\n    \
             zeitwerk (2.6.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  puma\n  rails (= 7.0.0)!\n\n\
             BUNDLED WITH\n   2.4.0\n"
        );
        let want = "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.0.0)\n    rack \
                    (3.0.0)\n    rails (7.0.0)\n      rack (>= 2)\n    zeitwerk (2.6.0)\n\nPLATFORMS\n  \
                    ruby\n\nDEPENDENCIES\n  puma\n  rails (= 7.0.0)\n\nBUNDLED WITH\n   2.4.0\n";
        // No CHECKSUMS (bundler 2.2–2.5): no registry lookup, offline works.
        assert_eq!(
            done(lock_edit(&hosted, &gem(), &[], DepEntry::Unpin, None, &ctx).unwrap()),
            want
        );
        // Transitive: the DEPENDENCIES entry the rewriter added goes.
        let out = done(lock_edit(&hosted, &gem(), &[], DepEntry::Drop, None, &ctx).unwrap());
        assert!(out.contains("DEPENDENCIES\n  puma\n\n"), "{out}");
    }

    #[test]
    fn checksums_need_the_upstream_sha() {
        let client = super::super::UpstreamClient::new(true);
        let ctx = ctx_with(&client);
        let hosted = format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n\nGEM\n  remote: {IDX}\n  specs:\n    \
             rails (7.0.0)\n\nDEPENDENCIES\n  rails (= 7.0.0)!\n\nCHECKSUMS\n  rails (7.0.0) \
             sha256={}\n",
            "d".repeat(64)
        );
        match lock_edit(&hosted, &gem(), &[], DepEntry::Unpin, None, &ctx).unwrap() {
            LockEdit::NeedsSha { remote } => {
                assert_eq!(remote.as_deref(), Some("https://rubygems.org/"))
            }
            LockEdit::Done(_) => panic!("CHECKSUMS entry left patched"),
        }
        let sha = "2".repeat(64);
        assert_eq!(
            done(lock_edit(&hosted, &gem(), &[], DepEntry::Unpin, Some(&sha), &ctx).unwrap()),
            format!(
                "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n\nDEPENDENCIES\n  \
                 rails (= 7.0.0)\n\nCHECKSUMS\n  rails (7.0.0) sha256={sha}\n"
            )
        );
        // The rewriter's ADDED entry next to bundler's bare one is dropped.
        let added = hosted.replace("CHECKSUMS\n", "CHECKSUMS\n  rails (7.0.0)\n");
        assert!(
            done(lock_edit(&added, &gem(), &[], DepEntry::Unpin, None, &ctx).unwrap())
                .ends_with("CHECKSUMS\n  rails (7.0.0)\n")
        );
    }

    #[test]
    fn merged_section_drops_only_the_socket_remote() {
        let client = super::super::UpstreamClient::new(true);
        let ctx = ctx_with(&client);
        let hosted = format!(
            "GEM\n  remote: https://rubygems.org/\n  remote: {IDX}\n  specs:\n    puma (6.0.0)\n    \
             rails (7.0.0)\n\nDEPENDENCIES\n  puma\n  rails (= 7.0.0)!\n\nBUNDLED WITH\n   2.1.4\n"
        );
        assert_eq!(
            done(lock_edit(&hosted, &gem(), &[], DepEntry::Unpin, None, &ctx).unwrap()),
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.0.0)\n    rails (7.0.0)\n\n\
             DEPENDENCIES\n  puma\n  rails (= 7.0.0)\n\nBUNDLED WITH\n   2.1.4\n"
        );
    }

    #[test]
    fn ambiguous_or_foreign_sections_are_refused() {
        let client = super::super::UpstreamClient::new(true);
        let ctx = ctx_with(&client);
        let two_upstreams = format!(
            "GEM\n  remote: https://gems.example/\n  specs:\n\nGEM\n  remote: https://mirror.example/\n  \
             specs:\n\nGEM\n  remote: {IDX}\n  specs:\n    rails (7.0.0)\n\nDEPENDENCIES\n  rails (= 7.0.0)!\n"
        );
        assert!(lock_edit(&two_upstreams, &gem(), &[], DepEntry::Unpin, None, &ctx).is_err());
        // The manifest's global source singles one out.
        let globals = vec!["https://mirror.example".to_string()];
        let out = done(
            lock_edit(
                &two_upstreams,
                &gem(),
                &globals,
                DepEntry::Unpin,
                None,
                &ctx,
            )
            .unwrap(),
        );
        assert!(
            out.contains("remote: https://mirror.example/\n  specs:\n    rails (7.0.0)\n"),
            "{out}"
        );
        // A Socket section locking another gem too is not ours to split.
        let extra = format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n\nGEM\n  remote: {IDX}\n  specs:\n    \
             rack (3.0.0)\n    rails (7.0.0)\n\nDEPENDENCIES\n  rails (= 7.0.0)!\n"
        );
        assert!(lock_edit(&extra, &gem(), &[], DepEntry::Unpin, None, &ctx).is_err());
        let none = format!(
            "GEM\n  remote: {IDX}\n  specs:\n    rails (7.0.0)\n\nDEPENDENCIES\n  rails!\n"
        );
        assert!(lock_edit(&none, &gem(), &[], DepEntry::Unpin, None, &ctx).is_err());
    }

    #[test]
    fn manifest_blocks_restore_in_place() {
        let client = super::super::UpstreamClient::new(true);
        let ctx = ctx_with(&client);
        let block = format!("source \"{IDX}\" do\n  gem \"rails\", \"7.0.0\"\nend");
        let direct = Decl::Direct(", \"7.0.0\"".into());
        let run = |text: &str, decl: &Decl| {
            let b = find_block(text, &gem(), "Gemfile", &ctx).unwrap().unwrap();
            restore_manifest(text, &b, &gem(), decl)
        };
        // After a global source: one blank line comes back.
        let t = format!("source \"https://rubygems.org\"\n{block}\ngem \"puma\"\n");
        assert_eq!(
            run(&t, &direct),
            "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\ngem \"puma\"\n"
        );
        // Inside a group: the group's indent + 2, options kept.
        let t = format!(
            "group :test do\nsource \"{IDX}\" do\n  gem \"rails\", \"7.0.0\", require: false\nend\nend\n"
        );
        assert_eq!(
            run(&t, &direct),
            "group :test do\n  gem \"rails\", \"7.0.0\", require: false\nend\n"
        );
        // CRLF manifest (the rewriter wrote its block in LF).
        let t = format!("source \"https://rubygems.org\"\r\ngem \"puma\"\r\n{block}\n");
        assert_eq!(
            run(&t, &direct),
            "source \"https://rubygems.org\"\r\ngem \"puma\"\r\ngem \"rails\", \"7.0.0\"\r\n"
        );
        // Transitive append removed with the blank line the rewriter puts
        // before it; mixed-state constraint kept.
        let t = format!("source \"https://rubygems.org\"\n\ngem \"puma\"\n\n{block}\n");
        assert_eq!(
            run(&t, &Decl::Transitive),
            "source \"https://rubygems.org\"\n\ngem \"puma\"\n"
        );
        // An append from before that separator existed (no blank line):
        // only the block goes.
        let t = format!("gem \"puma\"\n{block}\n");
        assert_eq!(run(&t, &Decl::Transitive), "gem \"puma\"\n");
        // After an inner `end` inside a block (#1476): the block's indent +
        // 2, a blank line only when another declaration follows.
        let t = format!("group :test do\n  if x\n    gem \"a\"\n  end\n{block}\nend\n");
        assert_eq!(
            run(&t, &direct),
            "group :test do\n  if x\n    gem \"a\"\n  end\n  gem \"rails\", \"7.0.0\"\nend\n"
        );
        let t =
            format!("group :test do\n  if x\n    gem \"a\"\n  end\n{block}\n  gem \"b\"\nend\n");
        assert_eq!(
            run(&t, &direct),
            "group :test do\n  if x\n    gem \"a\"\n  end\n\n  gem \"rails\", \"7.0.0\"\n  gem \"b\"\nend\n"
        );
        // A multi-line opener: the indent of the statement's first line.
        let t = format!("group :development,\n      :test do\n  if x\n  end\n{block}\nend\n");
        assert_eq!(
            run(&t, &direct),
            "group :development,\n      :test do\n  if x\n  end\n  gem \"rails\", \"7.0.0\"\nend\n"
        );
        let t = format!("gem \"puma\"\n{block}\n");
        assert_eq!(
            run(&t, &Decl::Direct(constraint_args("rails (>= 6, ~> 7.0)"))),
            "gem \"puma\"\ngem \"rails\", \">= 6\", \"~> 7.0\"\n"
        );
    }

    #[test]
    fn manifest_shapes_it_cannot_unwind_are_refused() {
        let client = super::super::UpstreamClient::new(true);
        let ctx = ctx_with(&client);
        let block = format!("source \"{IDX}\" do\n  gem \"rails\", \"7.0.0\"\nend\n");
        assert!(find_block(&format!("{block}{block}"), &gem(), "Gemfile", &ctx).is_err());
        let edited = format!("source \"{IDX}\" do\n  gem \"rails\", \"~> 7.0\"\nend\n");
        assert!(find_block(&edited, &gem(), "Gemfile", &ctx).is_err());
        assert!(find_block("gem \"rails\"\n", &gem(), "Gemfile", &ctx)
            .unwrap()
            .is_none());
    }

    #[test]
    fn provably_transitive_needs_a_blank_line_before_the_block() {
        let client = super::super::UpstreamClient::new(true);
        let ctx = ctx_with(&client);
        let block = format!("source \"{IDX}\" do\n  gem \"rails\", \"7.0.0\"\nend\n");
        let appended = format!("gem \"puma\"\n\n{block}");
        let b = find_block(&appended, &gem(), "Gemfile", &ctx)
            .unwrap()
            .unwrap();
        assert!(provably_appended(&appended, &b));
        let ambiguous = format!("gem \"puma\"\n{block}");
        let b = find_block(&ambiguous, &gem(), "Gemfile", &ctx)
            .unwrap()
            .unwrap();
        assert!(!provably_appended(&ambiguous, &b));
        assert!(is_subdependency(
            &["    x (1.0)", "      rails (>= 7)"],
            "rails"
        ));
        assert!(!is_subdependency(&["    rails (7.0.0)"], "rails"));
    }

    /// #457: what the hosted rewriter itself writes for a TRANSITIVE gem
    /// (an appended block, converged CHECKSUMS lock) must be recognized as
    /// its append, and undoing it must give the manifest back byte for
    /// byte, whatever its trailing newlines. A hand-built fixture is not
    /// enough: the rewriter used to append with no blank line before the
    /// block, so rollback re-added the gem as a direct exact pin.
    #[test]
    fn rewriter_transitive_append_restores_byte_identically() {
        use crate::patch::redirect::{
            rewrite_registry_redirect, DepOverride, Integrity, RegistryOverride,
            RegistryOverrideIdentifiers,
        };
        let client = super::super::UpstreamClient::new(true);
        let ctx = ctx_with(&client);
        let ov = DepOverride {
            ecosystem: "gem".into(),
            name: "rails".into(),
            namespace: None,
            version: "7.0.0".into(),
            token: "tok".into(),
            patch_uuid: UUID.into(),
            artifact_url: "https://patch.test/rails-7.0.0.gem".into(),
            registry_override: Some(RegistryOverride {
                kind: "rubygems-compact-index".into(),
                index_url: IDX.into(),
                identifiers: RegistryOverrideIdentifiers {
                    name: "rails".into(),
                    version: "7.0.0".into(),
                    gem_checksum_sha256: Some("f".repeat(64)),
                    ..Default::default()
                },
            }),
            integrity: Integrity::default(),
        };
        let lock = format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.0.0)\n      rails (>= 7)\n    \
             rails (7.0.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  puma\n\nCHECKSUMS\n  puma (6.0.0) \
             sha256={}\n  rails (7.0.0) sha256={}\n\nBUNDLED WITH\n   4.0.17\n",
            "a".repeat(64),
            "2".repeat(64)
        );
        let lf = "source \"https://rubygems.org\"\n\ngem \"puma\"\n";
        let crlf = lf.replace('\n', "\r\n");
        let unterminated = lf.trim_end_matches('\n');
        for (original, restored) in [
            // The issue's shape: the manifest ends with a declaration + LF.
            (lf.to_string(), lf.to_string()),
            // A trailing blank line (the issue's passing control).
            (format!("{lf}\n"), format!("{lf}\n")),
            (crlf.clone(), crlf.clone()),
            // No final line break: it comes back with one.
            (unterminated.to_string(), lf.to_string()),
        ] {
            let files = BTreeMap::from([
                ("Gemfile".to_string(), original.clone()),
                ("Gemfile.lock".to_string(), lock.clone()),
            ]);
            let r = rewrite_registry_redirect(&files, std::slice::from_ref(&ov));
            let gemfile = &r.files["Gemfile"];
            let lock_out = &r.files["Gemfile.lock"];
            assert!(
                lock_out.contains("  rails (= 7.0.0)!"),
                "converged lock: {lock_out}"
            );
            let b = find_block(gemfile, &gem(), "Gemfile", &ctx)
                .unwrap()
                .expect("the appended block is found");
            assert!(b.opts.is_none());
            assert!(
                provably_appended(gemfile, &b),
                "the rewriter's append must be provably an append: {gemfile:?}"
            );
            let lines: Vec<&str> = lock_out.split('\n').collect();
            assert!(is_subdependency(&lines, "rails"));
            assert_eq!(
                restore_manifest(gemfile, &b, &gem(), &Decl::Transitive),
                restored,
                "from {gemfile:?}"
            );
        }

        // Two transitive appends (two patches) unwind in either order.
        const RACK_UUID: &str = "88888888-8888-8888-8888-888888888888";
        let rack_ov = DepOverride {
            name: "rack".into(),
            version: "3.0.0".into(),
            patch_uuid: RACK_UUID.into(),
            registry_override: ov.registry_override.clone().map(|mut ro| {
                ro.index_url = IDX.replace(UUID, RACK_UUID);
                ro.identifiers.name = "rack".into();
                ro.identifiers.version = "3.0.0".into();
                ro
            }),
            ..ov.clone()
        };
        // A CHECKSUMS-less lock resolving both (hosted mode pins only a
        // version a lock resolves, #1125) and left untouched by the rewrite.
        let files = BTreeMap::from([
            ("Gemfile".to_string(), lf.to_string()),
            (
                "Gemfile.lock".to_string(),
                "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.0.0)\n      \
                 rack (>= 3)\n      rails (>= 7)\n    rack (3.0.0)\n    rails (7.0.0)\n\n\
                 PLATFORMS\n  ruby\n\nDEPENDENCIES\n  puma\n\nBUNDLED WITH\n   2.5.23\n"
                    .to_string(),
            ),
        ]);
        let gemfile =
            rewrite_registry_redirect(&files, &[ov.clone(), rack_ov]).files["Gemfile"].clone();
        let rack = || Gem {
            uuid: RACK_UUID,
            name: "rack".into(),
            version: "3.0.0".into(),
        };
        for (first, second) in [(gem(), rack()), (rack(), gem())] {
            let b = find_block(&gemfile, &first, "Gemfile", &ctx)
                .unwrap()
                .unwrap();
            assert!(provably_appended(&gemfile, &b), "{gemfile:?}");
            let half = restore_manifest(&gemfile, &b, &first, &Decl::Transitive);
            let b = find_block(&half, &second, "Gemfile", &ctx)
                .unwrap()
                .unwrap();
            assert!(provably_appended(&half, &b), "{half:?}");
            assert_eq!(restore_manifest(&half, &b, &second, &Decl::Transitive), lf);
        }
    }

    /// #457, the whole restore: `scan --mode hosted` on a converged
    /// (CHECKSUMS) lock redirects a transitive gem, and `rollback` /
    /// `remove` must give the pair back byte for byte: no new `gem` line in
    /// the manifest, no `(= version)` DEPENDENCIES pin in the lock (which
    /// would freeze the vulnerable version against `bundle update`).
    #[tokio::test]
    async fn transitive_redirect_round_trips_through_restore() {
        let client = super::super::UpstreamClient::new(true);
        let upstream_sha = "2".repeat(64);
        client
            .seed_rubygems_sha256("rails", "7.0.0", &upstream_sha)
            .await;
        let ctx = ctx_with(&client);
        let manifest = "source \"https://rubygems.org\"\n\ngem \"puma\", \"6.0.0\"\n";
        let lock = format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.0.0)\n      rails (>= 7)\n    \
             rails (7.0.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  puma (= 6.0.0)\n\nCHECKSUMS\n  \
             puma (6.0.0) sha256={}\n  rails (7.0.0) sha256={upstream_sha}\n\nBUNDLED WITH\n   4.0.17\n",
            "a".repeat(64)
        );
        let files = BTreeMap::from([
            ("Gemfile".to_string(), manifest.to_string()),
            ("Gemfile.lock".to_string(), lock.clone()),
        ]);
        let r = crate::patch::redirect::rewrite_registry_redirect(
            &files,
            &[crate::patch::redirect::DepOverride {
                ecosystem: "gem".into(),
                name: "rails".into(),
                namespace: None,
                version: "7.0.0".into(),
                token: "tok".into(),
                patch_uuid: UUID.into(),
                artifact_url: "https://patch.test/rails-7.0.0.gem".into(),
                registry_override: Some(crate::patch::redirect::RegistryOverride {
                    kind: "rubygems-compact-index".into(),
                    index_url: IDX.into(),
                    identifiers: crate::patch::redirect::RegistryOverrideIdentifiers {
                        name: "rails".into(),
                        version: "7.0.0".into(),
                        gem_checksum_sha256: Some("f".repeat(64)),
                        ..Default::default()
                    },
                }),
                integrity: Default::default(),
            }],
        );
        let (hosted_manifest, hosted_lock) = (&r.files["Gemfile"], &r.files["Gemfile.lock"]);
        assert!(hosted_lock.contains("  rails (= 7.0.0)!"), "{hosted_lock}");
        let (next_lock, next_manifest, _) = restore_one(
            &gem(),
            Some(hosted_lock),
            Some(hosted_manifest),
            "Gemfile",
            &global_sources(hosted_manifest),
            &ctx,
        )
        .await
        .unwrap()
        .expect("the redirect is found");
        assert_eq!(next_manifest.as_deref(), Some(manifest));
        assert_eq!(next_lock.as_deref(), Some(lock.as_str()));
    }

    /// #1056: a gem the user declared inside a `source "…" do` block is
    /// locked with a `!` source pin in `DEPENDENCIES` (bundler writes it
    /// for any dependency with an explicit source, rubygems.org included).
    /// The unwind puts the declaration back inside that block, so the `!`
    /// must stay or every frozen install refuses the restored pair.
    #[tokio::test]
    async fn source_block_declaration_keeps_its_bang_through_restore() {
        let client = super::super::UpstreamClient::new(true);
        let upstream_sha = "2".repeat(64);
        client
            .seed_rubygems_sha256("rails", "7.0.0", &upstream_sha)
            .await;
        let ctx = ctx_with(&client);
        for manifest in [
            "source \"https://rubygems.org\"\n\ngem \"puma\"\nsource \"https://rubygems.org\" do\n  \
             gem \"rails\", \"7.0.0\"\nend\n",
            // Nested in a group inside the source block, parenthesized opener.
            "source \"https://rubygems.org\"\n\ngem \"puma\"\nsource(\"https://rubygems.org\") do\n  \
             group :web do\n    gem \"rails\", \"7.0.0\"\n  end\nend\n",
            // Assignment-form keyword constructs before the declaration
            // (#1476): their `end`s close them, not the source block, and
            // the declaration comes back at the block's indent.
            "source \"https://rubygems.org\"\n\ngem \"puma\"\nsource \"https://rubygems.org\" do\n  \
             v = if ENV[\"ZZ\"]\n    \"a\"\n  else\n    \"b\"\n  end\n  gem \"rails\", \"7.0.0\"\nend\n",
            "source \"https://rubygems.org\"\n\ngem \"puma\"\nsource \"https://rubygems.org\" do\n  \
             v = case ENV[\"ZZ\"]\n      when \"x\" then \"a\"\n      else \"b\"\n      end\n  \
             w = begin\n    1\n  rescue\n    2\n  end\n  gem \"rails\", \"7.0.0\"\nend\n",
            "source \"https://rubygems.org\"\n\ngem \"puma\"\nsource \"https://rubygems.org\" do\n  \
             x ||= unless ENV[\"ZZ\"]\n    1\n  end\n  y = (while false\n  end)\n  \
             gem \"rails\", \"7.0.0\"\nend\n",
            // An `end` indented deeper than the block's body: the
            // declaration takes the block's body indent, not the `end`'s.
            "source \"https://rubygems.org\"\n\ngem \"puma\"\nsource \"https://rubygems.org\" do\n  \
             w = case ENV[\"ZZ\"]\n      when \"x\" then \"a\"\n      end\n  gem \"rails\", \"7.0.0\"\nend\n",
            // #1509: an opener whose arguments span lines, and a brace
            // block, which also sets the declaration's indent.
            "source \"https://rubygems.org\"\n\ngem \"puma\"\nsource(\n  \"https://rubygems.org\"\n) do\n  \
             gem \"rails\", \"7.0.0\"\nend\n",
            "source \"https://rubygems.org\"\n\ngem \"puma\"\nsource(\"https://rubygems.org\") {\n  \
             gem \"rails\", \"7.0.0\"\n}\n",
            // First of two in a multi-line opener's block: no blank line
            // comes back between the opener and the declaration.
            "source \"https://rubygems.org\"\n\ngem \"puma\"\nsource(\n  \"https://rubygems.org\"\n) do\n  \
             gem \"rails\", \"7.0.0\"\n  gem \"rack\"\nend\n",
            // #1531: an opener after a `;`, also on a statement's
            // continuation line, whose own indent the declaration follows.
            "source \"https://rubygems.org\"\n\ngem \"puma\"\nzz = 1; source \"https://rubygems.org\" do\n  \
             gem \"rails\", \"7.0.0\"\nend\n",
            "source \"https://rubygems.org\"\n\ngem \"puma\"\n    zz = [1,\n2]; source \"https://rubygems.org\" do\n  \
             gem \"rails\", \"7.0.0\"\nend\n",
        ] {
            let lock = format!(
                "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.0.0)\n    \
                 rails (7.0.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  puma\n  \
                 rails (= 7.0.0)!\n\nCHECKSUMS\n  puma (6.0.0) sha256={}\n  rails (7.0.0) \
                 sha256={upstream_sha}\n\nBUNDLED WITH\n   4.0.22\n",
                "a".repeat(64)
            );
            let files = BTreeMap::from([
                ("Gemfile".to_string(), manifest.to_string()),
                ("Gemfile.lock".to_string(), lock.clone()),
            ]);
            let r = crate::patch::redirect::rewrite_registry_redirect(
                &files,
                &[crate::patch::redirect::DepOverride {
                    ecosystem: "gem".into(),
                    name: "rails".into(),
                    namespace: None,
                    version: "7.0.0".into(),
                    token: "tok".into(),
                    patch_uuid: UUID.into(),
                    artifact_url: "https://patch.test/rails-7.0.0.gem".into(),
                    registry_override: Some(crate::patch::redirect::RegistryOverride {
                        kind: "rubygems-compact-index".into(),
                        index_url: IDX.into(),
                        identifiers: crate::patch::redirect::RegistryOverrideIdentifiers {
                            name: "rails".into(),
                            version: "7.0.0".into(),
                            gem_checksum_sha256: Some("f".repeat(64)),
                            ..Default::default()
                        },
                    }),
                    integrity: Default::default(),
                }],
            );
            let (hosted_manifest, hosted_lock) = (&r.files["Gemfile"], &r.files["Gemfile.lock"]);
            assert!(hosted_lock.contains(IDX), "{hosted_lock}");
            let (next_lock, next_manifest, _) = restore_one(
                &gem(),
                Some(hosted_lock),
                Some(hosted_manifest),
                "Gemfile",
                &global_sources(hosted_manifest),
                &ctx,
            )
            .await
            .unwrap()
            .expect("the redirect is found");
            assert_eq!(next_manifest.as_deref(), Some(manifest));
            assert_eq!(next_lock.as_deref(), Some(lock.as_str()));
        }
    }

    #[test]
    fn source_block_opener_mid_line() {
        // #1531: a `source` call after a `;` on its line, or anywhere else
        // it starts an expression, opens a source block just as a
        // line-leading one does.
        let at = |text: &str| in_source_block(text, text.find("gem \"rails\"").unwrap());
        for opener in [
            "zz = 1; source \"https://x\" do",
            "zz = 1;source \"https://x\" do",
            "a = 1; b = 2; source \"https://x\" do",
            "zz = 1; source(\"https://x\") do",
            "zz = 1; source(\"https://x\") {",
            "zz = 1; source(\n  \"https://x\"\n) do",
            "zz = 1; source \"https://x\",\n  type: :rubygems do",
            "git_source(:gh) { |r| \"https://github.com/#{r}.git\" }; source \"https://x\" do",
            // Anywhere a `source` call starts an expression.
            "x = source \"https://x\" do",
            "if true then source \"https://x\" do",
            "a = [1,\n  2]; source \"https://x\" do",
            "source ENV.fetch(\"S\") { warn \"x\"; \"https://x\" } do",
            // A `source` call or a `do` block inside the arguments' own
            // brace block leaves the outer call's `do` its block.
            "source ENV.fetch(\"S\") { source \"https://y\" } do",
            "source ENV.fetch(\"S\") { [1].each do |v| v end; \"https://x\" } do",
        ] {
            let close = if opener.ends_with('{') { "}" } else { "end" };
            let t =
                format!("source \"https://rubygems.org\"\n\n{opener}\n  gem \"rails\"\n{close}\n");
            assert!(at(&t), "{t}");
            let t = format!(
                "source \"https://rubygems.org\"\n\n{opener}\n  gem \"a\"\n{close}\ngem \"rails\"\n"
            );
            assert!(!at(&t), "{t}");
        }
        // Not a `source` call that starts an expression.
        for line in [
            "zz = 1; group :t do",
            "zz = 1; x.source \"https://x\" do",
            "zz = 1; sources \"https://x\" do",
            "foo(1; source \"https://x\") do",
            "zz = 1; source = mirrors.first do",
            "source = mirrors.first do",
            "source == x do",
            // A `source` call inside a closed brace block does not own the
            // `do` after it.
            "urls.each { |u| log(u); source u }.then do",
            "urls.each { |u| source u }.then do",
        ] {
            let t = format!("{line}\n  gem \"rails\"\nend\n");
            assert!(!at(&t), "{t}");
        }
        // A `;` statement that is not a source call clears a line-leading
        // `source` without a block.
        assert!(!at(
            "source \"https://x\"; group :t do\n  gem \"rails\"\nend\n"
        ));
    }

    #[test]
    fn source_block_detection() {
        let at = |text: &str| in_source_block(text, text.find("gem \"rails\"").unwrap());
        assert!(!at("source \"https://rubygems.org\"\ngem \"rails\"\n"));
        assert!(!at("group :test do\n  gem \"rails\"\nend\n"));
        assert!(at(
            "source \"https://x\" do # comment\n  gem \"rails\"\nend\n"
        ));
        // #1509: an opener whose arguments span lines, and a brace block.
        assert!(at("source(\n  \"https://x\"\n) do\n  gem \"rails\"\nend\n"));
        assert!(at(
            "source \"https://x\",\n  type: :rubygems do\n  gem \"rails\"\nend\n"
        ));
        assert!(at("source(\"https://x\") {\n  gem \"rails\"\n}\n"));
        assert!(at(
            "source(\n  \"https://x\"\n) {\n  group :t do\n    gem \"rails\"\n  end\n}\n"
        ));
        // A closed brace block, or a brace block of something else, does
        // not count, and a hash's braces never close the source block.
        assert!(!at("source(\"https://x\") { gem \"a\" }\ngem \"rails\"\n"));
        assert!(!at(
            "source(\"https://x\") {\n  gem \"a\"\n}\ngem \"rails\"\n"
        ));
        assert!(!at(
            "source \"https://x\"\n[1].each {\n  gem \"rails\"\n}\n"
        ));
        assert!(!at(
            "source(\n  \"https://x\"\n)\ngroup :t do\n  gem \"rails\"\nend\n"
        ));
        assert!(at(
            "source \"https://x\" do\n  h = {\n    a: 1,\n  }\n  gem \"rails\"\nend\n"
        ));
        assert!(at(
            "source \"https://x\" do\n  gem \"a\", require: %w{b c}\n  gem \"rails\"\nend\n"
        ));
        // Only the brace block right after the `source(…)` call is the
        // source's: one on an argument's own call is not, and leaves the
        // `do` that follows it the source's block.
        assert!(at(
            "source ENV.fetch(\"S\") { \"https://x\" } do\n  gem \"rails\"\nend\n"
        ));
        assert!(!at("source foo(\"https://x\") {\n  gem \"rails\"\n}\n"));
        assert!(at(
            "source(ENV.fetch(\"S\") { warn \"x\"; \"https://x\" }) do\n  gem \"rails\"\nend\n"
        ));
        // A hash argument spanning lines keeps the statement open.
        assert!(at(
            "source \"https://x\", opts: {\n  a: 1\n} do\n  gem \"rails\"\nend\n"
        ));
        // Character literals are not brackets.
        assert!(at(
            "x = ?(\nsource \"https://x\" do\n  gem \"rails\"\nend\n"
        ));
        assert!(at(
            "source \"https://x\" do\n  sep = ?}\n  gem \"rails\"\nend\n"
        ));
        // A keyword construct inside an open bracket or a stabby lambda
        // opens a frame its `end` closes (not the source block).
        assert!(at(
            "source \"https://x\" do\n  install_if -> {\n    os = RbConfig::CONFIG[\"host_os\"]\n    \
             if os =~ /darwin/\n      true\n    end\n  } do\n    gem \"a\"\n  end\n  gem \"rails\"\nend\n"
        ));
        assert!(at(
            "source \"https://x\" do\n  gem \"a\", require: (\n    v = 1\n    if v then \"a\" end\n  )\n  \
             gem \"b\", require: (\n    v = 1\n    if v\n      \"b\"\n    end\n  )\n  gem \"rails\"\nend\n"
        ));
        // A bracket the masker misses outside a `source` statement stays
        // on its line.
        assert!(at(
            "gem \"a\", path: \"#{File.join(\"(\", \"b\")}\"\nsource \"https://x\" do\n  gem \"rails\"\nend\n"
        ));
        // A stray `}` never closes a `do` block.
        assert!(at("source \"https://x\" do\n  }\n  gem \"rails\"\nend\n"));
        // A closed source block before the declaration does not count.
        assert!(!at(
            "source \"https://x\" do\n  gem \"a\"\nend\ngroup :t do |g|\n  gem \"rails\"\nend\n"
        ));
        // A one-line block opens and closes on its line.
        assert!(!at(
            "source \"https://x\" do gem \"a\" end\ngem \"rails\"\n"
        ));
        // The `end` of an `if`/`case`/`def` inside the source block does
        // not close it.
        assert!(at(
            "source \"https://x\" do\n  if ENV[\"A\"]\n    gem \"a\"\n  end\n  gem \"rails\"\nend\n"
        ));
        assert!(at(
            "source \"https://x\" do\n  case RUBY_ENGINE\n  when \"jruby\" then gem \"a\"\n  end\n  def x; end\n  gem \"rails\"\nend\n"
        ));
        // A modifier `if` opens nothing.
        assert!(!at(
            "source \"https://x\" do\n  gem \"a\" if true\nend\ngem \"rails\"\n"
        ));
        // An assignment-form construct (#1476) opens one too, whichever
        // keyword, operator or expression position introduces it.
        for opener in [
            "v = if ENV[\"A\"]",
            "v = unless ENV[\"A\"]",
            "v = case ENV[\"A\"]\n  when \"x\" then 1",
            "v = begin\n  1\n  rescue\n  2",
            "v ||= while false",
            "v += until true",
            "v = (if true",
            "foo(1, if true",
            "x = 1; if true",
            "v = [case 1\n  when 1 then 2",
            "gem \"foo\", require: if ENV[\"A\"]",
            "gem \"foo\", :require => case ENV[\"A\"]\n  when \"x\" then 1",
            "v = c ? case x\n  when 1 then 2",
            "v = a and if b",
            "v = for x in [] do",
            "if a then 1 else\n  2 end; v = (if true",
        ] {
            let t = format!(
                "source \"https://x\" do\n  {opener}\n    1\n  end\n  gem \"rails\"\nend\n"
            );
            assert!(at(&t), "{t}");
        }
        // Closed on its own line, it nets out.
        assert!(at(
            "source \"https://x\" do\n  v = if a then 1 else 2 end\n  gem \"rails\"\nend\n"
        ));
        assert!(at(
            "source \"https://x\" do\n  v = (case a when 1 then 2 end).to_s\n  gem \"rails\"\nend\n"
        ));
        assert!(!at(
            "v = if a then 1 else 2 end\nsource \"https://x\" do\n  gem \"a\"\nend\ngem \"rails\"\n"
        ));
        // Modifiers after a value, names that only look like keywords
        // (`x.class`, `:if`, `if:`, `begin?`, `"if"`), and an endless
        // `def` open nothing, so the source block's `end` still closes it.
        for line in [
            "v = 1 if true",
            "v = x unless y",
            "x.save! if y",
            "x.empty? while y",
            "return if y",
            "v = x =~ /re/ if y",
            "v = x.class",
            "v = range.begin",
            "v = [:if, :case]",
            "foo(if: 1, case: 2)",
            "v = x.begin?",
            "v = \"if case begin\"",
            "def x = 1",
            "def x(a) = a",
            "v = loop { break }",
            "v = compute.then if ENV[\"X\"]",
            "gem \"a\", require: %w[active_support/core_ext/class]",
            "gem \"a\", platforms: %i[mri case]",
            "gem \"a\" if RUBY_PLATFORM =~ /linux|case/",
            "v = `echo if`",
            "v = a / b if c",
            "v = a % b if c",
        ] {
            let t = format!("source \"https://x\" do\n  {line}\nend\ngem \"rails\"\n");
            assert!(!at(&t), "{t}");
        }
        // A `while … do` loop takes one `end`, not two.
        assert!(!at(
            "source \"https://x\" do\n  while false do\n  end\nend\ngem \"rails\"\n"
        ));
        // A `;` ends the loop's statement: a later `do` opens a block.
        assert!(at(
            "source \"https://x\" do\n  while q.any?; q.each do |x|\n  end\n  end\n  gem \"rails\"\nend\n"
        ));
        // A method named like a keyword is a name (`def begin`).
        assert!(!at(
            "source \"https://x\" do\n  def begin\n    1\n  end\nend\ngem \"rails\"\n"
        ));
        // `=begin` … `=end` comments and heredoc bodies are not code.
        assert!(!at(
            "source \"https://x\" do\n=begin\nGems for the CI box\n=end\nend\ngem \"rails\"\n"
        ));
        assert!(at(
            "source \"https://x\" do\n  NOTE = <<~EOS\n    the end\n    end\n  EOS\n  gem \"rails\"\nend\n"
        ));
        assert!(at(
            "source \"https://x\" do\n  NOTE = <<-'EOS' + <<B\n  if case\n  EOS\nend\nB\n  gem \"rails\"\nend\n"
        ));
        // An append is not a heredoc.
        assert!(at(
            "source \"https://x\" do\n  list << FOO\n  end_marker = 1\n  gem \"rails\"\nend\n"
        ));
        // A multi-line `%w[` array or string is masked across lines.
        assert!(!at(
            "source \"https://x\" do\n  gem \"a\", require: %w[\n    active_support/core_ext/module\n  ]\nend\ngem \"rails\"\n"
        ));
        assert!(!at(
            "source \"https://x\" do\n  NOTE = \"if\n  case\"\nend\ngem \"rails\"\n"
        ));
        // `class <<self` and `list <<name` are no heredocs.
        assert!(at(
            "source \"https://x\" do\n  class <<self\n  end\n  list <<name\n  gem \"rails\"\nend\n"
        ));
        // A modifier on a `\`-continued line is still a modifier; after a
        // trailing `,` or `=` the keyword starts an expression.
        assert!(!at(
            "source \"https://x\" do\n  gem \"pry\" \\\n    if ENV[\"DEBUG\"]\nend\ngem \"rails\"\n"
        ));
        assert!(at(
            "source \"https://x\" do\n  gem \"pry\",\n    require: if ENV[\"D\"]\n      true\n    end\n  gem \"rails\"\nend\n"
        ));
        // The comment starts where the literals say it does.
        assert!(!at(
            "source \"https://x\" do\n  gem \"a\" if RUBY_PLATFORM =~ /x'/ # we're at the end\nend\ngem \"rails\"\n"
        ));
        assert!(at(
            "source \"https://x\", path: %q(#a) do\n  gem \"rails\"\nend\n"
        ));
        // `%s()` / `%x()` literals and operator / nested-paren endless defs.
        for line in [
            "v = %x(echo begin)",
            "sym = %s(class)",
            "def ==(other) = id == other.id",
            "def x(a = foo()) = a",
            "def self.x = 1",
        ] {
            let t = format!("source \"https://x\" do\n  {line}\nend\ngem \"rails\"\n");
            assert!(!at(&t), "{t}");
        }
        // A setter `def x=(v)` still needs its `end`.
        assert!(at(
            "source \"https://x\" do\n  def x=(v)\n  end\n  gem \"rails\"\nend\n"
        ));
        assert!(!at("if true\n  gem \"a\"\nend\ngem \"rails\"\n"));
        // A `#` inside a string (`#{}` interpolation) is no comment: the
        // trailing `do` still opens the source block.
        assert!(at(
            "source \"https://#{ENV[\"HOST\"]}/gems\" do\n  gem \"rails\"\nend\n"
        ));
        assert!(at(
            "source 'https://x/#frag' do # comment\n  gem \"rails\"\nend\n"
        ));
    }

    /// A hosted Gemfile + lock pair for `rails 7.0.0` (a direct gem), from
    /// the real forward rewrite: `checksums` picks a converged
    /// (bundler 2.6+) or a pre-CHECKSUMS (2.5) lock.
    fn hosted_pair(checksums: bool, upstream_sha: &str) -> BTreeMap<String, String> {
        let manifest = "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n";
        let lock = format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n\nPLATFORMS\n  \
             ruby\n\nDEPENDENCIES\n  rails (= 7.0.0)\n\nCHECKSUMS\n  rails (7.0.0) \
             sha256={upstream_sha}\n\nBUNDLED WITH\n   2.6.9\n"
        );
        let files = BTreeMap::from([
            ("Gemfile".to_string(), manifest.to_string()),
            ("Gemfile.lock".to_string(), lock),
        ]);
        let r = crate::patch::redirect::rewrite_registry_redirect(
            &files,
            &[crate::patch::redirect::DepOverride {
                ecosystem: "gem".into(),
                name: "rails".into(),
                namespace: None,
                version: "7.0.0".into(),
                token: "tok".into(),
                patch_uuid: UUID.into(),
                artifact_url: "https://patch.test/rails-7.0.0.gem".into(),
                registry_override: Some(crate::patch::redirect::RegistryOverride {
                    kind: "rubygems-compact-index".into(),
                    index_url: IDX.into(),
                    identifiers: crate::patch::redirect::RegistryOverrideIdentifiers {
                        name: "rails".into(),
                        version: "7.0.0".into(),
                        gem_checksum_sha256: Some("f".repeat(64)),
                        ..Default::default()
                    },
                }),
                integrity: Default::default(),
            }],
        );
        let mut out = r.files;
        let lock = out.get_mut("Gemfile.lock").expect("the lock is redirected");
        assert!(lock.contains(IDX), "{lock}");
        if !checksums {
            // Bundler 2.5 converges the same hosted lock with no CHECKSUMS.
            let start = lock.find("CHECKSUMS\n").expect("a converged lock");
            let end = start + lock[start..].find("\n\n").expect("a section end") + 2;
            lock.replace_range(start..end, "");
            assert!(!lock.contains("sha256="), "{lock}");
        }
        out
    }

    fn sha_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(bytes))
    }

    /// Restore the hosted pair from `hosted_pair` in a temp project whose
    /// `cache_rel` dir holds `rails-7.0.0.gem` (unless `archive` is None),
    /// returning the restore's warnings.
    async fn restore_with_cache(
        checksums: bool,
        client: &super::super::UpstreamClient,
        upstream_sha: &str,
        bundle_config: Option<&str>,
        cache_rel: &str,
        archive: Option<&[u8]>,
    ) -> (tempfile::TempDir, Vec<(&'static str, String)>) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for (rel, text) in hosted_pair(checksums, upstream_sha) {
            std::fs::write(root.join(rel), text).unwrap();
        }
        if let Some(config) = bundle_config {
            std::fs::create_dir_all(root.join(".bundle")).unwrap();
            std::fs::write(root.join(".bundle/config"), config).unwrap();
        }
        if let Some(bytes) = archive {
            std::fs::create_dir_all(root.join(cache_rel)).unwrap();
            std::fs::write(root.join(cache_rel).join("rails-7.0.0.gem"), bytes).unwrap();
        }
        let pin = HostedPin {
            purl: "pkg:gem/rails@7.0.0".into(),
            uuid: UUID.into(),
            files: vec!["Gemfile".into(), "Gemfile.lock".into()],
        };
        let ctx = ctx_with(client);
        let mut view = View::new(root);
        let r = restore(&mut view, &[&pin], &pin.files, &ctx).await;
        assert!(r.refused.is_empty(), "{:?}", r.refused);
        assert!(r.handled.contains(UUID));
        (tmp, r.warnings)
    }

    fn stale_cache<'w>(warnings: &'w [(&'static str, String)]) -> Vec<&'w str> {
        warnings
            .iter()
            .filter(|(code, _)| *code == STALE_CACHE)
            .map(|(_, d)| d.as_str())
            .collect()
    }

    /// #1260: `bundle cache` while the hosted pin was live left the
    /// PATCHED archive in vendor/cache. The restored CHECKSUMS pins the
    /// upstream sha, so every later install fails (exit 37) until that
    /// file goes: the unwind must name it.
    #[tokio::test]
    async fn restore_warns_about_a_patched_archive_in_vendor_cache() {
        let upstream_sha = sha_hex(b"upstream gem");
        let client = super::super::UpstreamClient::new(true);
        client
            .seed_rubygems_sha256("rails", "7.0.0", &upstream_sha)
            .await;
        let (tmp, warnings) = restore_with_cache(
            true,
            &client,
            &upstream_sha,
            None,
            "vendor/cache",
            Some(b"patched gem"),
        )
        .await;
        let hits = stale_cache(&warnings);
        assert_eq!(hits.len(), 1, "{warnings:?}");
        let path = tmp
            .path()
            .join("vendor")
            .join("cache")
            .join("rails-7.0.0.gem");
        assert!(hits[0].contains(&path.display().to_string()), "{}", hits[0]);
        assert!(hits[0].contains("pkg:gem/rails@7.0.0"), "{}", hits[0]);
        assert!(hits[0].contains("non-upstream"), "{}", hits[0]);
    }

    /// #1260: an upstream archive in the cache (cached before the hosted
    /// scan, or re-cached after) is healthy: no warning.
    #[tokio::test]
    async fn restore_keeps_quiet_about_an_upstream_archive_in_vendor_cache() {
        let upstream_sha = sha_hex(b"upstream gem");
        let client = super::super::UpstreamClient::new(true);
        client
            .seed_rubygems_sha256("rails", "7.0.0", &upstream_sha)
            .await;
        let (_tmp, warnings) = restore_with_cache(
            true,
            &client,
            &upstream_sha,
            None,
            "vendor/cache",
            Some(b"upstream gem"),
        )
        .await;
        assert!(stale_cache(&warnings).is_empty(), "{warnings:?}");
        // No archive at all: nothing to say either.
        let (_tmp, warnings) =
            restore_with_cache(true, &client, &upstream_sha, None, "vendor/cache", None).await;
        assert!(stale_cache(&warnings).is_empty(), "{warnings:?}");
    }

    /// #1260, `cache_path gems/cache`: the dir bundler reads is the
    /// configured one, so that's the archive the warning names.
    #[tokio::test]
    async fn restore_follows_the_configured_bundle_cache_path() {
        let upstream_sha = sha_hex(b"upstream gem");
        let client = super::super::UpstreamClient::new(true);
        client
            .seed_rubygems_sha256("rails", "7.0.0", &upstream_sha)
            .await;
        let (tmp, warnings) = restore_with_cache(
            true,
            &client,
            &upstream_sha,
            Some("---\nBUNDLE_CACHE_PATH: \"gems/cache\"\n"),
            "gems/cache",
            Some(b"patched gem"),
        )
        .await;
        let hits = stale_cache(&warnings);
        assert_eq!(hits.len(), 1, "{warnings:?}");
        let path = tmp
            .path()
            .join("gems")
            .join("cache")
            .join("rails-7.0.0.gem");
        assert!(hits[0].contains(&path.display().to_string()), "{}", hits[0]);
    }

    /// #1260 on bundler 2.5 (no CHECKSUMS): a frozen install takes the
    /// cached patched archive without complaint, so the rollback silently
    /// doesn't take effect. The upstream sha comes from rubygems.org; when
    /// it can't be fetched (`--offline`) the warning still names the file.
    #[tokio::test]
    async fn restore_warns_about_a_cached_archive_without_checksums() {
        let upstream_sha = sha_hex(b"upstream gem");
        let client = super::super::UpstreamClient::new(true);
        client
            .seed_rubygems_sha256("rails", "7.0.0", &upstream_sha)
            .await;
        let (_tmp, warnings) = restore_with_cache(
            false,
            &client,
            &upstream_sha,
            None,
            "vendor/cache",
            Some(b"patched gem"),
        )
        .await;
        let hits = stale_cache(&warnings);
        assert_eq!(hits.len(), 1, "{warnings:?}");
        assert!(hits[0].contains("non-upstream"), "{}", hits[0]);

        let (_tmp, warnings) = restore_with_cache(
            false,
            &client,
            &upstream_sha,
            None,
            "vendor/cache",
            Some(b"upstream gem"),
        )
        .await;
        assert!(stale_cache(&warnings).is_empty(), "{warnings:?}");

        let offline = super::super::UpstreamClient::new(true);
        let (tmp, warnings) = restore_with_cache(
            false,
            &offline,
            &upstream_sha,
            None,
            "vendor/cache",
            Some(b"patched gem"),
        )
        .await;
        let hits = stale_cache(&warnings);
        assert_eq!(hits.len(), 1, "{warnings:?}");
        let path = tmp
            .path()
            .join("vendor")
            .join("cache")
            .join("rails-7.0.0.gem");
        assert!(hits[0].contains(&path.display().to_string()), "{}", hits[0]);
        assert!(hits[0].contains("could not be checked"), "{}", hits[0]);
    }

    /// The project a vendored unwind leaves behind (#1594): the lock back on
    /// the upstream `GEM` entry, `checksum` its `CHECKSUMS` sha (none for a
    /// pre-2.6 lock), and `archive` in `vendor/cache`.
    fn unwound_project(
        remote: &str,
        checksum: Option<&str>,
        archive: Option<&[u8]>,
    ) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let checksums = checksum
            .map(|sha| format!("CHECKSUMS\n  rails (7.0.0) sha256={sha}\n\n"))
            .unwrap_or_default();
        std::fs::write(
            tmp.path().join("Gemfile.lock"),
            format!(
                "GEM\n  remote: {remote}\n  specs:\n    rails (7.0.0)\n\n\
                 PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (= 7.0.0)\n\n{checksums}\
                 BUNDLED WITH\n   2.6.9\n"
            ),
        )
        .unwrap();
        if let Some(bytes) = archive {
            std::fs::create_dir_all(tmp.path().join("vendor/cache")).unwrap();
            std::fs::write(tmp.path().join("vendor/cache/rails-7.0.0.gem"), bytes).unwrap();
        }
        tmp
    }

    /// #1594: a hosted → vendored takeover keeps the patched archive a
    /// `bundle cache` took while the hosted pin was live, and the vendored
    /// unwind puts the lock back on upstream: name the archive, exactly as
    /// the hosted unwind does.
    #[tokio::test]
    async fn vendored_unwind_names_a_patched_archive_in_vendor_cache() {
        let upstream_sha = sha_hex(b"upstream gem");
        let tmp = unwound_project(
            "https://rubygems.org/",
            Some(&upstream_sha),
            Some(b"patched gem"),
        );
        let (code, detail) = unwound_stale_cache(tmp.path(), "pkg:gem/rails@7.0.0", true)
            .await
            .expect("the patched archive is named");
        assert_eq!(code, STALE_CACHE);
        let path = tmp
            .path()
            .join("vendor")
            .join("cache")
            .join("rails-7.0.0.gem");
        assert!(detail.contains(&path.display().to_string()), "{detail}");
        assert!(detail.contains("pkg:gem/rails@7.0.0"), "{detail}");
        assert!(detail.contains("non-upstream"), "{detail}");
    }

    /// #1594: an upstream archive, or none at all, is healthy.
    #[tokio::test]
    async fn vendored_unwind_keeps_quiet_about_an_upstream_or_missing_archive() {
        let upstream_sha = sha_hex(b"upstream gem");
        let tmp = unwound_project(
            "https://rubygems.org/",
            Some(&upstream_sha),
            Some(b"upstream gem"),
        );
        let hit = unwound_stale_cache(tmp.path(), "pkg:gem/rails@7.0.0", true).await;
        assert_eq!(hit, None);
        let tmp = unwound_project("https://rubygems.org/", Some(&upstream_sha), None);
        let hit = unwound_stale_cache(tmp.path(), "pkg:gem/rails@7.0.0", true).await;
        assert_eq!(hit, None);
    }

    /// #1594 on a lock without `CHECKSUMS`: offline, the upstream sha can't
    /// be fetched, so the archive is named as unchecked rather than passed.
    #[tokio::test]
    async fn vendored_unwind_names_an_unchecked_archive_offline() {
        let tmp = unwound_project("https://rubygems.org/", None, Some(b"patched gem"));
        let (code, detail) = unwound_stale_cache(tmp.path(), "pkg:gem/rails@7.0.0", true)
            .await
            .expect("the unchecked archive is named");
        assert_eq!(code, STALE_CACHE);
        assert!(detail.contains("could not be checked"), "{detail}");
    }

    /// #1594: a FIFO at the lock path is skipped, never opened for reading
    /// (which would block): the check goes on without a lock.
    #[cfg(unix)]
    #[tokio::test]
    async fn vendored_unwind_skips_a_fifo_lock() {
        let tmp = unwound_project("https://rubygems.org/", None, Some(b"patched gem"));
        let lock = tmp.path().join("Gemfile.lock");
        std::fs::remove_file(&lock).unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(&lock)
            .status()
            .unwrap();
        assert!(status.success());
        let hit = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            unwound_stale_cache(tmp.path(), "pkg:gem/rails@7.0.0", true),
        )
        .await
        .expect("a FIFO lock must not block the check");
        assert!(hit.is_some_and(|(_, d)| d.contains("could not be checked")));
    }

    /// #1594: a gem locked from a private remote with no `CHECKSUMS` sha
    /// can't be checked against rubygems.org (it isn't from there), and a
    /// committed cache of private gems is normal: no warning.
    #[tokio::test]
    async fn vendored_unwind_skips_an_unchecked_private_gem() {
        let tmp = unwound_project("https://gems.example.com/", None, Some(b"private gem"));
        let hit = unwound_stale_cache(tmp.path(), "pkg:gem/rails@7.0.0", true).await;
        assert_eq!(hit, None);
        // A CHECKSUMS sha still judges it, whatever the remote.
        let upstream_sha = sha_hex(b"upstream gem");
        let tmp = unwound_project(
            "https://gems.example.com/",
            Some(&upstream_sha),
            Some(b"patched gem"),
        );
        let hit = unwound_stale_cache(tmp.path(), "pkg:gem/rails@7.0.0", true).await;
        assert!(hit.is_some_and(|(_, d)| d.contains("non-upstream")));
    }

    /// A gem restored in both a `Gemfile` and a `gems.rb` pair shares one
    /// cache dir: one warning, not one per pair.
    #[tokio::test]
    async fn restore_warns_once_for_both_lock_spellings() {
        let upstream_sha = sha_hex(b"upstream gem");
        let client = super::super::UpstreamClient::new(true);
        client
            .seed_rubygems_sha256("rails", "7.0.0", &upstream_sha)
            .await;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let pair = hosted_pair(true, &upstream_sha);
        std::fs::write(root.join("Gemfile"), &pair["Gemfile"]).unwrap();
        std::fs::write(root.join("Gemfile.lock"), &pair["Gemfile.lock"]).unwrap();
        std::fs::write(root.join("gems.rb"), &pair["Gemfile"]).unwrap();
        std::fs::write(root.join("gems.locked"), &pair["Gemfile.lock"]).unwrap();
        std::fs::create_dir_all(root.join("vendor/cache")).unwrap();
        std::fs::write(root.join("vendor/cache/rails-7.0.0.gem"), b"patched gem").unwrap();
        let pin = HostedPin {
            purl: "pkg:gem/rails@7.0.0".into(),
            uuid: UUID.into(),
            files: vec![
                "Gemfile".into(),
                "Gemfile.lock".into(),
                "gems.locked".into(),
                "gems.rb".into(),
            ],
        };
        let ctx = ctx_with(&client);
        let mut view = View::new(root);
        let r = restore(&mut view, &[&pin], &pin.files, &ctx).await;
        assert!(r.refused.is_empty(), "{:?}", r.refused);
        assert_eq!(stale_cache(&r.warnings).len(), 1, "{:?}", r.warnings);
    }

    /// #1626: a superseding hosted re-scan on a lock with no CHECKSUMS
    /// moves only the Gemfile block to the new uuid; the lock still pins
    /// the old one until a `bundle install`. Restoring the lock's pin must
    /// undo that block too, or the next unfrozen install re-patches.
    #[tokio::test]
    async fn restore_undoes_a_superseding_patch_block() {
        const NEW: &str = "88888888-8888-8888-8888-888888888888";
        let client = super::super::UpstreamClient::new(true);
        let ctx = ctx_with(&client);
        let upstream = hosted_pair(false, &"a".repeat(64));
        let run = |pins: Vec<HostedPin>, gemfile: String| {
            let lock = upstream["Gemfile.lock"].clone();
            let ctx = &ctx;
            async move {
                let tmp = tempfile::tempdir().unwrap();
                std::fs::write(tmp.path().join("Gemfile"), &gemfile).unwrap();
                std::fs::write(tmp.path().join("Gemfile.lock"), &lock).unwrap();
                let mut view = View::new(tmp.path());
                let refs: Vec<&HostedPin> = pins.iter().collect();
                let files = vec!["Gemfile".to_string(), "Gemfile.lock".to_string()];
                let r = restore(&mut view, &refs, &files, ctx).await;
                let changed = view.changed();
                (
                    r,
                    changed.get("Gemfile").cloned().flatten(),
                    changed.get("Gemfile.lock").cloned().flatten(),
                )
            }
        };
        let pin = |uuid: &str, files: &[&str]| HostedPin {
            purl: "pkg:gem/rails@7.0.0".into(),
            uuid: uuid.into(),
            files: files.iter().map(|f| f.to_string()).collect(),
        };
        let superseded = upstream["Gemfile"].replace(UUID, NEW);
        assert!(superseded.contains(NEW), "{superseded}");
        let want = "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n";

        // Only the lock's (old) pin is discovered.
        let (r, gemfile, lock) = run(vec![pin(UUID, &["Gemfile.lock"])], superseded.clone()).await;
        assert!(r.refused.is_empty(), "{:?}", r.refused);
        assert!(r.handled.contains(UUID));
        assert_eq!(gemfile.as_deref(), Some(want));
        let lock = lock.expect("the lock is restored");
        assert!(
            !lock.contains(IDX) && !lock.contains("patch-registry"),
            "{lock}"
        );

        // Both pins in one run, in either order: the lock's pin undoes the
        // block, and neither is refused.
        for pins in [
            vec![pin(UUID, &["Gemfile.lock"]), pin(NEW, &["Gemfile"])],
            vec![pin(NEW, &["Gemfile"]), pin(UUID, &["Gemfile.lock"])],
        ] {
            let (r, gemfile, lock) = run(pins, superseded.clone()).await;
            assert!(r.refused.is_empty(), "{:?}", r.refused);
            assert!(r.handled.contains(UUID) && r.handled.contains(NEW));
            assert_eq!(gemfile.as_deref(), Some(want));
            assert!(!lock.unwrap().contains("patch-registry"));
        }

        // The superseding pin alone can't restore the pair: undoing its
        // block would leave the lock on the earlier patch.
        let (r, gemfile, lock) = run(vec![pin(NEW, &["Gemfile"])], superseded.clone()).await;
        let why = r.refused.get(NEW).expect("refused");
        assert!(why.contains(UUID), "{why}");
        assert_eq!((gemfile, lock), (None, None));

        // Two superseding blocks for the same gem: not ours to pick.
        let other = upstream["Gemfile"].replace(UUID, "99999999-9999-9999-9999-999999999999");
        let block = &other[other.find("source \"https://patch").unwrap()..];
        let (r, _, _) = run(
            vec![pin(UUID, &["Gemfile.lock"])],
            format!("{superseded}{block}"),
        )
        .await;
        assert!(r.refused.contains_key(UUID), "{:?}", r.handled);
    }

    /// #1626: only a Socket section of its own pins the gem to an earlier
    /// patch; another gem's Socket remote in a merged (bundler < 2.2)
    /// section must not refuse this gem's restore.
    #[test]
    fn earlier_lock_pin_needs_a_section_of_its_own() {
        const OTHER: &str = "https://patch.socket.dev/patch-registry/gem/11111111-1111-1111-1111-111111111111/99999999-9999-9999-9999-999999999999/";
        let client = super::super::UpstreamClient::new(true);
        let ctx = ctx_with(&client);
        let own = format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n\nGEM\n  remote: {OTHER}\n  \
             specs:\n    rails (7.0.0)\n\nDEPENDENCIES\n  rails (= 7.0.0)!\n"
        );
        let lines: Vec<&str> = own.split('\n').collect();
        assert_eq!(
            earlier_lock_pin(&lines, &gem(), &ctx).as_deref(),
            Some("99999999-9999-9999-9999-999999999999")
        );
        let merged = format!(
            "GEM\n  remote: https://rubygems.org/\n  remote: {OTHER}\n  specs:\n    puma \
             (6.0.0)\n    rails (7.0.0)\n\nDEPENDENCIES\n  puma!\n  rails (= 7.0.0)\n"
        );
        let lines: Vec<&str> = merged.split('\n').collect();
        assert_eq!(earlier_lock_pin(&lines, &gem(), &ctx), None);
    }

    #[test]
    fn global_sources_skip_blocks() {
        let m = format!("source 'https://rubygems.org'\nsource(\"https://b.example\")\nsource \"{IDX}\" do\nend\n");
        assert_eq!(
            global_sources(&m),
            vec![
                "https://rubygems.org".to_string(),
                "https://b.example".to_string()
            ]
        );
    }
}
