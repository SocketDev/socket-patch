//! RubyGems upstream restore: a hosted gem goes back to the upstream `GEM`
//! section of `Gemfile.lock` / `gems.locked`, and the Socket source the
//! hosted rewriter (`rewrite_gem`) gave it in `Gemfile` / `gems.rb` is taken
//! off. Discovery records only the lock; the manifest is its bundler sibling
//! ([`bundler_manifest_for`]).
//!
//! The manifest wires a hosted gem in one of three ways ([`Wired`]):
//!
//! * a `source: "<patch registry>"` option appended to the user's own
//!   declaration. The option (and the comma before it) is removed; nothing
//!   else of the declaration was ever touched, so the line is back byte for
//!   byte;
//! * a line the rewriter added for a gem the manifest did not declare (a
//!   transitive dependency), marked with
//!   [`ADDED_LINE_MARKER`](crate::formats::gem::declarations::ADDED_LINE_MARKER).
//!   The line goes, with the blank line written before it, and the
//!   `DEPENDENCIES` entry added for it;
//! * the `source "<patch registry>" do … end` block socket-patch 5.0 / 5.1
//!   put in the declaration's place. See "The block form" below.
//!
//! The lock states a hosted gem can be in, and what each restore does:
//!
//! * **Converged** (bundler ≥ 2.2): the gem's spec (+ its dependency
//!   sub-lines) sits in a `GEM` section of its own whose single remote is
//!   the patch registry. The section is deleted and the spec moves back, in
//!   name order, into the upstream `GEM` section: the one remaining
//!   non-Socket single-remote section, or — when there are several — the
//!   one naming the manifest's global `source`, else the rubygems.org one;
//!   anything else is ambiguous and refused.
//! * **Merged** (bundler ≤ 2.1 writes every rubygems source into ONE `GEM`
//!   section): the Socket `remote:` line is dropped from it.
//! * **Mixed** (a block of 5.0 / 5.1 on a bundler < 2.6 lock those releases
//!   left alone, which still records the upstream source; see
//!   `redirect_gem_frozen_install`): discovery finds no pin for it (no lock
//!   wiring), so it is only unwound when a caller hands in a pin for it —
//!   the manifest block alone is then undone, and the untouched lock says
//!   exactly how the gem was declared.
//!
//! In every state a `CHECKSUMS` entry is re-pinned to the upstream sha256
//! from the rubygems.org compact index (`info/<name>`, what bundler itself
//! records; other upstream remotes are refused: their index may need
//! credentials and is not the default registry), and the `DEPENDENCIES`
//! source pin (`name (…)!`) loses its `!` — unless the declaration sits
//! inside the user's own `source … do` block, where bundler writes the `!`
//! itself ([`in_source_block`], #1056). A `CHECKSUMS` entry the rewriter
//! ADDED is only recognizable next to bundler's own bare entry for the gem
//! (then it is dropped); otherwise it is re-pinned in place.
//!
//! ## The block form
//!
//! What that rewrite discarded is NOT derivable, so the restore picks the
//! installable reading and says so ([`DECLARATION_PINNED`]):
//!
//! * the original declaration's version constraint (`"~> 7.0"`, or none),
//!   quote style, parenthesized form and comment: the gem comes back as
//!   `gem "<name>", "<version>"[, <options>]` — the exact pin the lock
//!   records as `name (= version)`, so the pair stays frozen-installable
//!   (the mixed state keeps the lock's own constraint instead);
//! * the blank lines and indentation the rewriter's `^\s*gem` match
//!   swallowed before the declaration: see [`declaration_prefix`];
//! * whether the gem was declared at all. That rewriter APPENDED a block for
//!   a transitive gem and added its `DEPENDENCIES` entry, but a direct gem
//!   on the manifest's last line produced the same bytes. The block and
//!   entry are removed only when that is provable: an option-less block the
//!   rewriter could not have written in place (a blank line before it —
//!   the in-place match swallowed every blank line before the declaration,
//!   and the append always wrote one; it goes with the block) that
//!   another locked spec depends on (a spec sub-line, or a Bundler 4.1
//!   `OVERRIDES` `with:` target, #1989). Otherwise the gem is kept as a
//!   direct pin: a stray exact pin installs the same bytes, while dropping
//!   a real declaration would stop `Bundler.require` loading the gem.

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;

use super::{Ctx, FormatResult, HostedPin, UpstreamClient, View};
use crate::formats::gem::declarations::{self, Declaration};
use crate::formats::gem::ruby::{block_stack, BlockSource};
use crate::formats::gem::{
    bundler_manifest_for, parse_spec, same_remote, split_checksum_entry, BUNDLER_LOCKS,
};
use crate::utils::line_endings::{self, to_lf, LineEndings};
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

/// Whether another locked spec depends on `name`: a 6-space sub-line, or
/// the `with:` target of a Bundler 4.1 `OVERRIDES` entry (#1989). An
/// `override "other", with: "name", in: "parent"` keeps `parent`'s
/// original edge to `other` in the specs, so no sub-line names `name`.
fn is_subdependency(lines: &[&str], name: &str) -> bool {
    lines
        .iter()
        .any(|l| indented(l, 6).is_some_and(|d| d.split([' ', '(']).next() == Some(name)))
        || override_targets(lines).any(|t| t == name)
}

/// The `with:` values of the lock's `OVERRIDES` entries
/// (`  "other", with: "name", in: "parent"`).
fn override_targets<'l>(lines: &'l [&'l str]) -> impl Iterator<Item = &'l str> + 'l {
    let range = named_section(lines, "OVERRIDES").unwrap_or((0, 0));
    lines[range.0..range.1].iter().filter_map(|l| {
        let entry = indented(l, 2)?.trim_end();
        // Bundler writes `"<target>", with: "<gem>", in: "<parent>"`
        // (`Override#to_lock`: `inspect`ed values joined by `, `). A
        // `version:` value may itself hold `, `, so splitting on it can
        // break that value apart, but never the `with:` one: a gem name
        // holds no `"`, `,` or space.
        entry.split(", ").find_map(|arg| {
            arg.strip_prefix("with: \"")?
                .strip_suffix('"')
                .filter(|v| !v.contains('"'))
        })
    })
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

/// The `source "<index>" do\n  gem "n", "v"[, opts]\nend` block that
/// socket-patch 5.0 / 5.1 wrote.
struct Block {
    start: usize,
    /// Past the `end` line's line break.
    end: usize,
    opts: Option<String>,
    /// Whether a line break followed `end` (the declaration's own).
    eol: bool,
}

/// How the manifest gives the gem its Socket source (module docs).
enum Wired {
    /// A `source:` option on the gem's own declaration.
    Option(Declaration),
    /// The line the rewriter added for a gem the manifest did not declare.
    AddedLine(Declaration),
    /// The block of socket-patch 5.0 / 5.1.
    Block(Block),
}

impl Wired {
    /// The byte range that holds the wiring's Socket URL: the `source:`
    /// argument, or the whole block.
    fn span(&self) -> (usize, usize) {
        match self {
            Wired::Option(decl) | Wired::AddedLine(decl) => decl
                .source()
                .map_or((decl.start, decl.end), |(arg, _)| (arg.start, arg.end)),
            Wired::Block(block) => (block.start, block.end),
        }
    }

    /// Whether `text` names `uuid` anywhere but in this wiring.
    fn mentioned_outside(&self, text: &str, uuid: &str) -> bool {
        let (start, end) = self.span();
        text[..start].contains(uuid) || text[end..].contains(uuid)
    }
}

/// Every wiring of `gem` to a hosted patch the manifest holds, with the
/// patch uuid its URL names: a `source:` option on a declaration of the
/// gem's name, and a 5.0 / 5.1 block for its name and version.
fn socket_wirings(text: &str, gem: &Gem<'_>, ctx: &Ctx<'_>) -> Vec<(Wired, String)> {
    let mut out: Vec<(Wired, String)> = socket_blocks(text, gem, ctx)
        .into_iter()
        .map(|(block, uuid)| (Wired::Block(block), uuid))
        .collect();
    for decl in declarations::declarations(text).literal {
        if decl.name != gem.name {
            continue;
        }
        let Some(uuid) = decl
            .source()
            .and_then(|(_, url)| url)
            .and_then(|url| ctx.hosted_uuid(url))
        else {
            continue;
        };
        let wired = if declarations::is_added_line(text, &decl) {
            Wired::AddedLine(decl)
        } else {
            Wired::Option(decl)
        };
        out.push((wired, uuid));
    }
    out
}

fn find_wiring(
    text: &str,
    gem: &Gem<'_>,
    rel: &str,
    ctx: &Ctx<'_>,
) -> Result<Option<Wired>, String> {
    let mut hits: Vec<Wired> = socket_wirings(text, gem, ctx)
        .into_iter()
        .filter(|(_, uuid)| uuid == gem.uuid)
        .map(|(wired, _)| wired)
        .collect();
    match hits.len() {
        0 if text.contains(gem.uuid) => Err(format!(
            "{rel} wires it in a shape other than the `source:` option or the source block \
             socket-patch writes"
        )),
        0 => Ok(None),
        1 if hits[0].mentioned_outside(text, gem.uuid) => Err(format!(
            "{rel} names the patch outside the `source:` option or the source block \
             socket-patch writes"
        )),
        1 => Ok(hits.pop()),
        _ => Err(format!("{rel} gives it the patch's source more than once")),
    }
}

/// Every `source "<patch registry>" do` block of the shape 5.0 / 5.1 wrote
/// for `gem`'s name and version, with the hosted patch uuid its index names.
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

/// The wiring another patch of the same gem left in the manifest while the
/// lock still pins `gem`'s uuid (#1626): a superseding hosted re-scan by
/// socket-patch 5.0 / 5.1 on a lock with no `CHECKSUMS` section moved only
/// the manifest's block to the new patch's uuid, and a hand-merged pair can
/// disagree the same way. Restoring the lock alone would leave that wiring
/// behind, and the next unfrozen install would re-patch. Returns the wiring
/// and the superseding patch's uuid.
fn superseded_wiring(
    text: &str,
    gem: &Gem<'_>,
    rel: &str,
    ctx: &Ctx<'_>,
) -> Result<Option<(Wired, String)>, String> {
    let mut hits: Vec<(Wired, String)> = socket_wirings(text, gem, ctx)
        .into_iter()
        .filter(|(_, uuid)| uuid != gem.uuid)
        .collect();
    match hits.len() {
        0 => Ok(None),
        1 if hits[0].0.mentioned_outside(text, &hits[0].1) => Err(format!(
            "{rel} names the superseding patch {} outside the `source:` option or the source \
             block socket-patch writes",
            hits[0].1
        )),
        1 => Ok(hits.pop()),
        _ => Err(format!(
            "{rel} gives it the source of several superseding patches"
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
    block_stack(text, at)
        .iter()
        .any(|f| f.source == Some(BlockSource::Source))
}

/// How a gem wired by a 5.0 / 5.1 block comes back into the manifest.
enum Decl {
    /// Gone: the block was the rewriter's append for a transitive gem.
    Transitive,
    /// `gem "<name>"<args>[, <opts>]`; `args` is the version constraint list
    /// (`, "7.0.0"`).
    Direct(String),
}

/// The manifest without the wiring `wired`: the `source:` option off the
/// declaration, the added line gone, or the block undone as `decl` says.
fn unwire_manifest(text: &str, wired: &Wired, gem: &Gem<'_>, decl: &Decl) -> String {
    match wired {
        Wired::Option(declaration) => match declaration.source() {
            Some((arg, _)) => declarations::without_arg(text, arg),
            None => text.to_string(),
        },
        Wired::AddedLine(declaration) => declarations::without_added_line(text, declaration),
        Wired::Block(block) => restore_manifest(text, block, gem, decl),
    }
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
    // The restored line takes the block's ending: the rewriter writes it in
    // the ending of the line it replaced (#1831). A block in LF, the only
    // spelling before #1831, takes the ending of the lines around it.
    let eol = if text[block.start..block.end].contains("\r\n") {
        "\r\n"
    } else {
        line_endings::terminator(&format!("{}{}", &text[..block.start], &text[block.end..]))
    };
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
        // The declarations that came back as exact pins (module docs, "The
        // block form").
        let mut pinned: Vec<String> = Vec::new();
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
                Ok(Some(restored)) => {
                    if endings == Some(LineEndings::Mixed) && restored.lock != lock {
                        result.refuse(
                            &pin.uuid,
                            format!("{lock_rel} mixes CRLF and LF line endings"),
                        );
                        continue;
                    }
                    lock = restored.lock;
                    manifest = restored.manifest;
                    result.handled.insert(pin.uuid.clone());
                    undone.extend(restored.superseded);
                    if restored.pinned {
                        pinned.push(format!("`gem \"{}\", \"{}\"`", gem.name, gem.version));
                    }
                }
                Err(why) => result.refuse(&pin.uuid, why),
            }
        }
        if !pinned.is_empty() {
            let (was, each) = if pinned.len() == 1 {
                ("was restored as an exact pin", "the declaration")
            } else {
                ("were restored as exact pins", "each declaration")
            };
            result.warnings.push((
                DECLARATION_PINNED,
                format!(
                    "{manifest_rel}: {} {was}. socket-patch 5.0 / 5.1 replaced {each} with a \
                     `source … do` block, so the original version requirement, quoting and \
                     comment could not be recovered; if the requirement was a range (for \
                     example `~> 2.2`), put it back by hand and run `bundle lock`",
                    pinned.join(", ")
                ),
            ));
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

/// The warning code for declarations a restore brought back as exact pins:
/// a `source … do` block of socket-patch 5.0 / 5.1 does not hold the
/// declaration it replaced (module docs, "The block form").
pub(crate) const DECLARATION_PINNED: &str = "upstream_gem_declaration_pinned";

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
/// it, else the next texts ([`Restored`]).
async fn restore_one(
    gem: &Gem<'_>,
    lock: Option<&str>,
    manifest: Option<&str>,
    manifest_rel: &str,
    globals: &[String],
    ctx: &Ctx<'_>,
) -> Result<Option<Restored>, String> {
    let mut wiring_in_manifest = match manifest {
        Some(text) => find_wiring(text, gem, manifest_rel, ctx)?,
        None => None,
    };
    let lines: Vec<&str> = lock.map(|l| l.split('\n').collect()).unwrap_or_default();
    let wired = match lock {
        Some(_) => wiring(&gem_sections(&lines), gem.uuid, ctx)?.is_some(),
        None => false,
    };
    let mut superseded = None;
    if wired && wiring_in_manifest.is_none() {
        if let Some((other, uuid)) = manifest
            .map(|text| superseded_wiring(text, gem, manifest_rel, ctx))
            .transpose()?
            .flatten()
        {
            wiring_in_manifest = Some(other);
            superseded = Some(uuid);
        }
    }
    if !wired && wiring_in_manifest.is_none() {
        return Ok(None);
    }
    // The other side of #1626: the manifest's wiring is this (superseding)
    // patch's, but the lock still pins the gem to an earlier Socket patch.
    // Undoing the manifest alone would leave the lock on that patch, so only
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
    let block = match &wiring_in_manifest {
        Some(Wired::Block(block)) => Some(block),
        _ => None,
    };
    // What a 5.0 / 5.1 block comes back as (module docs, "The block form").
    let decl = if wired {
        let transitive = block.is_some_and(|b| {
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
    // The declaration is (or goes back) where the wiring is: a user
    // `source … do` block around it keeps the `!` bundler wrote for it.
    let line_start = |text: &str, at: usize| text[..at].rfind('\n').map_or(0, |i| i + 1);
    let dep = match (&wiring_in_manifest, manifest) {
        // The line and its DEPENDENCIES entry are the rewriter's own.
        (Some(Wired::AddedLine(_)), _) => DepEntry::Drop,
        (Some(Wired::Option(declaration)), Some(text))
            if in_source_block(text, line_start(text, declaration.start)) =>
        {
            DepEntry::Keep
        }
        (Some(Wired::Option(_)), _) => DepEntry::Unpin,
        (Some(Wired::Block(b)), Some(text))
            if matches!(decl, Decl::Direct(_)) && in_source_block(text, b.start) =>
        {
            DepEntry::Keep
        }
        _ if matches!(decl, Decl::Transitive) => DepEntry::Drop,
        _ => DepEntry::Unpin,
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
    let next_manifest = match (manifest, &wiring_in_manifest) {
        (Some(text), Some(wiring)) => Some(unwire_manifest(text, wiring, gem, &decl)),
        _ => manifest.map(str::to_string),
    };
    Ok(Some(Restored {
        lock: next_lock,
        manifest: next_manifest,
        superseded,
        // The lock's exact pin stood in for a declaration the block replaced.
        pinned: wired && block.is_some() && matches!(decl, Decl::Direct(_)),
    }))
}

/// What [`restore_one`] gives back.
struct Restored {
    /// The next lock and manifest texts.
    lock: Option<String>,
    manifest: Option<String>,
    /// The superseding patch whose manifest wiring was undone with this
    /// gem's ([`superseded_wiring`]).
    superseded: Option<String>,
    /// Whether a 5.0 / 5.1 block came back as an exact pin
    /// ([`DECLARATION_PINNED`]).
    pinned: bool,
}

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

    /// The 5.0 / 5.1 block that wires `gem`, as [`find_wiring`] reads it.
    fn find_block(
        text: &str,
        gem: &Gem<'_>,
        rel: &str,
        ctx: &Ctx<'_>,
    ) -> Result<Option<Block>, String> {
        Ok(match find_wiring(text, gem, rel, ctx)? {
            Some(Wired::Block(block)) => Some(block),
            Some(_) => panic!("{text}: wired by an option, not a block"),
            None => None,
        })
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
        // CRLF manifest, its block in LF (written before #1831).
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

    /// #1989: Bundler 4.1's `override "other", with: "rails", in: "puma"`
    /// keeps `puma`'s original edge to `other` in the specs and records
    /// the replacement only in `OVERRIDES`, so its `with:` target is a
    /// dependency of another spec although no sub-line names it.
    #[test]
    fn an_overrides_with_target_is_a_subdependency() {
        let lock = |overrides: &str| {
            format!(
                "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.0.0)\n      \
                 other (>= 1)\n    rails (7.0.0)\n\nDEPENDENCIES\n  puma\n\nOVERRIDES\n\
                 {overrides}\nBUNDLED WITH\n   4.1.0.beta3\n"
            )
        };
        let has = |overrides: &str| {
            let text = lock(overrides);
            let lines: Vec<&str> = text.split('\n').collect();
            is_subdependency(&lines, "rails")
        };
        assert!(has("  \"other\", with: \"rails\", in: \"puma\"\n"));
        assert!(has("  \"other\", in: \"puma\", with: \"rails\"\n"));
        // A replacement version requirement, as Bundler 4.1 locks it.
        assert!(has(
            "  \"other\", with: \"rails\", in: \"puma\", version: \">= 7, < 8\"\n"
        ));
        assert!(has(
            "  \"x\", with: \"y\", in: \"z\"\n  \"other\", with: \"rails\", in: \"puma\"\n"
        ));
        // `rails` as the overridden name, the parent, or a prefix is not
        // a `with:` target.
        assert!(!has("  \"rails\", with: \"other\", in: \"puma\"\n"));
        assert!(!has("  \"other\", with: \"x\", in: \"rails\"\n"));
        assert!(!has("  \"other\", with: \"rails-html\", in: \"puma\"\n"));
        // `with: nil` drops the dependency: no target.
        assert!(!has("  \"rails\", with: nil, in: \"puma\"\n"));
        assert!(!has(""));
        // A `with:` entry outside the OVERRIDES section is not read.
        let lines = ["DEPENDENCIES", "  \"other\", with: \"rails\", in: \"puma\""];
        assert!(!is_subdependency(&lines, "rails"));
    }

    /// The hosted override for `rails 7.0.0` under patch [`UUID`].
    fn rails_override() -> crate::patch::redirect::DepOverride {
        use crate::patch::redirect::{
            DepOverride, Integrity, RegistryOverride, RegistryOverrideIdentifiers,
        };
        DepOverride {
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
        }
    }

    /// The pair socket-patch 5.0 / 5.1 left for a `gem "rails", "7.0.0"`
    /// declaration of `manifest`: its `source … do` block in the
    /// declaration's place (the blank lines and indent before the line
    /// swallowed, as that rewriter's `^\s*gem` match did), and `lock`
    /// converged on it with the patched checksum.
    fn block_form_pair(manifest: &str, lock: &str, upstream_sha: &str) -> (String, String) {
        use crate::formats::gem::hosted::{converge_gem_lock_source, DependencyPin};
        let decl = Regex::new(r#"(?m)^\s*gem "rails", "7.0.0"$"#).unwrap();
        assert!(decl.is_match(manifest), "{manifest}");
        let hosted_manifest = decl
            .replace(
                manifest,
                regex::NoExpand(&format!(
                    "source \"{IDX}\" do\n  gem \"rails\", \"7.0.0\"\nend"
                )),
            )
            .into_owned();
        let mut hosted_lock = lock.replace(
            &format!("rails (7.0.0) sha256={upstream_sha}"),
            &format!("rails (7.0.0) sha256={}", "f".repeat(64)),
        );
        converge_gem_lock_source(
            &mut hosted_lock,
            &rails_override(),
            IDX,
            "Gemfile.lock",
            DependencyPin::Exact("= 7.0.0"),
            &mut false,
            &mut Default::default(),
        )
        .expect("the lock converges");
        (hosted_manifest, hosted_lock)
    }

    /// #457: what the hosted rewriter itself writes for a TRANSITIVE gem
    /// (one added line, converged CHECKSUMS lock) must be recognized as its
    /// own line, and undoing it must give the manifest back byte for byte,
    /// whatever its line ending and whether it ends on one.
    #[test]
    fn rewriter_added_line_restores_byte_identically() {
        use crate::patch::redirect::{rewrite_registry_redirect, DepOverride};
        let client = super::super::UpstreamClient::new(true);
        let ctx = ctx_with(&client);
        let ov = rails_override();
        let lock = format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.0.0)\n      rails (>= 7)\n    \
             rails (7.0.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  puma\n\nCHECKSUMS\n  puma (6.0.0) \
             sha256={}\n  rails (7.0.0) sha256={}\n\nBUNDLED WITH\n   4.0.17\n",
            "a".repeat(64),
            "2".repeat(64)
        );
        let lf = "source \"https://rubygems.org\"\n\ngem \"puma\"\n";
        let crlf = lf.replace('\n', "\r\n");
        for original in [
            // The issue's shape: the manifest ends with a declaration + LF.
            lf.to_string(),
            // A trailing blank line.
            format!("{lf}\n"),
            crlf.clone(),
            // No final line break: it comes back without one.
            lf.trim_end_matches('\n').to_string(),
            crlf.trim_end_matches("\r\n").to_string(),
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
            let wired = find_wiring(gemfile, &gem(), "Gemfile", &ctx)
                .unwrap()
                .expect("the added line is found");
            assert!(
                matches!(wired, Wired::AddedLine(_)),
                "the rewriter's line must be recognized as added: {gemfile:?}"
            );
            assert_eq!(
                unwire_manifest(gemfile, &wired, &gem(), &Decl::Transitive),
                original,
                "from {gemfile:?}"
            );
        }

        // Two added lines (two patches) unwind in either order.
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
            let wired = find_wiring(&gemfile, &first, "Gemfile", &ctx)
                .unwrap()
                .unwrap();
            let half = unwire_manifest(&gemfile, &wired, &first, &Decl::Transitive);
            let wired = find_wiring(&half, &second, "Gemfile", &ctx)
                .unwrap()
                .unwrap();
            assert_eq!(
                unwire_manifest(&half, &wired, &second, &Decl::Transitive),
                lf
            );
        }
    }

    /// B2 / RE-D5: a hosted pin of a DIRECT gem unwinds to the pre-scan
    /// pair byte for byte, in every form the declaration is written in:
    /// the appended option goes, and the lock's entry keeps the requirement
    /// the user wrote (`rails (~> 7.0)`, not an exact pin). LF and CRLF.
    #[tokio::test]
    async fn direct_redirect_round_trips_through_restore_in_every_declaration_form() {
        let client = super::super::UpstreamClient::new(true);
        let upstream_sha = "2".repeat(64);
        client
            .seed_rubygems_sha256("rails", "7.0.0", &upstream_sha)
            .await;
        let ctx = ctx_with(&client);
        for (decl, entry) in [
            (
                "gem \"rails\", \"~> 7.0\"       # the framework",
                "rails (~> 7.0)",
            ),
            ("gem 'rails'", "rails"),
            (
                "gem 'rails', '>= 7.0.0', '< 7.1', group: :test",
                "rails (>= 7.0.0, < 7.1)",
            ),
            ("gem(\"rails\", \"7.0.0\")", "rails (= 7.0.0)"),
            (
                "gem \"rails\",\n    \"7.0.0\",\n    require: false",
                "rails (= 7.0.0)",
            ),
            (
                "gem \"rails\", platforms: %i[mri windows], require: %w[rails rails/all]",
                "rails",
            ),
            (
                "group :development do\n  gem \"rails\", \"7.0.0\" # pinned\nend",
                "rails (= 7.0.0)",
            ),
            (
                "gem \"rails\", \"7.0.0\" if RUBY_VERSION >= \"3.0\"",
                "rails (= 7.0.0)",
            ),
            ("gem \"rails\", \"7.0.0\"; gem \"puma\"", "rails (= 7.0.0)"),
        ] {
            for eol in ["\n", "\r\n"] {
                for checksums in [true, false] {
                    let manifest =
                        format!("source \"https://rubygems.org\"\n\n{decl}\ngem \"rack\"\n")
                            .replace('\n', eol);
                    let pins = if checksums {
                        format!(
                            "CHECKSUMS\n  puma (6.0.0) sha256={a}\n  rack (3.0.0) sha256={a}\n  \
                             rails (7.0.0) sha256={upstream_sha}\n\n",
                            a = "a".repeat(64)
                        )
                    } else {
                        String::new()
                    };
                    let lock = format!(
                        "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.0.0)\n    \
                         rack (3.0.0)\n    rails (7.0.0)\n      rack (>= 2)\n\nPLATFORMS\n  ruby\n\n\
                         DEPENDENCIES\n  puma\n  rack\n  {entry}\n\n{pins}BUNDLED WITH\n   4.0.17\n"
                    )
                    .replace('\n', eol);
                    let files = BTreeMap::from([
                        ("Gemfile".to_string(), manifest.clone()),
                        ("Gemfile.lock".to_string(), lock.clone()),
                    ]);
                    let r = crate::patch::redirect::rewrite_registry_redirect(
                        &files,
                        &[rails_override()],
                    );
                    let hosted_manifest = r
                        .files
                        .get("Gemfile")
                        .unwrap_or_else(|| panic!("{decl}: {:?}", r.warnings));
                    let hosted_lock = &r.files["Gemfile.lock"];
                    assert!(
                        hosted_lock.contains(&format!("  {entry}!{eol}")),
                        "{hosted_lock}"
                    );
                    // The restore edits the lock in LF, as `restore` hands it in.
                    let restored = restore_one(
                        &gem(),
                        Some(&hosted_lock.replace("\r\n", "\n")),
                        Some(hosted_manifest),
                        "Gemfile",
                        &global_sources(hosted_manifest),
                        &ctx,
                    )
                    .await
                    .unwrap()
                    .expect("the redirect is found");
                    assert_eq!(
                        restored.manifest.as_deref(),
                        Some(manifest.as_str()),
                        "{decl}"
                    );
                    assert_eq!(
                        restored.lock.map(|l| l.replace('\n', eol)).as_deref(),
                        Some(lock.as_str()),
                        "{decl} (checksums: {checksums})"
                    );
                    assert!(
                        !restored.pinned,
                        "{decl}: nothing was lost, nothing to report"
                    );
                }
            }
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
        let Restored {
            lock: next_lock,
            manifest: next_manifest,
            ..
        } = restore_one(
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

    /// #1989: a gem reached only through a Bundler 4.1 `override …, with:`
    /// is transitive too. The lock keeps the parent's original edge, so no
    /// spec sub-line names it; the restore must still drop the appended
    /// block and its DEPENDENCIES entry, not write a new exact pin.
    #[tokio::test]
    async fn override_target_redirect_round_trips_through_restore() {
        let client = super::super::UpstreamClient::new(true);
        let upstream_sha = "2".repeat(64);
        client
            .seed_rubygems_sha256("rails", "7.0.0", &upstream_sha)
            .await;
        let ctx = ctx_with(&client);
        let manifest = "source \"https://rubygems.org\"\n\ngem \"puma\"\n\n\
                        override \"other\", with: \"rails\", in: \"puma\"\n";
        let lock = format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.0.0)\n      other\n    \
             rails (7.0.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  puma\n\nOVERRIDES\n  \
             \"other\", with: \"rails\", in: \"puma\"\n\nCHECKSUMS\n  puma (6.0.0) sha256={}\n  \
             rails (7.0.0) sha256={upstream_sha}\n\nBUNDLED WITH\n   4.1.0.beta3\n",
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
        let Restored {
            lock: next_lock,
            manifest: next_manifest,
            ..
        } = restore_one(
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
            // The pair as socket-patch 5.0 / 5.1 left it: the gem's own
            // Socket block nested in the user's (today's rewriter refuses a
            // declaration in a user's source block instead).
            let (hosted_manifest, hosted_lock) = block_form_pair(manifest, &lock, &upstream_sha);
            assert!(hosted_lock.contains(IDX), "{hosted_lock}");
            let restored = restore_one(
                &gem(),
                Some(&hosted_lock),
                Some(&hosted_manifest),
                "Gemfile",
                &global_sources(&hosted_manifest),
                &ctx,
            )
            .await
            .unwrap()
            .expect("the redirect is found");
            assert_eq!(restored.manifest.as_deref(), Some(manifest));
            assert_eq!(restored.lock.as_deref(), Some(lock.as_str()));
        }

        // A `source:` option on a declaration inside the user's block (a
        // hand-edited pair): it comes off, and the `!` stays the same way.
        let manifest = "source \"https://rubygems.org\"\n\nsource \"https://rubygems.org\" do\n  \
                        gem \"rails\", \"7.0.0\"\nend\n";
        let lock = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n\n\
                    PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (= 7.0.0)!\n\nBUNDLED WITH\n   2.5.23\n";
        let hosted_manifest = manifest.replace(
            "gem \"rails\", \"7.0.0\"",
            &format!("gem \"rails\", \"7.0.0\", source: \"{IDX}\""),
        );
        let hosted_lock = format!(
            "GEM\n  remote: {IDX}\n  specs:\n    rails (7.0.0)\n\nGEM\n  remote: \
             https://rubygems.org/\n  specs:\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  \
             rails (= 7.0.0)!\n\nBUNDLED WITH\n   2.5.23\n"
        );
        let restored = restore_one(
            &gem(),
            Some(&hosted_lock),
            Some(&hosted_manifest),
            "Gemfile",
            &global_sources(&hosted_manifest),
            &ctx,
        )
        .await
        .unwrap()
        .expect("the redirect is found");
        assert_eq!(restored.manifest.as_deref(), Some(manifest));
        assert_eq!(restored.lock.as_deref(), Some(lock));
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

        // Two superseding wirings for the same gem: not ours to pick.
        let block = format!(
            "source \"{}\" do\n  gem \"rails\", \"7.0.0\"\nend\n",
            IDX.replace(UUID, "99999999-9999-9999-9999-999999999999")
        );
        let (r, _, _) = run(
            vec![pin(UUID, &["Gemfile.lock"])],
            format!("{superseded}{block}"),
        )
        .await;
        assert!(r.refused.contains_key(UUID), "{:?}", r.handled);
    }

    /// RE-D5: a pin socket-patch 5.0 / 5.1 wrote as a `source … do` block
    /// still unwinds as before — the declaration comes back as the exact
    /// pin the lock records — and the restore now says so, naming the
    /// declaration, once for the manifest. A pin in the option form restores
    /// the user's own declaration and reports nothing.
    #[tokio::test]
    async fn restore_of_a_block_names_the_declaration_it_pinned() {
        let client = super::super::UpstreamClient::new(true);
        let upstream_sha = "2".repeat(64);
        client
            .seed_rubygems_sha256("rails", "7.0.0", &upstream_sha)
            .await;
        let ctx = ctx_with(&client);
        let original = "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n";
        let lock = format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n\nPLATFORMS\n  \
             ruby\n\nDEPENDENCIES\n  rails (= 7.0.0)\n\nCHECKSUMS\n  rails (7.0.0) \
             sha256={upstream_sha}\n\nBUNDLED WITH\n   2.6.9\n"
        );
        let (block_manifest, block_lock) = block_form_pair(original, &lock, &upstream_sha);
        let option_pair = hosted_pair(true, &upstream_sha);
        let pin = HostedPin {
            purl: "pkg:gem/rails@7.0.0".into(),
            uuid: UUID.into(),
            files: vec!["Gemfile.lock".into()],
        };
        for (manifest, hosted_lock, warns) in [
            (&block_manifest, &block_lock, true),
            (&option_pair["Gemfile"], &option_pair["Gemfile.lock"], false),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::write(tmp.path().join("Gemfile"), manifest).unwrap();
            std::fs::write(tmp.path().join("Gemfile.lock"), hosted_lock).unwrap();
            let mut view = View::new(tmp.path());
            let r = restore(&mut view, &[&pin], &pin.files, &ctx).await;
            assert!(r.refused.is_empty(), "{:?}", r.refused);
            let changed = view.changed();
            assert_eq!(
                changed.get("Gemfile").cloned().flatten().as_deref(),
                Some(original)
            );
            assert_eq!(
                changed.get("Gemfile.lock").cloned().flatten().as_deref(),
                Some(lock.as_str())
            );
            let pinned: Vec<&str> = r
                .warnings
                .iter()
                .filter(|(code, _)| *code == DECLARATION_PINNED)
                .map(|(_, detail)| detail.as_str())
                .collect();
            assert_eq!(pinned.len(), usize::from(warns), "{:?}", r.warnings);
            if let [detail] = pinned.as_slice() {
                assert!(
                    detail.contains(
                        "Gemfile: `gem \"rails\", \"7.0.0\"` was restored as an exact pin"
                    ) && detail.contains("put it back by hand")
                        && detail.contains("bundle lock"),
                    "{detail}"
                );
            }
        }
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
