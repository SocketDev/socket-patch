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
//! source pin (`name (= v)!`) loses its `!`.
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
//!   the in-place match swallows every blank line before the declaration)
//!   that another locked spec depends on. Otherwise the gem is kept as a
//!   direct pin: a stray exact pin installs the same bytes, while dropping
//!   a real declaration would stop `Bundler.require` loading the gem.
//! * a `CHECKSUMS` entry the rewriter ADDED is only recognizable next to
//!   bundler's own bare entry for the gem (then it is dropped); otherwise it
//!   is re-pinned in place.

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;

use super::{Ctx, FormatResult, HostedPin, View};
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

/// Restore `gem` in the LF lock text (module docs). `transitive`: drop the
/// `DEPENDENCIES` entry instead of unpinning it.
fn lock_edit(
    lock: &str,
    gem: &Gem<'_>,
    globals: &[String],
    transitive: bool,
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
            if transitive {
                drop.insert(k);
            } else if let Some(unpinned) = entry.strip_suffix('!') {
                replace.insert(k, format!("  {unpinned}"));
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
    let re = Regex::new(&format!(
        r#"(?m)^source "([^"\r\n]*)" do\r?\n  gem "{}", "{}"(?:, ([^\r\n]*))?\r?\nend(\r?\n|\z)"#,
        regex::escape(&gem.name),
        regex::escape(&gem.version)
    ))
    .expect("source-block regex from escaped coordinates is valid");
    let hits: Vec<Block> = re
        .captures_iter(text)
        .filter(|c| ctx.hosted_uuid(&c[1]).as_deref() == Some(gem.uuid))
        .map(|c| {
            let m = c.get(0).expect("group 0 is the whole match");
            Block {
                start: m.start(),
                end: m.end(),
                opts: c.get(2).map(|o| o.as_str().to_string()),
                eol: !c[3].is_empty(),
            }
        })
        .collect();
    let rest_mentions = |b: Option<&Block>| {
        let rest = match b {
            Some(b) => format!("{}{}", &text[..b.start], &text[b.end..]),
            None => text.to_string(),
        };
        rest.contains(gem.uuid)
    };
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
/// conventional layout from the neighbors: inside a block (`group … do`)
/// or right after another declaration or a comment, the neighbor's indent
/// and no blank line; after anything else (`source`, `ruby`, `end`, …) one
/// blank line and the indent of the declaration that follows, if any.
fn declaration_prefix(text: &str, block: &Block, eol: &str) -> String {
    let Some(prev) = line_before(text, block.start) else {
        return String::new();
    };
    let trimmed = prev.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let code = trimmed.split('#').next().unwrap_or_default().trim_end();
    if code == "do" || code.ends_with(" do") || (code.ends_with('|') && code.contains(" do |")) {
        return format!("{}  ", indent_of(prev));
    }
    if trimmed.starts_with('#') || gem_declaration_any(trimmed).is_some() {
        return indent_of(prev).to_string();
    }
    let next = text[block.end..].split('\n').next().unwrap_or_default();
    let indent = if gem_declaration_any(next.trim()).is_some() {
        indent_of(next)
    } else {
        ""
    };
    format!("{eol}{indent}")
}

/// How the gem comes back into the manifest.
enum Decl {
    /// Gone: the block was the rewriter's append for a transitive gem.
    Transitive,
    /// `gem "<name>"<args>[, <opts>]`; `args` is the version constraint list
    /// (`, "7.0.0"`).
    Direct(String),
}

fn restore_manifest(text: &str, block: &Block, gem: &Gem<'_>, decl: &Decl) -> String {
    let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let replacement = match decl {
        Decl::Transitive => String::new(),
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
    format!(
        "{}{replacement}{}",
        &text[..block.start],
        &text[block.end..]
    )
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
        for pin in pins {
            if result.refused.contains_key(&pin.uuid) {
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
                Ok(Some((next_lock, next_manifest))) => {
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
                }
                Err(why) => result.refuse(&pin.uuid, why),
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

/// Restore one gem in a lock + manifest pair: `Ok(None)` when neither wires
/// it, else the next `(lock, manifest)` texts.
async fn restore_one(
    gem: &Gem<'_>,
    lock: Option<&str>,
    manifest: Option<&str>,
    manifest_rel: &str,
    globals: &[String],
    ctx: &Ctx<'_>,
) -> Result<Option<(Option<String>, Option<String>)>, String> {
    let block = match manifest {
        Some(text) => find_block(text, gem, manifest_rel, ctx)?,
        None => None,
    };
    let lines: Vec<&str> = lock.map(|l| l.split('\n').collect()).unwrap_or_default();
    let wired = match lock {
        Some(_) => wiring(&gem_sections(&lines), gem.uuid, ctx)?.is_some(),
        None => false,
    };
    if !wired && block.is_none() {
        return Ok(None);
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
    let transitive = matches!(decl, Decl::Transitive);
    let next_lock = match lock {
        None => None,
        Some(text) => Some(
            match lock_edit(text, gem, globals, transitive, None, ctx)? {
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
                    match lock_edit(text, gem, globals, transitive, Some(&sha), ctx)? {
                        LockEdit::Done(next) => next,
                        LockEdit::NeedsSha { .. } => unreachable!("a sha was supplied"),
                    }
                }
            },
        ),
    };
    let next_manifest = match (manifest, &block) {
        (Some(text), Some(b)) => Some(restore_manifest(text, b, gem, &decl)),
        _ => manifest.map(str::to_string),
    };
    Ok(Some((next_lock, next_manifest)))
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
            done(lock_edit(&hosted, &gem(), &[], false, None, &ctx).unwrap()),
            want
        );
        // Transitive: the DEPENDENCIES entry the rewriter added goes.
        let out = done(lock_edit(&hosted, &gem(), &[], true, None, &ctx).unwrap());
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
        match lock_edit(&hosted, &gem(), &[], false, None, &ctx).unwrap() {
            LockEdit::NeedsSha { remote } => {
                assert_eq!(remote.as_deref(), Some("https://rubygems.org/"))
            }
            LockEdit::Done(_) => panic!("CHECKSUMS entry left patched"),
        }
        let sha = "2".repeat(64);
        assert_eq!(
            done(lock_edit(&hosted, &gem(), &[], false, Some(&sha), &ctx).unwrap()),
            format!(
                "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n\nDEPENDENCIES\n  \
                 rails (= 7.0.0)\n\nCHECKSUMS\n  rails (7.0.0) sha256={sha}\n"
            )
        );
        // The rewriter's ADDED entry next to bundler's bare one is dropped.
        let added = hosted.replace("CHECKSUMS\n", "CHECKSUMS\n  rails (7.0.0)\n");
        assert!(
            done(lock_edit(&added, &gem(), &[], false, None, &ctx).unwrap())
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
            done(lock_edit(&hosted, &gem(), &[], false, None, &ctx).unwrap()),
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
        assert!(lock_edit(&two_upstreams, &gem(), &[], false, None, &ctx).is_err());
        // The manifest's global source singles one out.
        let globals = vec!["https://mirror.example".to_string()];
        let out = done(lock_edit(&two_upstreams, &gem(), &globals, false, None, &ctx).unwrap());
        assert!(
            out.contains("remote: https://mirror.example/\n  specs:\n    rails (7.0.0)\n"),
            "{out}"
        );
        // A Socket section locking another gem too is not ours to split.
        let extra = format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n\nGEM\n  remote: {IDX}\n  specs:\n    \
             rack (3.0.0)\n    rails (7.0.0)\n\nDEPENDENCIES\n  rails (= 7.0.0)!\n"
        );
        assert!(lock_edit(&extra, &gem(), &[], false, None, &ctx).is_err());
        let none = format!(
            "GEM\n  remote: {IDX}\n  specs:\n    rails (7.0.0)\n\nDEPENDENCIES\n  rails!\n"
        );
        assert!(lock_edit(&none, &gem(), &[], false, None, &ctx).is_err());
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
        // Transitive append removed; mixed-state constraint kept.
        let t = format!("source \"https://rubygems.org\"\n\ngem \"puma\"\n\n{block}\n");
        assert_eq!(
            run(&t, &Decl::Transitive),
            "source \"https://rubygems.org\"\n\ngem \"puma\"\n\n"
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
