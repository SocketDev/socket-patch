//! The routed shape of a hosted pin in a lockfileVersion 9 `pnpm-lock.yaml`.
//!
//! Hosted mode can route a patched `name@version` through a pnpm named
//! registry: pnpm-workspace.yaml declares the patch server's registry of
//! the patch (`socket-58f14d5a`, written `<alias>` below;
//! [`super::named_registries`]) and overrides `name@version` with
//! `<alias>:version`. pnpm then resolves the package from that registry,
//! and the lock it writes names the registry everywhere the release is
//! named:
//!
//! * `overrides:` gains `name@version: <alias>:version`, in the workspace
//!   file's order;
//! * the `packages:` key becomes `name@<alias>:version`, its `resolution`
//!   the patched tarball, the entry's other fields as they were, less
//!   `deprecated` (the upstream registry's remark, which the patch
//!   server's document does not carry);
//! * each `snapshots:` key of the release becomes
//!   `name@<alias>:version(<peers>)`;
//! * every reference follows: a snapshot's `name: <alias>:version(<peers>)`,
//!   the `(name@<alias>:version)` inside another package's peer suffix, and
//!   an importer's `specifier: <alias>:version` /
//!   `version: <alias>:version(<peers>)`;
//! * a package whose key now holds the registry in its peer suffix, and
//!   that is not itself from a named registry, gets a `version:` line
//!   (pnpm records one for a key that contains a `:`);
//! * `packages:` and `snapshots:` stay sorted by key.
//!
//! [`OverrideLock`] makes those edits without running pnpm, as line splices
//! over the project document, and takes them back out. Its output is pinned
//! to pnpm's own by the `pnpm-registry-overrides` fixtures (see
//! `scripts/gen-pnpm-registry-override-golden.mjs`), which pnpm 11.20
//! through 12.22 produce byte for byte alike. Two shapes those releases do
//! NOT lock alike, or not as a plain respelling, are refused, and the run
//! stays on `trustLockfile`: a package installed both with and without the
//! release as its peer (pnpm 11 and 12 differ on its `version:` line), and
//! a release installed as another package's optional peer (pnpm resolves
//! that copy around the override, so it would stay unpatched).
//!
//! Pure text in, answers out; the callers own the reads and writes.

use std::collections::{BTreeMap, BTreeSet};

use super::lines::{
    indent_of, next_block, parse_key_line, section_bounds, split_lines, split_project_document,
    unquote_value, yaml_key, yaml_value,
};
use super::named_registries::{HostedOverride, Owned};
use super::version::override_applies;
use super::{lock_version_major, strip_pnpm_peer_suffix};
use crate::utils::line_endings::LineEndings;

/// The top-level keys pnpm writes after `overrides:`, in its order: a new
/// `overrides:` section goes before the first one present.
const KEYS_AFTER_OVERRIDES: [&str; 7] = [
    "packageExtensionsChecksum",
    "pnpmfileChecksum",
    "untrackedPnpmfileReadPackageHook",
    "patchedDependencies",
    "importers",
    "packages",
    "snapshots",
];

/// One hosted pin to write in the override shape.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AliasPin<'a> {
    /// The package's full name (`@scope/name`).
    pub(crate) name: &'a str,
    pub(crate) version: &'a str,
    /// The registry of ours the release is routed to.
    pub(crate) alias: &'a str,
    /// The patched tarball's `sha512-…` integrity.
    pub(crate) integrity: &'a str,
    /// The patched tarball's URL.
    pub(crate) tarball: &'a str,
}

/// What [`OverrideLock::pin`] did for one pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Pinned {
    /// The lock does not lock this release.
    Absent,
    /// The release was already in this exact shape.
    InPlace,
    /// The release was rewritten; `from` is the `packages:` key it had.
    Rewritten { from: String },
}

/// What a package.json (`manifest`, an importer's) asks for `name`: the
/// specifier of its `dependencies`, `devDependencies` or
/// `optionalDependencies` entry. `None` when it names the package in none
/// of them, or in two with different specifiers.
pub(crate) fn manifest_specifier(manifest: &str, name: &str) -> Option<String> {
    let manifest: serde_json::Value =
        serde_json::from_str(crate::formats::text::strip_bom(manifest)).ok()?;
    let mut found: Option<&str> = None;
    for field in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(spec) = manifest.get(field).and_then(|deps| deps.get(name)) else {
            continue;
        };
        let spec = spec.as_str()?;
        if found.is_some_and(|seen| seen != spec) {
            return None;
        }
        found = Some(spec);
    }
    found.map(str::to_string)
}

/// How an importer's `specifier:` is written when a release moves.
enum Specifier<'a> {
    /// To the override shape: the override's own value.
    Alias,
    /// Back to the registry shape: what the importer's manifest asks for
    /// (`(importer, dependency name)`); the lock no longer says.
    Manifest(&'a dyn Fn(&str, &str) -> Option<String>),
}

/// A lockfileVersion 9 lock under edit: the project document's lines, with
/// whatever precedes it (pnpm >= 11's env document) kept aside.
#[derive(Debug, Clone)]
pub(crate) struct OverrideLock {
    prefix: String,
    lines: Vec<String>,
    crlf: bool,
    /// Which registries a key may name are hosted mode's.
    owned: Owned,
    changed: bool,
    /// Packages (by their `packages:` key) whose snapshot keys changed
    /// under them: their `version:` line is settled by [`Self::finish`].
    touched: BTreeSet<String>,
    /// `packages:` / `snapshots:` keys that were renamed, to re-sort.
    moved: [BTreeSet<String>; 2],
}

const SECTIONS: [&str; 2] = ["packages", "snapshots"];

/// `(token, suffix)` when `key` names `name@version`: the token is the
/// version as the key spells it (`1.0.0`, or `socket-58f14d5a:1.0.0`) and the
/// suffix what follows (empty, or a peer suffix).
fn release_token<'k>(
    key: &'k str,
    name: &str,
    version: &str,
    owned: &Owned,
) -> Option<(&'k str, &'k str)> {
    let rest = key.strip_prefix(name)?.strip_prefix('@')?;
    let end = token_end(rest, version, owned)?;
    Some(rest.split_at(end))
}

/// The length of the token naming `version` at the start of `value`
/// (`1.0.0…` or `socket-58f14d5a:1.0.0…`, the registry one of ours), when what
/// follows it is the end or a peer suffix.
fn token_end(value: &str, version: &str, owned: &Owned) -> Option<usize> {
    let plain = value.strip_prefix(version).map(|_| version.len());
    let routed = value.split_once(':').and_then(|(registry, rest)| {
        owned.alias(registry).then_some(())?;
        rest.strip_prefix(version)
            .map(|_| registry.len() + 1 + version.len())
    });
    plain
        .or(routed)
        .filter(|&end| value[end..].is_empty() || value[end..].starts_with('('))
}

/// The registry of ours a version token (`socket-58f14d5a:1.0.0`) names.
fn token_alias<'t>(token: &'t str, owned: &Owned) -> Option<&'t str> {
    let (registry, _) = token.split_once(':')?;
    owned.alias(registry).then_some(registry)
}

/// `text` with every `(name@from` peer reference (followed by `)` or `(`)
/// respelled `(name@to`.
fn retoken_peers(text: &str, name: &str, from: &str, to: &str) -> Option<String> {
    let needle = format!("({name}@{from}");
    if !text.contains(&needle) {
        return None;
    }
    let mut out = String::with_capacity(text.len() + to.len());
    let mut rest = text;
    let mut changed = false;
    while let Some(at) = rest.find(&needle) {
        let after = &rest[at + needle.len()..];
        out.push_str(&rest[..at]);
        if after.starts_with([')', '(']) {
            out.push_str(&format!("({name}@{to}"));
            changed = true;
        } else {
            out.push_str(&needle);
        }
        rest = after;
    }
    out.push_str(rest);
    changed.then_some(out)
}

/// Whether `text`, a lock [`OverrideLock::parse`] refuses, may still hold
/// something of a registry route: a key, a reference or an `overrides:`
/// record that spells a version through a registry whose name starts as
/// ours do (`socket-58f14d5a:1.0.0`; an unreleased build's `socket:1.0.0`).
///
/// The edits cannot say what such a lock routes, so a caller that would
/// take a route out of the workspace file beside it leaves the route
/// alone: half of a route does not install. A scoped package named
/// `@socket…/x` is not a route (`@socketsecurity/lib@1.0.0`).
pub(crate) fn names_a_route(text: &str) -> bool {
    text.match_indices("socket").any(|(at, _)| {
        let before = text[..at].chars().next_back();
        if !matches!(before, Some('@' | ' ' | '\'' | '"' | '(')) {
            return false;
        }
        let rest = &text[at..];
        let name = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .unwrap_or(rest.len());
        rest[name..]
            .strip_prefix(':')
            .and_then(|version| version.chars().next())
            .is_some_and(|c| c.is_ascii_digit() || c == '@' || c.is_ascii_alphabetic())
    })
}

impl OverrideLock {
    /// Read a lock for the override edits; `owned` says which registries
    /// its keys may name are hosted mode's. `Err` completes "the lock …"
    /// with why it is not one these edits were captured against.
    pub(crate) fn parse(text: &str, owned: &Owned) -> Result<Self, String> {
        let crlf = match LineEndings::of(text) {
            LineEndings::Crlf => true,
            LineEndings::Lf | LineEndings::None => false,
            LineEndings::Mixed => return Err("mixes CRLF and LF line endings".to_string()),
        };
        let lf = if crlf {
            text.replace("\r\n", "\n")
        } else {
            text.to_string()
        };
        let (prefix, project) = split_project_document(&lf)?;
        if lock_version_major(project) != Some(9) {
            return Err("is not a lockfileVersion 9 lock".to_string());
        }
        let lines = split_lines(project);
        if section_bounds(&lines, "packages").is_some()
            && section_bounds(&lines, "snapshots").is_none()
        {
            return Err("has `packages:` but no `snapshots:`".to_string());
        }
        // pnpm writes each entry as one run of lines, with one empty line
        // between entries; the edits move and rewrite entries by that. A
        // text of several paragraphs (a `deprecated: |` block with an empty
        // line in it, or one that keeps its trailing line breaks) does not
        // fit it: part of the entry would be left behind.
        for section in SECTIONS {
            let Some((start, end)) = section_bounds(&lines, section) else {
                continue;
            };
            let entries = &lines[start + 1..end];
            let split = entries
                .windows(2)
                .any(|pair| pair[0].is_empty() && (pair[1].is_empty() || indent_of(&pair[1]) >= 4));
            if split {
                return Err(format!(
                    "has an entry under `{section}:` whose text runs past an empty line \
                     (a block of several paragraphs)"
                ));
            }
        }
        Ok(OverrideLock {
            prefix: prefix.to_string(),
            lines,
            crlf,
            owned: owned.clone(),
            changed: false,
            touched: BTreeSet::new(),
            moved: Default::default(),
        })
    }

    /// The lock as edited, or `None` when nothing changed.
    pub(crate) fn render(&self) -> Option<String> {
        if !self.changed {
            return None;
        }
        let text = format!("{}{}", self.prefix, self.lines.join("\n"));
        Some(if self.crlf {
            text.replace('\n', "\r\n")
        } else {
            text
        })
    }

    /// The blocks of a section, as `(header line, end line, key)`.
    fn blocks(&self, section: &str) -> Vec<(usize, usize, String)> {
        let Some((start, end)) = section_bounds(&self.lines, section) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut at = start + 1;
        while let Some(block) = next_block(&self.lines, at, end) {
            at = block.end;
            out.push((block.header, block.end, block.key));
        }
        out
    }

    /// Respell the key of the block at `header`.
    fn rekey(&mut self, section: usize, header: usize, new_key: &str) {
        let rest = parse_key_line(&self.lines[header], 2).map_or("", |(_, _, rest)| rest);
        let rest = if rest.is_empty() {
            String::new()
        } else {
            format!(" {rest}")
        };
        self.lines[header] = format!("  {}:{rest}", yaml_key(new_key));
        self.moved[section].insert(new_key.to_string());
        self.changed = true;
    }

    /// Every release a `packages:` key routes through a registry of ours:
    /// the hosted pins this lock holds in the routed shape.
    pub(crate) fn aliased(&self) -> Vec<HostedOverride> {
        self.blocks("packages")
            .into_iter()
            .filter_map(|(_, _, key)| {
                let at = key.get(1..)?.find('@')? + 1;
                let (registry, version) = key[at + 1..].split_once(':')?;
                self.owned.alias(registry).then(|| HostedOverride {
                    name: key[..at].to_string(),
                    version: version.to_string(),
                    alias: registry.to_string(),
                })
            })
            .collect()
    }

    /// The entries of the lock's `overrides:` section that route a release
    /// to a registry of ours.
    pub(crate) fn routed_overrides(&self) -> Vec<HostedOverride> {
        self.overrides()
            .iter()
            .filter_map(|(key, value)| self.owned.route(key, value))
            .collect()
    }

    /// Whether the lock holds something of a registry route: a release it
    /// keys by a registry of ours ([`Self::aliased`]), or a record of an
    /// override that routes one there ([`Self::routed_overrides`]). A lock
    /// can hold the second alone: pnpm records the workspace file's
    /// overrides in every lock it governs.
    pub(crate) fn holds_route(&self) -> bool {
        !self.aliased().is_empty() || !self.routed_overrides().is_empty()
    }

    /// The lock's importers, as it keys them (`.`, `packages/a`).
    pub(crate) fn importers(&self) -> Vec<String> {
        self.blocks("importers")
            .into_iter()
            .map(|(_, _, key)| key)
            .collect()
    }

    /// The `(key, value)` entries of the lock's `overrides:` section.
    pub(crate) fn overrides(&self) -> Vec<(String, String)> {
        let Some((start, end)) = section_bounds(&self.lines, "overrides") else {
            return Vec::new();
        };
        self.lines[start + 1..end]
            .iter()
            .filter_map(|line| parse_key_line(line, 2))
            .map(|(key, _, rest)| (key.to_string(), unquote_value(rest).to_string()))
            .collect()
    }

    /// Move `name@version` to the routed shape under `pin`'s registry,
    /// from the plain shape or from another registry of ours. `Err` (why,
    /// completing "the lock …") leaves the lock as it was.
    pub(crate) fn pin(&mut self, pin: &AliasPin<'_>) -> Result<Pinned, String> {
        let mut edited = self.clone();
        let outcome = edited.pin_in_place(pin)?;
        *self = edited;
        Ok(outcome)
    }

    fn pin_in_place(&mut self, pin: &AliasPin<'_>) -> Result<Pinned, String> {
        let release = format!("{}@{}", pin.name, pin.version);
        let entries: Vec<(usize, usize, String)> = self
            .blocks("packages")
            .into_iter()
            .filter(|(_, _, key)| {
                release_token(key, pin.name, pin.version, &self.owned)
                    .is_some_and(|(_, sfx)| sfx.is_empty())
            })
            .collect();
        let (header, end, key) = match entries.as_slice() {
            [] => return Ok(Pinned::Absent),
            [entry] => entry.clone(),
            _ => {
                return Err(format!(
                    "locks {release} under more than one `packages:` key"
                ))
            }
        };
        let (from, _) =
            release_token(&key, pin.name, pin.version, &self.owned).expect("matched above");
        let from = from.to_string();
        let to = format!("{}:{}", pin.alias, pin.version);
        let resolution = format!(
            "    resolution: {{integrity: {}, tarball: {}}}",
            pin.integrity, pin.tarball
        );
        let at = (header + 1..end)
            .find(|&i| parse_key_line(&self.lines[i], 4).is_some_and(|(k, _, _)| k == "resolution"))
            .ok_or_else(|| format!("has no `resolution` for {release}"))?;
        let original = self.lines[at].clone();
        // Only a registry tarball can be swapped for another: a git or
        // directory resolution names something else.
        let flow = original
            .strip_prefix("    resolution: {")
            .and_then(|rest| rest.strip_suffix('}'))
            .ok_or_else(|| format!("resolves {release} in a form other than `{{integrity: …}}`"))?;
        if flow
            .split(", ")
            .any(|field| !field.starts_with("integrity: ") && !field.starts_with("tarball: "))
        {
            return Err(format!(
                "resolves {release} with more than an integrity and a tarball"
            ));
        }
        if from == to && original == resolution {
            return Ok(Pinned::InPlace);
        }
        self.retoken(pin.name, pin.version, &from, &to, &Specifier::Alias)?;
        // The entry is found again: the rename may have moved nothing yet,
        // but the lines above it can have changed.
        let (header, end, _) = self
            .blocks("packages")
            .into_iter()
            .find(|(_, _, key)| *key == format!("{}@{to}", pin.name))
            .expect("the entry was just renamed");
        let field = |line: &String, name: &str| {
            parse_key_line(line, 4).is_some_and(|(key, _, _)| key == name)
        };
        for i in header + 1..end {
            if field(&self.lines[i], "resolution") {
                self.lines[i] = resolution.clone();
            }
        }
        // The upstream registry's remark on the release: the patch server's
        // document carries none, so pnpm records none for a routed entry.
        // A remark of several lines is a block scalar (`deprecated: |-`),
        // whose lines follow it more deeply indented.
        if let Some(at) = (header + 1..end).find(|&i| field(&self.lines[i], "deprecated")) {
            let after = (at + 1..end)
                .find(|&i| indent_of(&self.lines[i]) <= 4)
                .unwrap_or(end);
            self.lines.drain(at..after);
        }
        self.changed = true;
        Ok(Pinned::Rewritten { from: key })
    }

    /// Move every routed release `moves` picks back to the plain shape
    /// (its `resolution` is the caller's to restore). `specifier` answers
    /// what an importer's manifest asks for; `Err` (why) leaves the lock as
    /// it was. Returns the releases moved.
    pub(crate) fn unpin(
        &mut self,
        moves: &dyn Fn(&HostedOverride) -> bool,
        specifier: &dyn Fn(&str, &str) -> Option<String>,
    ) -> Result<Vec<HostedOverride>, String> {
        let mut edited = self.clone();
        let moved: Vec<HostedOverride> = edited
            .aliased()
            .into_iter()
            .filter(|pin| moves(pin))
            .collect();
        for pin in &moved {
            edited.retoken(
                &pin.name,
                &pin.version,
                &pin.value(),
                &pin.version,
                &Specifier::Manifest(specifier),
            )?;
        }
        *self = edited;
        Ok(moved)
    }

    /// Whether routing `name@version` (now spelled `from`) is a plain
    /// respelling of the lock, which is what the fixtures prove of pnpm
    /// 11.20 through 12.22. `Err` (why) for the two shapes where it is not:
    ///
    /// * a package installed both with and without the release as its
    ///   peer: pnpm 12 records no `version:` line for it, pnpm 11 does;
    /// * the release installed as another package's optional peer: pnpm
    ///   resolves such a copy around the override, from the default
    ///   registry, so a lock that routed it would lose the patched copy
    ///   the next time pnpm resolves.
    fn routes_as_a_respelling(&self, name: &str, version: &str, from: &str) -> Result<(), String> {
        let release = format!("{name}@{version}");
        let peer = format!("({name}@{from}");
        let as_peer = |key: &str| {
            key.match_indices(&peer)
                .any(|(at, _)| key[at + peer.len()..].starts_with([')', '(']))
        };
        let snapshots = self.blocks("snapshots");
        for (header, end, key) in &snapshots {
            if !as_peer(key) {
                continue;
            }
            let package = strip_pnpm_peer_suffix(key);
            if snapshots
                .iter()
                .any(|(_, _, other)| strip_pnpm_peer_suffix(other) == package && !as_peer(other))
            {
                return Err(format!(
                    "installs {package} both with and without {release} as its peer, which \
                     pnpm releases lock differently"
                ));
            }
            let mut optional = false;
            for line in &self.lines[header + 1..*end] {
                if let Some((section, _, rest)) = parse_key_line(line, 4) {
                    optional = rest.is_empty() && section == "optionalDependencies";
                } else if optional && parse_key_line(line, 6).is_some_and(|(dep, _, _)| dep == name)
                {
                    return Err(format!(
                        "installs {release} as an optional peer of {package}, which pnpm \
                         resolves around an override"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Respell the release `name@version` from the token `from` to `to`
    /// everywhere the lock names it.
    fn retoken(
        &mut self,
        name: &str,
        version: &str,
        from: &str,
        to: &str,
        specifier: &Specifier<'_>,
    ) -> Result<(), String> {
        let release = format!("{name}@{version}");
        if from == to {
            return Ok(());
        }
        let owned = self.owned.clone();
        if let Specifier::Alias = specifier {
            self.routes_as_a_respelling(name, version, from)?;
        }
        // A copy the user patched with `pnpm patch` is not the registry's.
        let patched = |key: &str| key.contains("(patch_hash=");
        // `packages:`, then `snapshots:` with the peer suffix kept.
        for (section, name_of_section) in SECTIONS.iter().enumerate() {
            for (header, _, key) in self.blocks(name_of_section) {
                let Some((token, suffix)) = release_token(&key, name, version, &owned) else {
                    continue;
                };
                if patched(&key) {
                    return Err(format!("holds a patched copy of {release} (`{key}`)"));
                }
                if token == from {
                    self.rekey(section, header, &format!("{name}@{to}{suffix}"));
                    // Its own `version:` line follows its new key.
                    self.touched.insert(format!("{name}@{to}"));
                }
            }
        }
        // Peer suffixes and dependency references in `snapshots:`.
        for (header, end, key) in self.blocks("snapshots") {
            if let Some(new_key) = retoken_peers(&key, name, from, to) {
                self.touched
                    .insert(strip_pnpm_peer_suffix(&new_key).to_string());
                self.rekey(1, header, &new_key);
            }
            for i in header + 1..end {
                let line = self.lines[i].clone();
                let Some((dep, repr, rest)) = parse_key_line(&line, 6) else {
                    continue;
                };
                let value = unquote_value(rest);
                // `alias: name@version`: an npm alias of the release.
                if value
                    .strip_prefix(name)
                    .and_then(|rest| rest.strip_prefix('@'))
                    .is_some_and(|rest| token_end(rest, version, &owned).is_some())
                {
                    return Err(format!("installs {release} under another name (`{dep}`)"));
                }
                let mut new_value = None;
                if dep == name && value.strip_prefix(from).is_some_and(follows_token) {
                    new_value = Some(format!("{to}{}", &value[from.len()..]));
                }
                let seen = new_value.as_deref().unwrap_or(value);
                if let Some(peers) = retoken_peers(seen, name, from, to) {
                    new_value = Some(peers);
                }
                if let Some(new_value) = new_value {
                    self.lines[i] = format!("      {repr}: {}", yaml_value(&new_value));
                    self.changed = true;
                }
            }
        }
        self.retoken_importers(name, version, from, to, specifier)
    }

    /// The importers' part of [`Self::retoken`]: a direct dependency locked
    /// at the release takes the new specifier and version, and every
    /// version's peer suffix follows.
    fn retoken_importers(
        &mut self,
        name: &str,
        version: &str,
        from: &str,
        to: &str,
        specifier: &Specifier<'_>,
    ) -> Result<(), String> {
        let release = format!("{name}@{version}");
        for (header, end, importer) in self.blocks("importers") {
            let mut dep: Option<String> = None;
            let mut spec_line: Option<usize> = None;
            for i in header + 1..end {
                let line = self.lines[i].clone();
                if let Some((key, _, "")) = parse_key_line(&line, 6) {
                    dep = Some(key.to_string());
                    spec_line = None;
                    continue;
                }
                let (Some(dep), Some((field, _, rest))) =
                    (dep.as_deref(), parse_key_line(&line, 8))
                else {
                    continue;
                };
                if field == "specifier" {
                    spec_line = Some(i);
                    continue;
                }
                if field != "version" {
                    continue;
                }
                let value = unquote_value(rest);
                if value
                    .strip_prefix(name)
                    .and_then(|rest| rest.strip_prefix('@'))
                    .is_some_and(|rest| token_end(rest, version, &self.owned).is_some())
                {
                    return Err(format!(
                        "installs {release} under another name (`{dep}` of importer `{importer}`)"
                    ));
                }
                let mut new_value = None;
                if dep == name {
                    let locked_here = value.strip_prefix(from).is_some_and(follows_token);
                    let Some(at) = spec_line else {
                        return Err(format!(
                            "locks {name} for importer `{importer}` without a specifier"
                        ));
                    };
                    let spec = parse_key_line(&self.lines[at], 8)
                        .map(|(_, _, rest)| unquote_value(rest).to_string())
                        .unwrap_or_default();
                    if let Specifier::Alias = specifier {
                        // pnpm applies the override to every specifier that
                        // admits the release, wherever it is locked now.
                        // Already ours: the short spelling, or the long one
                        // an unreleased build wrote.
                        let ours = token_alias(from, &self.owned).is_some_and(|registry| {
                            spec == from || spec == format!("{registry}:{release}")
                        });
                        let applies = if ours {
                            Some(true)
                        } else {
                            override_applies(&spec, version)
                        };
                        match (locked_here, applies) {
                            (true, Some(true)) | (false, Some(false)) => {}
                            (true, _) => {
                                return Err(format!(
                                    "locks {release} for importer `{importer}` through the \
                                     specifier `{spec}`, which pnpm would not override"
                                ))
                            }
                            (false, _) => {
                                return Err(format!(
                                    "locks {name} for importer `{importer}` at another version \
                                     through the specifier `{spec}`, which may admit {version}"
                                ))
                            }
                        }
                    }
                    if locked_here {
                        let new_spec = match specifier {
                            Specifier::Alias => to.to_string(),
                            Specifier::Manifest(read) => {
                                read(&importer, name).ok_or_else(|| {
                                    format!(
                                        "locks {release} for importer `{importer}`, whose \
                                     package.json does not say which version it asks for"
                                    )
                                })?
                            }
                        };
                        self.lines[at] = format!("        specifier: {}", yaml_value(&new_spec));
                        new_value = Some(format!("{to}{}", &value[from.len()..]));
                    }
                }
                let seen = new_value.as_deref().unwrap_or(value);
                if let Some(peers) = retoken_peers(seen, name, from, to) {
                    new_value = Some(peers);
                }
                if let Some(new_value) = new_value {
                    self.lines[i] = format!("        version: {}", yaml_value(&new_value));
                    self.changed = true;
                }
            }
        }
        Ok(())
    }

    /// Make the `overrides:` section hold exactly `wanted` among the
    /// overrides of ours: entries of ours that are not wanted go, one
    /// spelled otherwise (another registry of ours) is rewritten in place,
    /// and the missing ones are appended in key order — the order
    /// [`super::named_registries`] gives the workspace file, which pnpm
    /// mirrors. Any other entry is the user's and stays.
    pub(crate) fn set_overrides(&mut self, wanted: &[HostedOverride]) {
        let wanted: BTreeMap<String, String> =
            wanted.iter().map(|o| (o.key(), o.value())).collect();
        let entry = |key: &str, value: &str| format!("  {}: {}", yaml_key(key), yaml_value(value));
        let Some((start, end)) = section_bounds(&self.lines, "overrides") else {
            if wanted.is_empty() {
                return;
            }
            let at = self
                .lines
                .iter()
                .position(|line| {
                    KEYS_AFTER_OVERRIDES
                        .iter()
                        .any(|key| line.strip_prefix(key).is_some_and(|r| r.starts_with(':')))
                })
                .unwrap_or(self.lines.len());
            let mut section = vec!["overrides:".to_string()];
            section.extend(wanted.iter().map(|(key, value)| entry(key, value)));
            section.push(String::new());
            self.lines.splice(at..at, section);
            self.changed = true;
            return;
        };
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut kept: Vec<String> = Vec::new();
        let mut last_entry = 0;
        for line in &self.lines[start + 1..end] {
            let parsed = parse_key_line(line, 2)
                .map(|(key, _, rest)| (key.to_string(), unquote_value(rest).to_string()));
            let ours = parsed
                .as_ref()
                .and_then(|(key, value)| self.owned.route(key, value));
            match (parsed, ours) {
                (Some((key, value)), Some(_)) => match wanted.get(&key) {
                    Some(want) => {
                        seen.insert(key.clone());
                        kept.push(if *want == value {
                            line.clone()
                        } else {
                            entry(&key, want)
                        });
                        last_entry = kept.len();
                    }
                    None => continue,
                },
                (Some(_), None) => {
                    kept.push(line.clone());
                    last_entry = kept.len();
                }
                (None, _) => kept.push(line.clone()),
            }
        }
        let missing: Vec<String> = wanted
            .iter()
            .filter(|(key, _)| !seen.contains(*key))
            .map(|(key, value)| entry(key, value))
            .collect();
        kept.splice(last_entry..last_entry, missing);
        let rebuilt: Vec<String> = if kept.iter().all(|line| line.is_empty()) {
            // Nothing left in the section: it goes with its blank line.
            Vec::new()
        } else {
            std::iter::once("overrides:".to_string())
                .chain(kept)
                .collect()
        };
        if rebuilt != self.lines[start..end] {
            self.lines.splice(start..end, rebuilt);
            self.changed = true;
        }
    }

    /// Take the overrides of ours `keep` does not pick out of the
    /// `overrides:` section, and add or rewrite none: what is left of a
    /// route follows what the locks still hold.
    pub(crate) fn prune_overrides(&mut self, keep: &dyn Fn(&HostedOverride) -> bool) {
        let kept: Vec<HostedOverride> = self
            .routed_overrides()
            .into_iter()
            .filter(|pin| keep(pin))
            .collect();
        if kept.len() != self.routed_overrides().len() {
            let Some((start, end)) = section_bounds(&self.lines, "overrides") else {
                return;
            };
            let stays = |line: &String| {
                parse_key_line(line, 2)
                    .and_then(|(key, _, rest)| self.owned.route(key, unquote_value(rest)))
                    .is_none_or(|pin| kept.contains(&pin))
            };
            let rest: Vec<String> = self.lines[start + 1..end]
                .iter()
                .filter(|line| stays(line))
                .cloned()
                .collect();
            let rebuilt: Vec<String> = if rest.iter().all(|line| line.is_empty()) {
                Vec::new()
            } else {
                std::iter::once("overrides:".to_string())
                    .chain(rest)
                    .collect()
            };
            self.lines.splice(start..end, rebuilt);
            self.changed = true;
        }
    }

    /// Settle what the renames leave behind: the `version:` line of each
    /// package whose keys changed, and the place of each renamed block in
    /// its section. `Err` (why) when a section is not laid out as pnpm
    /// writes one.
    pub(crate) fn finish(&mut self) -> Result<(), String> {
        let touched = std::mem::take(&mut self.touched);
        if !touched.is_empty() {
            // Each section is read once, however many packages the renames
            // touched: a widely peered release touches hundreds.
            let keyed_with_colon: BTreeSet<String> = self
                .blocks("snapshots")
                .into_iter()
                .filter(|(_, _, key)| key.contains(':'))
                .map(|(_, _, key)| strip_pnpm_peer_suffix(&key).to_string())
                .collect();
            let mut entries: Vec<(usize, usize, String)> = self
                .blocks("packages")
                .into_iter()
                .filter(|(_, _, key)| touched.contains(key))
                .collect();
            // From the last entry up: a line added or removed moves only
            // the lines after it.
            entries.sort_by(|a, b| b.0.cmp(&a.0));
            for (header, end, package) in entries {
                let in_snapshot = keyed_with_colon.contains(&package);
                self.settle_version_line(header, end, &package, in_snapshot);
            }
        }
        for (section, name) in SECTIONS.iter().enumerate() {
            let moved = std::mem::take(&mut self.moved[section]);
            if !moved.is_empty() {
                self.resort(name, &moved)?;
            }
        }
        Ok(())
    }

    /// pnpm records `version:` on a `packages:` entry when the package's
    /// key (peer suffix included) contains a `:` and the package is not
    /// from a named registry. `header..end` is the entry of `package`,
    /// and `keyed_with_colon` whether one of its `snapshots:` keys has a
    /// `:`.
    fn settle_version_line(
        &mut self,
        header: usize,
        end: usize,
        package: &str,
        keyed_with_colon: bool,
    ) {
        let Some(at) = package.get(1..).and_then(|rest| rest.find('@')) else {
            return;
        };
        let version = &package[at + 2..];
        let from_named_registry = token_alias(version, &self.owned).is_some();
        let wanted = !from_named_registry && keyed_with_colon;
        let field = |lines: &[String], i: usize, name: &str| {
            parse_key_line(&lines[i], 4).is_some_and(|(key, _, _)| key == name)
        };
        let existing = (header + 1..end).find(|&i| field(&self.lines, i, "version"));
        match (wanted, existing) {
            (true, None) => {
                // After `resolution`, `id` and `name`, as pnpm orders them.
                let after = (header + 1..end).rfind(|&i| {
                    ["resolution", "id", "name"]
                        .iter()
                        .any(|name| field(&self.lines, i, name))
                });
                if let Some(after) = after {
                    self.lines
                        .insert(after + 1, format!("    version: {version}"));
                    self.changed = true;
                }
            }
            (false, Some(i)) if !package[at + 1..].contains(':') || from_named_registry => {
                self.lines.remove(i);
                self.changed = true;
            }
            _ => {}
        }
    }

    /// Put each block named in `moved` where its key sorts (pnpm orders a
    /// section's keys by code unit), leaving every other block in place.
    fn resort(&mut self, section: &str, moved: &BTreeSet<String>) -> Result<(), String> {
        let Some((start, end)) = section_bounds(&self.lines, section) else {
            return Ok(());
        };
        let mut blocks: Vec<(String, Vec<String>)> = Vec::new();
        let mut last = start + 1;
        for (header, block_end, key) in self.blocks(section) {
            blocks.push((key, self.lines[header..block_end].to_vec()));
            last = block_end;
        }
        let trailer: Vec<String> = self.lines[last..end].to_vec();
        let rebuild = |blocks: &[(String, Vec<String>)]| {
            let mut out: Vec<String> = Vec::with_capacity(end - start);
            for (_, lines) in blocks {
                out.push(String::new());
                out.extend(lines.iter().cloned());
            }
            out.extend(trailer.iter().cloned());
            out
        };
        let as_written = rebuild(&blocks) == self.lines[start + 1..end];
        let order: Vec<String> = blocks.iter().map(|(key, _)| key.clone()).collect();
        for key in moved {
            let Some(at) = blocks.iter().position(|(k, _)| k == key) else {
                continue;
            };
            let block = blocks.remove(at);
            let to = blocks
                .iter()
                .position(|(k, _)| k.as_str() > key.as_str())
                .unwrap_or(blocks.len());
            blocks.insert(to, block);
        }
        if blocks.iter().map(|(key, _)| key).eq(order.iter()) {
            return Ok(());
        }
        // One blank line before each block, as pnpm writes a section: any
        // other layout would be reshaped by moving a block.
        if !as_written {
            return Err(format!(
                "has a `{section}:` section that is not laid out as pnpm writes it"
            ));
        }
        self.lines.splice(start + 1..end, rebuild(&blocks));
        self.changed = true;
        Ok(())
    }
}

/// Whether what follows a version token ends it: nothing, or a peer suffix.
fn follows_token(rest: &str) -> bool {
    rest.is_empty() || rest.starts_with('(')
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! The `pnpm-registry-overrides` golden fixtures: projects as pnpm
    //! locked them, and the files pnpm ends with once pnpm-workspace.yaml
    //! routes the patches through the patch server's registry.

    use std::path::PathBuf;

    use super::super::named_registries::Owned;

    /// The patch server of the fixtures.
    pub(crate) const ORIGIN: &str = "https://patch.test";

    #[derive(Debug, Clone, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct Patch {
        pub(crate) name: String,
        pub(crate) version: String,
        pub(crate) uuid: String,
        pub(crate) artifact_url: String,
        /// The registry address a reference result carries: the directory
        /// the tarball is served from.
        pub(crate) npm_registry_url: String,
        pub(crate) sha512: String,
    }

    pub(crate) fn root() -> PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/pnpm-registry-overrides")
    }

    fn all() -> Vec<String> {
        let mut cases: Vec<String> = std::fs::read_dir(root())
            .expect("the fixture directory")
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                path.is_dir()
                    .then(|| path.file_name()?.to_str().map(str::to_string))
                    .flatten()
            })
            .collect();
        cases.sort();
        cases
    }

    /// Every case the scan routes, by name.
    pub(crate) fn cases() -> Vec<String> {
        let cases: Vec<String> = all()
            .into_iter()
            .filter(|case| read(case, "refuses.txt").is_none())
            .collect();
        assert!(cases.len() >= 15, "{cases:?}");
        cases
    }

    /// Every case real pnpm locks in a way the scan does not reproduce,
    /// with the reason the scan gives for staying off the route.
    pub(crate) fn refused() -> Vec<(String, String)> {
        let cases: Vec<(String, String)> = all()
            .into_iter()
            .filter_map(|case| {
                let why = read(&case, "refuses.txt")?;
                Some((case, why.trim().to_string()))
            })
            .collect();
        assert!(cases.len() >= 2, "{cases:?}");
        cases
    }

    pub(crate) fn read(case: &str, rel: &str) -> Option<String> {
        std::fs::read_to_string(root().join(case).join(rel)).ok()
    }

    pub(crate) fn patches(case: &str) -> Vec<Patch> {
        serde_json::from_str(&read(case, "patches.json").expect("patches.json")).expect("patches")
    }

    /// Every file of the case's `project/`, by root-relative path.
    pub(crate) fn project(case: &str) -> Vec<(String, String)> {
        fn walk(dir: &std::path::Path, base: &std::path::Path, out: &mut Vec<(String, String)>) {
            for entry in std::fs::read_dir(dir).expect("a project directory") {
                let path = entry.expect("an entry").path();
                if path.is_dir() {
                    walk(&path, base, out);
                } else {
                    let rel = path.strip_prefix(base).expect("under the project");
                    let rel = rel.to_str().expect("utf-8 path").replace('\\', "/");
                    out.push((rel, std::fs::read_to_string(&path).expect("a text file")));
                }
            }
        }
        let base = root().join(case).join("project");
        let mut out = Vec::new();
        walk(&base, &base, &mut out);
        out.sort();
        out
    }

    /// The project's pnpm locks, by root-relative path.
    pub(crate) fn locks(case: &str) -> Vec<String> {
        project(case)
            .into_iter()
            .map(|(rel, _)| rel)
            .filter(|rel| rel.ends_with("pnpm-lock.yaml"))
            .collect()
    }

    /// Which registries of the case's project are hosted mode's.
    pub(crate) fn owned(case: &str) -> Owned {
        Owned::of(
            read(case, "project/pnpm-workspace.yaml").as_deref(),
            &|origin| origin == ORIGIN,
        )
    }

    /// The name the registry of `patch` takes in the case's project.
    pub(crate) fn alias(case: &str, patch: &Patch) -> String {
        let patches = patches(case);
        let others = patches.iter().map(|other| other.uuid.as_str()).collect();
        owned(case)
            .name_for(&patch.uuid, &others)
            .expect("a free name")
    }

    /// What the package.json beside `lock`'s `importer` asks for `name`.
    pub(crate) fn manifest_specifier(
        case: &str,
        lock: &str,
        importer: &str,
        name: &str,
    ) -> Option<String> {
        let dir = lock.strip_suffix("pnpm-lock.yaml").expect("a lock path");
        let rel = if importer == "." {
            format!("project/{dir}package.json")
        } else {
            format!("project/{dir}{importer}/package.json")
        };
        super::manifest_specifier(&read(case, &rel)?, name)
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{self, Patch};
    use super::*;

    fn pin_of<'p>(patch: &'p Patch, alias: &'p str) -> AliasPin<'p> {
        AliasPin {
            name: &patch.name,
            version: &patch.version,
            alias,
            integrity: &patch.sha512,
            tarball: &patch.artifact_url,
        }
    }

    /// The release `patch` routes, through the registry `alias`.
    fn route_of(patch: &Patch, alias: String) -> HostedOverride {
        HostedOverride {
            name: patch.name.clone(),
            version: patch.version.clone(),
            alias,
        }
    }

    /// The releases a case routes, as the workspace file overrides them.
    fn routes(case: &str) -> Vec<HostedOverride> {
        let mut routes: Vec<HostedOverride> = fixtures::patches(case)
            .iter()
            .map(|patch| route_of(patch, fixtures::alias(case, patch)))
            .collect();
        routes.sort_by_key(HostedOverride::key);
        routes
    }

    /// The scan's edits to one lock of a case, in its order: every pin the
    /// lock holds, then the settling pass, then the project's overrides.
    fn apply(case: &str, lock: &str, patches: &[Patch]) -> (OverrideLock, Vec<Pinned>) {
        apply_as(case, lock, patches, &|patch| fixtures::alias(case, patch))
    }

    /// [`apply`], each patch's registry named by `alias`.
    fn apply_as(
        case: &str,
        lock: &str,
        patches: &[Patch],
        alias: &dyn Fn(&Patch) -> String,
    ) -> (OverrideLock, Vec<Pinned>) {
        let mut lock = OverrideLock::parse(lock, &fixtures::owned(case)).expect("a v9 lock");
        let pinned: Vec<Pinned> = patches
            .iter()
            .map(|patch| {
                lock.pin(&pin_of(patch, &alias(patch)))
                    .unwrap_or_else(|why| panic!("{case}: {why}"))
            })
            .filter(|pinned| *pinned != Pinned::Absent)
            .collect();
        lock.finish().expect("pnpm's layout");
        let mut wanted: Vec<HostedOverride> = patches
            .iter()
            .map(|patch| route_of(patch, alias(patch)))
            .collect();
        wanted.sort_by_key(HostedOverride::key);
        lock.set_overrides(&wanted);
        (lock, pinned)
    }

    /// `lock` with each patched release's resolution set to the hosted
    /// tarball and nothing else changed: the shape a `trustLockfile` run
    /// leaves, and what [`OverrideLock::unpin`] returns to before the
    /// caller restores the registry's resolution. `deprecated` is the
    /// upstream registry's remark, which a routed entry does not carry and
    /// an unpinned one therefore lacks.
    fn trust_shape(lock: &str, patches: &[Patch], deprecated: bool) -> String {
        let mut lines: Vec<String> = lock.split('\n').map(str::to_string).collect();
        for patch in patches {
            let key = format!("{}@{}", patch.name, patch.version);
            let Some(header) = lines
                .iter()
                .position(|line| parse_key_line(line, 2).is_some_and(|(k, _, _)| k == key))
            else {
                continue;
            };
            lines[header + 1] = format!(
                "    resolution: {{integrity: {}, tarball: {}}}",
                patch.sha512, patch.artifact_url
            );
            let end = (header + 1..lines.len())
                .find(|&i| lines[i].is_empty())
                .unwrap_or(lines.len());
            let remark = (header + 1..end).find(|&i| lines[i].starts_with("    deprecated:"));
            if let Some(remark) = remark.filter(|_| !deprecated) {
                // With the lines of a block scalar, which are indented
                // more deeply than the field.
                let after = (remark + 1..end)
                    .find(|&i| !lines[i].starts_with("     "))
                    .unwrap_or(end);
                lines.drain(remark..after);
            }
        }
        lines.join("\n")
    }

    /// The rewriter's locks are pnpm's own, byte for byte, from the plain
    /// shape and from the shape a `trustLockfile` run left; a second pass
    /// changes nothing; and a CRLF lock gets the same edits in CRLF.
    #[test]
    fn the_routed_shape_is_what_pnpm_writes() {
        for case in fixtures::cases() {
            let patches = fixtures::patches(&case);
            for rel in fixtures::locks(&case) {
                let before = fixtures::read(&case, &format!("project/{rel}")).unwrap();
                let expected = fixtures::read(&case, &format!("expected/{rel}")).unwrap();
                for start in [before.clone(), trust_shape(&before, &patches, true)] {
                    let (lock, pinned) = apply(&case, &start, &patches);
                    assert!(
                        pinned.iter().all(|p| matches!(p, Pinned::Rewritten { .. })),
                        "{case} {rel}: {pinned:?}"
                    );
                    assert_eq!(
                        lock.render().as_deref(),
                        Some(expected.as_str()),
                        "{case} {rel}"
                    );
                }
                let (again, pinned) = apply(&case, &expected, &patches);
                assert!(pinned.iter().all(|p| *p == Pinned::InPlace), "{case} {rel}");
                assert_eq!(
                    again.render(),
                    None,
                    "{case} {rel}: a second pass is a no-op"
                );

                let (crlf, _) = apply(&case, &before.replace('\n', "\r\n"), &patches);
                assert_eq!(
                    crlf.render(),
                    Some(expected.replace('\n', "\r\n")),
                    "{case} {rel} (CRLF)"
                );
            }
        }
    }

    /// The shapes real pnpm does not lock as a plain respelling are told
    /// apart and refused, with the lock left as it was.
    #[test]
    fn the_shapes_pnpm_locks_otherwise_are_refused() {
        for (case, why) in fixtures::refused() {
            let patches = fixtures::patches(&case);
            let mut refused = false;
            for rel in fixtures::locks(&case) {
                let before = fixtures::read(&case, &format!("project/{rel}")).unwrap();
                let mut lock = OverrideLock::parse(&before, &fixtures::owned(&case)).unwrap();
                for patch in &patches {
                    let alias = fixtures::alias(&case, patch);
                    if let Err(refusal) = lock.pin(&pin_of(patch, &alias)) {
                        assert!(refusal.contains(&why), "{case}: {refusal}");
                        refused = true;
                    }
                }
                if refused {
                    assert_eq!(lock.render(), None, "{case}");
                }
            }
            assert!(refused, "{case} must be refused");
        }
    }

    /// Unpinning takes every edit back out: with the registry's resolution
    /// still to restore, the lock is the one the scan started from.
    #[test]
    fn unpinning_restores_the_plain_shape() {
        for case in fixtures::cases() {
            let patches = fixtures::patches(&case);
            for rel in fixtures::locks(&case) {
                let before = fixtures::read(&case, &format!("project/{rel}")).unwrap();
                let expected = fixtures::read(&case, &format!("expected/{rel}")).unwrap();
                let owned = fixtures::owned(&case);
                let mut lock = OverrideLock::parse(&expected, &owned).unwrap();
                let held = lock.aliased().len();
                let moved = lock
                    .unpin(&|_| true, &|importer, name| {
                        fixtures::manifest_specifier(&case, &rel, importer, name)
                    })
                    .unwrap_or_else(|why| panic!("{case} {rel}: {why}"));
                assert_eq!(moved.len(), held, "{case} {rel}");
                lock.finish().unwrap();
                lock.set_overrides(&[]);
                assert_eq!(
                    lock.render(),
                    Some(trust_shape(&before, &patches, false)),
                    "{case} {rel}"
                );
                // An importer whose manifest cannot say what it asked for
                // refuses, and the lock is left as it was.
                let direct = expected
                    .lines()
                    .any(|line| line.starts_with("        specifier: socket"));
                let mut lock = OverrideLock::parse(&expected, &owned).unwrap();
                assert_eq!(
                    lock.unpin(&|_| true, &|_, _| None).is_err(),
                    direct,
                    "{case} {rel}"
                );
                if direct {
                    assert_eq!(lock.render(), None, "{case} {rel}");
                }
            }
        }
    }

    /// One release at a time comes back out, leaving the others' edits.
    #[test]
    fn unpinning_one_release_leaves_the_rest() {
        for case in ["peers-both", "three-packages", "several"] {
            let before = fixtures::read(case, "project/pnpm-lock.yaml").unwrap();
            let expected = fixtures::read(case, "expected/pnpm-lock.yaml").unwrap();
            let patches = fixtures::patches(case);
            for gone in &patches {
                let mut lock = OverrideLock::parse(&expected, &fixtures::owned(case)).unwrap();
                lock.unpin(
                    &|pin| pin.name == gone.name && pin.version == gone.version,
                    &|importer, name| {
                        fixtures::manifest_specifier(case, "pnpm-lock.yaml", importer, name)
                    },
                )
                .unwrap();
                lock.finish().unwrap();
                let left = lock.aliased();
                assert_eq!(left.len(), patches.len() - 1, "{case}");
                lock.set_overrides(&left);
                // The same lock as routing the others over a lock whose
                // unpinned release a trust run left.
                let kept: Vec<Patch> = patches
                    .iter()
                    .filter(|p| p.uuid != gone.uuid)
                    .cloned()
                    .collect();
                let start = trust_shape(&before, std::slice::from_ref(gone), false);
                let (only, _) = apply(case, &start, &kept);
                assert_eq!(lock.render(), only.render(), "{case} without {}", gone.name);
            }
        }
    }

    /// A release moves from one registry of ours to another whole: every
    /// key, reference, specifier and override. So a patch replaced by
    /// another (its registry is named after the new patch), a name that
    /// had to be lengthened, and the shapes an unreleased build wrote (a
    /// registry per patch named by its whole UUID, with the long override
    /// value; one registry for the whole project) end as the lock pnpm
    /// writes.
    #[test]
    fn a_release_moves_between_registries_of_ours() {
        for case in ["transitive-leaf", "workspace-importers", "patched-peer"] {
            let expected = fixtures::read(case, "expected/pnpm-lock.yaml").unwrap();
            let patches = fixtures::patches(case);
            let [patch] = patches.as_slice() else {
                panic!("{case} routes one release");
            };
            let release = format!("{}@{}", patch.name, patch.version);
            let alias = fixtures::alias(case, patch);
            assert_eq!(alias, "socket-11111111", "{case}");

            // Under another name of ours: a longer one, another patch's.
            for other in ["socket-111111111111", "socket-99999999"] {
                let (moved, pinned) = apply_as(case, &expected, &patches, &|_| other.to_string());
                assert!(pinned.iter().all(|p| matches!(p, Pinned::Rewritten { .. })));
                let renamed = expected.replace(&format!("{alias}:"), &format!("{other}:"));
                assert_ne!(renamed, expected);
                assert_eq!(moved.render(), Some(renamed.clone()), "{case} {other}");
                // And back.
                let (back, _) = apply(case, &renamed, &patches);
                assert_eq!(back.render().as_deref(), Some(expected.as_str()), "{case}");
            }

            // The unreleased shape: the patch's own registry under its
            // whole UUID, and the long value in the overrides and in an
            // importer's specifier.
            let legacy = format!("socket-patch-{}", patch.uuid);
            let per_patch = expected
                .replace(
                    &format!("{release}: {alias}:{}", patch.version),
                    &format!("{release}: {legacy}:{release}"),
                )
                .replace(
                    &format!("specifier: {alias}:{}", patch.version),
                    &format!("specifier: {legacy}:{release}"),
                )
                .replace(&format!("{alias}:"), &format!("{legacy}:"));
            assert_ne!(per_patch, expected);
            assert!(!per_patch.contains(&format!("{alias}:")), "{per_patch}");
            let (lock, pinned) = apply(case, &per_patch, &patches);
            assert!(pinned.iter().all(|p| matches!(p, Pinned::Rewritten { .. })));
            assert_eq!(lock.render().as_deref(), Some(expected.as_str()), "{case}");

            // The other unreleased shape: one registry for the project,
            // which is ours as the workspace file declares it.
            let shared = expected.replace(&format!("{alias}:"), "socket:");
            let declared = format!(
                "namedRegistries:\n  socket: {}/patch/npm/~/11111111111141118111/\n",
                fixtures::ORIGIN
            );
            let owned = Owned::of(Some(&declared), &|origin| origin == fixtures::ORIGIN);
            let mut lock = OverrideLock::parse(&shared, &owned).unwrap();
            assert!(matches!(
                lock.pin(&pin_of(patch, &alias)),
                Ok(Pinned::Rewritten { .. })
            ));
            lock.finish().unwrap();
            lock.set_overrides(&[route_of(patch, alias.clone())]);
            assert_eq!(lock.render().as_deref(), Some(expected.as_str()), "{case}");
            // Undeclared, a plain `socket` is not ours to move.
            let mut lock = OverrideLock::parse(&shared, &fixtures::owned(case)).unwrap();
            assert_eq!(
                lock.pin(&pin_of(patch, &alias)),
                Ok(Pinned::Absent),
                "{case}"
            );
        }
    }

    /// A lock the edits cannot read is still asked whether it may hold
    /// something of a route: a version spelled through a registry whose
    /// name starts as ours do, in a key, a reference, a peer suffix or an
    /// `overrides:` record. A package that merely has `socket` in its name
    /// is none.
    #[test]
    fn a_lock_says_whether_it_may_hold_a_route() {
        for routed in [
            "  leaf@socket-58f14d5a:1.0.0:\n",
            "  '@scope/x@socket-58f14d5a9122:1.0.0':\n",
            "      leaf: socket-58f14d5a:1.0.0\n",
            "        specifier: socket-58f14d5a:1.0.0\n",
            "  leaf@1.0.0: socket-58f14d5a:1.0.0\n",
            "  user@1.0.0(leaf@socket-58f14d5a:1.0.0):\n",
            // The spellings of unreleased builds.
            "  leaf@socket:1.0.0:\n",
            "  leaf@1.0.0: socket-patch-58f14d5a-9122-413a-962f-f9338960eedf:leaf@1.0.0\n",
            "  '@scope/x@1.0.0': 'socket-2:@scope/x@1.0.0'\n",
        ] {
            assert!(names_a_route(routed), "{routed}");
        }
        for plain in [
            "  '@socketsecurity/lib@1.0.0':\n",
            "  socket.io@4.7.5:\n",
            "  socket@1.0.0:\n",
            "      socket: 1.0.0\n",
            "      socket-io:\n        specifier: ^1.0.0\n",
            "  websocket@1.0.0:\n",
            "      rsocket-core: 0.0.27\n",
            "  leaf@1.0.0:\n    resolution: {integrity: sha512-socket==}\n",
        ] {
            assert!(!names_a_route(plain), "{plain}");
        }
    }

    /// The upstream registry's remark on a release goes with the routing,
    /// whole: a message of several lines is a block scalar, and all of its
    /// lines go (the `deprecated-block` fixture is what pnpm writes). A
    /// message of several paragraphs, or one that keeps its trailing line
    /// breaks, is not an entry in one run of lines; no entry of such a
    /// lock is moved, and the lock is refused with the reason.
    #[test]
    fn a_remark_of_several_lines_goes_whole_or_the_lock_is_refused() {
        let lock = |remark: &str| {
            format!(
                "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      old:\n        \
                 specifier: 1.0.0\n        version: 1.0.0\n\npackages:\n\n  old@1.0.0:\n    \
                 resolution: {{integrity: sha512-UPSTREAM==}}\n    deprecated: {remark}\n\n\
                 snapshots:\n\n  old@1.0.0: {{}}\n"
            )
        };
        let owned = Owned::default();
        let pin = AliasPin {
            name: "old",
            version: "1.0.0",
            alias: "socket-11111111",
            integrity: "sha512-PATCHED==",
            tarball: "https://patch.test/patch/npm/old/1.0.0/tok/11111111-1111-4111-8111-111111111111/old-1.0.0.tgz",
        };
        for remark in [
            "use something else",
            "|-\n      use something else\n      second line: with a colon\n        indented third",
        ] {
            let mut routed = OverrideLock::parse(&lock(remark), &owned).expect("one run of lines");
            assert!(matches!(routed.pin(&pin), Ok(Pinned::Rewritten { .. })));
            routed.finish().unwrap();
            let text = routed.render().unwrap();
            assert!(
                text.contains(
                    "packages:\n\n  old@socket-11111111:1.0.0:\n    resolution: {integrity: \
                     sha512-PATCHED==, tarball: https://patch.test/patch/npm/old/1.0.0/tok/\
                     11111111-1111-4111-8111-111111111111/old-1.0.0.tgz}\n\nsnapshots:\n"
                ),
                "{remark}:\n{text}"
            );
            for left in ["deprecated", "something else", "indented third"] {
                assert!(!text.contains(left), "{left}:\n{text}");
            }
        }
        for (remark, section) in [
            // Two paragraphs, as pnpm writes them.
            (
                "|\n      first paragraph\n\n      second paragraph",
                "packages",
            ),
            // Trailing line breaks kept.
            ("|+\n      ends with line breaks\n", "packages"),
        ] {
            let refused = OverrideLock::parse(&lock(remark), &owned)
                .err()
                .unwrap_or_else(|| panic!("{remark} must be refused"));
            assert_eq!(
                refused,
                format!(
                    "has an entry under `{section}:` whose text runs past an empty line (a \
                     block of several paragraphs)"
                )
            );
        }
    }

    /// A measurement, not a check: what the lock edits cost on a lock
    /// from the environment, for each release named there.
    ///
    /// ```text
    /// SOCKET_PATCH_LOCK_BENCH=/path/to/pnpm-lock.yaml \
    /// SOCKET_PATCH_LOCK_BENCH_RELEASES='react@19.1.1 debug@4.4.3' \
    ///   cargo test --release -p socket-patch-core --lib -- --ignored --nocapture \
    ///   the_lock_edits_are_timed
    /// ```
    ///
    /// Each release is routed on its own over a fresh parse of the lock
    /// (parse, pin, record the override, settle, render) and taken back
    /// out of the result; a release the edits refuse says why.
    #[test]
    #[ignore = "a measurement: set SOCKET_PATCH_LOCK_BENCH and SOCKET_PATCH_LOCK_BENCH_RELEASES"]
    fn the_lock_edits_are_timed_on_a_lock_from_the_environment() {
        use std::time::Instant;
        let (Ok(path), Ok(releases)) = (
            std::env::var("SOCKET_PATCH_LOCK_BENCH"),
            std::env::var("SOCKET_PATCH_LOCK_BENCH_RELEASES"),
        ) else {
            return;
        };
        let text = std::fs::read_to_string(&path).expect("the lock to measure");
        let owned = Owned::default();
        println!("lock: {} lines, {} bytes", text.lines().count(), text.len());
        for release in releases.split_whitespace() {
            let (name, version) = release.rsplit_once('@').expect("name@version");
            let started = Instant::now();
            let mut lock = match OverrideLock::parse(&text, &owned) {
                Ok(lock) => lock,
                Err(why) => {
                    println!("{release}: the lock {why}");
                    return;
                }
            };
            let parsed = started.elapsed();
            let tarball = format!(
                "https://patch.test/patch/npm/{name}/{version}/tok/11111111-1111-4111-8111-111111111111/x-{version}.tgz"
            );
            let pin = AliasPin {
                name,
                version,
                alias: "socket-11111111",
                integrity: "sha512-PATCHED==",
                tarball: &tarball,
            };
            let before = Instant::now();
            let pinned = lock.pin(&pin);
            let pinning = before.elapsed();
            let touched = lock.touched.len();
            let before = Instant::now();
            let route = HostedOverride {
                name: name.to_string(),
                version: version.to_string(),
                alias: "socket-11111111".to_string(),
            };
            lock.set_overrides(std::slice::from_ref(&route));
            let settled = lock.finish();
            let finishing = before.elapsed();
            let before = Instant::now();
            let rendered = lock.render();
            let rendering = before.elapsed();
            println!(
                "{release}: pin {pinned:?} ({} entries touched), settle {settled:?}; parse {parsed:?}, \
                 pin {pinning:?}, settle {finishing:?}, render {rendering:?}, total {:?}",
                touched,
                started.elapsed()
            );
            let Some(routed) = rendered.filter(|_| settled.is_ok()) else {
                continue;
            };
            let started = Instant::now();
            let mut back = OverrideLock::parse(&routed, &owned).expect("the routed lock");
            let moved = back.unpin(&|_| true, &|_, _| Some(version.to_string()));
            let settled = back.finish();
            back.set_overrides(&[]);
            let plain = back.render();
            println!(
                "{release}: back out {:?} (moved {:?}, settle {settled:?}, {} bytes)",
                started.elapsed(),
                moved.map(|pins| pins.len()),
                plain.map_or(0, |text| text.len())
            );
        }
    }

    #[test]
    fn a_release_the_lock_does_not_hold_is_absent() {
        let case = "transitive-leaf";
        let before = fixtures::read(case, "project/pnpm-lock.yaml").unwrap();
        let mut lock = OverrideLock::parse(&before, &fixtures::owned(case)).unwrap();
        let mut patch = fixtures::patches(case).remove(0);
        patch.version = "9.9.9".into();
        assert_eq!(
            lock.pin(&pin_of(&patch, "socket-11111111")),
            Ok(Pinned::Absent)
        );
        patch.name = "lea".into();
        patch.version = "1.0.0".into();
        assert_eq!(
            lock.pin(&pin_of(&patch, "socket-11111111")),
            Ok(Pinned::Absent)
        );
        assert_eq!(lock.render(), None);
    }

    /// A registry under a name of hosted mode's shape that the project
    /// declares for itself is the user's: a key that names it is not a
    /// routed release, and nothing of it moves.
    #[test]
    fn the_users_registry_is_not_ours() {
        let case = "user-registry";
        let expected = fixtures::read(case, "expected/pnpm-lock.yaml").unwrap();
        let owned = fixtures::owned(case);
        assert!(!owned.alias("socket") && !owned.alias("socket-11111111"));
        assert!(owned.alias("socket-111111111111"));
        assert!(
            expected.contains("leaf@socket-111111111111:1.0.0"),
            "{expected}"
        );
        // The same lock, had either registry of the user's served the
        // release.
        for theirs in ["socket-11111111:", "socket:"] {
            let users = expected.replace("socket-111111111111:", theirs);
            let mut lock = OverrideLock::parse(&users, &owned).unwrap();
            assert!(lock.aliased().is_empty(), "{theirs}");
            assert!(lock.routed_overrides().is_empty(), "{theirs}");
            assert_eq!(lock.unpin(&|_| true, &|_, _| None), Ok(Vec::new()));
            lock.set_overrides(&[]);
            assert_eq!(lock.render(), None, "{theirs}");
        }
        let users = expected.replace("socket-111111111111:", "socket:");
        let mut lock = OverrideLock::parse(&users, &owned).unwrap();
        assert!(lock.aliased().is_empty());
        assert!(lock.routed_overrides().is_empty());
        assert_eq!(lock.unpin(&|_| true, &|_, _| None), Ok(Vec::new()));
        lock.set_overrides(&[]);
        assert_eq!(lock.render(), None);
        let ours = OverrideLock::parse(&expected, &owned).unwrap();
        assert_eq!(ours.aliased().len(), 1);
        assert_eq!(ours.routed_overrides(), ours.aliased());
    }

    /// Locks the override edits were not captured against are refused, and
    /// left as they were.
    #[test]
    fn shapes_outside_the_fixtures_are_refused() {
        let case = "workspace-importers";
        let patch = fixtures::patches(case).remove(0);
        let before = fixtures::read(case, "project/pnpm-lock.yaml").unwrap();
        let owned = fixtures::owned(case);
        let refused = |lock: String, why: &str| {
            let mut lock = OverrideLock::parse(&lock, &owned).unwrap();
            let refusal = lock.pin(&pin_of(&patch, "socket-11111111")).expect_err(why);
            assert!(refusal.contains(why), "{why}: {refusal}");
            assert_eq!(lock.render(), None, "{why}");
        };
        // An importer that asks for the release through something pnpm
        // would not override, or through a catalog.
        for spec in ["latest", "npm:leaf@1.0.0", "catalog:", "workspace:*"] {
            refused(
                before.replacen("specifier: ^1.0.0", &format!("specifier: {spec}"), 1),
                "which pnpm would not override",
            );
        }
        // Another version locked through a range that admits the release.
        refused(
            before.replacen(
                "specifier: ~1.0.0\n        version: 1.0.0",
                "specifier: '>=1.0.0'\n        version: 2.0.0",
                1,
            ),
            "which may admit 1.0.0",
        );
        // An npm alias of the release.
        refused(
            before.replacen("      leaf: 1.0.0", "      alias: leaf@1.0.0", 1),
            "under another name",
        );
        // A copy patched with `pnpm patch`.
        refused(
            before.replace("  leaf@1.0.0: {}", "  leaf@1.0.0(patch_hash=abc): {}"),
            "a patched copy",
        );
        // A resolution that is not a registry tarball.
        refused(
            before.replacen(
                "  leaf@1.0.0:\n    resolution: {integrity:",
                "  leaf@1.0.0:\n    resolution: {type: directory, integrity:",
                1,
            ),
            "more than an integrity and a tarball",
        );
        // Another version of the same package locked through a range that
        // leaves the release out is no obstacle.
        let other = before.replacen(
            "specifier: ~1.0.0\n        version: 1.0.0",
            "specifier: ^2.0.0\n        version: 2.0.0",
            1,
        );
        let mut lock = OverrideLock::parse(&other, &owned).unwrap();
        assert!(matches!(
            lock.pin(&pin_of(&patch, "socket-11111111")),
            Ok(Pinned::Rewritten { .. })
        ));

        for (text, why) in [
            ("lockfileVersion: '6.0'\n", "not a lockfileVersion 9 lock"),
            (
                "lockfileVersion: '9.0'\r\n\nimporters:\n",
                "mixes CRLF and LF",
            ),
            (
                "lockfileVersion: '9.0'\n\npackages:\n\n  a@1.0.0:\n    resolution: {integrity: sha512-x}\n",
                "no `snapshots:`",
            ),
        ] {
            let refusal = OverrideLock::parse(text, &owned).expect_err(why);
            assert!(refusal.contains(why), "{refusal}");
        }
    }

    /// The overrides section follows the wanted set: ours come and go, the
    /// user's stay, and an emptied section leaves with its blank line.
    #[test]
    fn the_overrides_section_holds_exactly_the_wanted_pins() {
        let case = "user-overrides";
        let expected = fixtures::read(case, "expected/pnpm-lock.yaml").unwrap();
        let owned = fixtures::owned(case);
        let mut lock = OverrideLock::parse(&expected, &owned).unwrap();
        assert_eq!(
            lock.overrides(),
            vec![
                ("other".to_string(), "1.0.0".to_string()),
                (
                    "leaf@1.0.0".to_string(),
                    "socket-11111111:1.0.0".to_string()
                ),
            ]
        );
        assert_eq!(lock.routed_overrides(), routes(case));
        lock.set_overrides(&[]);
        let rendered = lock.render().unwrap();
        assert!(rendered.contains("overrides:\n  other: 1.0.0\n\nimporters:"));
        assert!(!rendered.contains("  leaf@1.0.0: socket"));

        // No section of its own: one is created before `importers:`, and
        // goes again with the last pin.
        let plain = fixtures::read("scoped-direct", "project/pnpm-lock.yaml").unwrap();
        let mut lock = OverrideLock::parse(&plain, &owned).unwrap();
        lock.set_overrides(&routes("scoped-direct"));
        let with = lock.render().unwrap();
        assert!(
            with.contains(
                "\noverrides:\n  '@scope/direct@1.0.0': socket-11111111:1.0.0\n\nimporters:\n"
            ),
            "{with}"
        );
        let mut lock = OverrideLock::parse(&with, &owned).unwrap();
        lock.set_overrides(&[]);
        assert_eq!(lock.render(), Some(plain));
    }

    #[test]
    fn a_manifest_says_what_an_importer_asks_for() {
        let manifest = r#"{"dependencies":{"a":"^1.0.0","both":"1.0.0"},
            "devDependencies":{"b":"~2.0.0","both":"1.0.0","split":"1.0.0"},
            "optionalDependencies":{"c":"3.0.0","split":"2.0.0"},"peerDependencies":{"d":"*"}}"#;
        for (name, want) in [
            ("a", Some("^1.0.0")),
            ("b", Some("~2.0.0")),
            ("c", Some("3.0.0")),
            ("both", Some("1.0.0")),
            // Two fields that disagree, a peer, an absent package.
            ("split", None),
            ("d", None),
            ("e", None),
        ] {
            assert_eq!(
                manifest_specifier(manifest, name).as_deref(),
                want,
                "{name}"
            );
        }
        assert_eq!(manifest_specifier("not json", "a"), None);
    }
}
