//! The two maps of a pnpm-workspace.yaml hosted mode routes patched
//! packages through, as it reads and edits them.
//!
//! pnpm >= 11 verifies every lock entry that records a tarball URL against
//! a registry's version document. The patch service answers such a
//! document for each patch, under the directory the patch's tarball is
//! served from: `GET <address><name>` is the one-version document of the
//! patched package, and any other name there is a 404. Each address is
//! fixed for the life of its patch, so what it answers can be cached.
//! Hosted mode declares the address of each patch as a named registry and
//! overrides the patched release with it, which makes pnpm resolve the
//! package there whenever it resolves at all (`pnpm add`, `update`,
//! `dedupe`) and verify the lock entry against it:
//!
//! ```yaml
//! namedRegistries:
//!   socket-58f14d5a: https://<patch server>/patch/npm/<name>/<version>/<token>/<patch uuid>/
//! overrides:
//!   '<name>@<version>': 'socket-58f14d5a:<version>'
//! ```
//!
//! The lock mirrors both ([`super::registry_alias`]). An address answers
//! for its one package only, so it is never declared as a scope or default
//! registry.
//!
//! A registry is named after its patch: `socket-` and the first eight hex
//! digits of the patch UUID, four more at a time while that name is taken
//! ([`Owned::name_for`]). It is ours by that name together with its
//! address, the serve directory of a patch whose UUID starts with those
//! digits, on a patch server ([`Owned`]). An override is ours when it
//! routes its release to one of those. Everything else is the user's and
//! is never rewritten or removed. Edits are line splices
//! ([`super::workspace`]), never a YAML round trip, so every other byte of
//! the file and its line endings stay as they are; a shape a splice cannot
//! extend safely is refused with its reason.
//!
//! Pure text in, answers out; the callers own the reads and writes.

use std::collections::{BTreeMap, BTreeSet};

use super::lines::parse_key_line;
use super::workspace::{
    block_insert_point, block_section_bounds, is_keyless, splice_lines, strip_comment,
    strip_keyless_splice, top_level_key, yaml_scalar, PACKAGES_SCAFFOLD,
};
use crate::patch::path_safety::is_canonical_uuid;
use crate::utils::line_endings::{eol_eq, terminator};

/// The pnpm-workspace.yaml key of the registry map. pnpm 12 also reads it
/// as `registries: {<url>: {prefix: …}}`, which pnpm 10 cannot parse, so
/// that spelling is never written.
pub(crate) const NAMED_REGISTRIES: &str = "namedRegistries";

/// The pnpm-workspace.yaml key of the override map.
pub(crate) const OVERRIDES: &str = "overrides";

/// What every registry name of ours starts with (a lock key search
/// prefix).
pub(crate) const ALIAS_PREFIX: &str = "socket";

/// What a registry name starts with, before the digits of its patch.
const ALIAS_HEAD: &str = "socket-";

/// How many leading hex digits of the patch UUID a registry name carries:
/// the fewest, how many more at a time while the name is taken, and all.
const ALIAS_DIGITS: (usize, usize, usize) = (8, 4, 32);

/// The indent of the entries hosted mode writes.
const ENTRY_INDENT: usize = 2;

/// The 32 hex digits of a canonical UUID.
fn uuid_digits(uuid: &str) -> String {
    uuid.replace('-', "")
}

/// The digits of a registry name of ours: `socket-` and 8 to 32 lowercase
/// hex digits, the leading digits of the UUID of the patch it serves.
fn alias_digits(alias: &str) -> Option<&str> {
    let digits = alias.strip_prefix(ALIAS_HEAD)?;
    ((ALIAS_DIGITS.0..=ALIAS_DIGITS.2).contains(&digits.len())
        && digits
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
    .then_some(digits)
}

/// The patch UUID of a registry name an unreleased build of this feature
/// gave a patch (`socket-patch-<patch uuid>`). Never written; the next
/// scan renames it.
fn legacy_patch_uuid(alias: &str) -> Option<&str> {
    alias
        .strip_prefix("socket-patch-")
        .filter(|uuid| is_canonical_uuid(uuid))
}

/// Whether `alias` is a name an unreleased build of this feature gave the
/// one registry of a whole project: `socket`, `socket-patch`, and either
/// with `-2`, `-3`, …. Never written; ours only where the file declares it
/// at such a registry's address ([`legacy_set_origin`]).
fn is_legacy_set_alias(alias: &str) -> bool {
    ["socket-patch", "socket"].iter().any(|base| {
        let Some(rest) = alias.strip_prefix(base) else {
            return false;
        };
        let Some(part) = rest.strip_prefix('-') else {
            return rest.is_empty();
        };
        !part.starts_with('0')
            && part.len() <= 4
            && part.bytes().all(|b| b.is_ascii_digit())
            && part.parse::<usize>().is_ok_and(|part| part >= 2)
    })
}

/// Whether `alias` has the shape of a name hosted mode gives a registry
/// today (not one of an unreleased build).
pub(crate) fn is_current_alias(alias: &str) -> bool {
    alias_digits(alias).is_some()
}

/// Whether `alias` has the shape of a name hosted mode gives a registry,
/// or gave one in an unreleased build.
pub(crate) fn is_alias_name(alias: &str) -> bool {
    alias_digits(alias).is_some()
        || legacy_patch_uuid(alias).is_some()
        || is_legacy_set_alias(alias)
}

/// The version of a lock's version token, which a release routed through
/// a registry of ours spells `<alias>:<version>`.
///
/// A reader has the lock alone to go by, so only the name hosted mode
/// gives a registry today counts ([`is_current_alias`]). The names an
/// unreleased build used (`socket`, `socket-patch`, …) are as likely a
/// registry of the project's own, whose `leaf@socket:1.0.0` is not npm's
/// leaf@1.0.0: they are ours only where the workspace file proves it
/// ([`Owned`]), which the hosted run checks before it respells such keys.
pub(crate) fn strip_alias(token: &str) -> &str {
    token
        .split_once(':')
        .filter(|(registry, _)| is_current_alias(registry))
        .map_or(token, |(_, version)| version)
}

/// `(origin, path)` of an `http(s)` URL with a plain host: the origin is
/// `http(s)://<host>[:<port>]`, the path starts at its first `/`.
fn split_origin(url: &str) -> Option<(&str, &str)> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let (authority, path) = rest.split_at(rest.find('/')?);
    let plain_host = !authority.is_empty()
        && authority
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'));
    plain_host.then(|| (&url[..url.len() - path.len()], path))
}

/// A registry address: the directory a patch server serves one patch
/// from, `<origin>/…/<patch uuid>/`
/// (`<origin>/patch/npm/<name>/<version>/<token>/<patch uuid>/` on
/// Socket's). The reference result of a patch carries it, and it is
/// written as returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Address {
    /// `http(s)://<host>[:<port>]`.
    pub(crate) origin: String,
    /// The patch served there: the directory's own name.
    pub(crate) uuid: String,
}

impl Address {
    /// Read `url` as a registry address (the final `/` may be missing, as
    /// pnpm reads it either way).
    pub(crate) fn parse(url: &str) -> Option<Address> {
        let (origin, path) = split_origin(url)?;
        let clean = !path.contains(|c: char| c.is_whitespace() || matches!(c, '?' | '#'));
        let uuid = path.strip_suffix('/').unwrap_or(path).rsplit('/').next()?;
        (clean && is_canonical_uuid(uuid)).then(|| Address {
            origin: origin.to_string(),
            uuid: uuid.to_string(),
        })
    }

    /// Whether `tarball` is a file of the directory `url` (an address as
    /// written) names: what pnpm verifies a lock entry by.
    pub(crate) fn serves(url: &str, tarball: &str) -> bool {
        let directory = url.strip_suffix('/').unwrap_or(url);
        tarball
            .strip_prefix(directory)
            .and_then(|rest| rest.strip_prefix('/'))
            .is_some_and(|file| !file.is_empty() && !file.contains('/'))
    }
}

/// The origin of the address an unreleased build declared for the one
/// registry of a whole project (`<origin>/patch/npm/~/<member>.<member>/`).
fn legacy_set_origin(url: &str) -> Option<&str> {
    let (origin, path) = split_origin(url)?;
    let members = path.strip_prefix("/patch/npm/~/")?;
    let members = members.strip_suffix('/').unwrap_or(members);
    let is_member = |member: &str| {
        (20..=32).contains(&member.len())
            && member
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    };
    members.split('.').all(is_member).then_some(origin)
}

/// A hosted override: the release `name@version` routed to the registry
/// `alias`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct HostedOverride {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) alias: String,
}

impl HostedOverride {
    /// The override key, `name@version`.
    pub(crate) fn key(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }

    /// The override value, `<alias>:<version>`: the shortest spelling pnpm
    /// takes (the package is the key's).
    pub(crate) fn value(&self) -> String {
        format!("{}:{}", self.alias, self.version)
    }
}

/// Which registries of a project are hosted mode's.
///
/// A registry under a name of hosted mode's shape is the USER's when the
/// workspace file declares it at an address that is not the serve
/// directory, on a patch server, of a patch whose UUID the name's digits
/// start. Any other use of such a name is ours: the one we declare, and a
/// name left in an override or a lock key by a run whose declaration is
/// gone. The one registry of a whole project an unreleased build declared
/// (`socket`, `socket-patch`, `-N`) is ours only as declared, at that
/// build's kind of address: on its own such a name is as likely the
/// user's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Owned {
    users: BTreeSet<String>,
    legacy_sets: BTreeSet<String>,
}

impl Owned {
    /// Read the registries of a pnpm-workspace.yaml (`None` when the
    /// project has none). `patch_server` answers whether an origin
    /// (`http(s)://host[:port]`) is one.
    pub(crate) fn of(workspace: Option<&str>, patch_server: &dyn Fn(&str) -> bool) -> Owned {
        let mut owned = Owned::default();
        for (alias, url) in workspace.map(declared).unwrap_or_default() {
            let served = |ours: &dyn Fn(&Address) -> bool| {
                Address::parse(&url)
                    .is_some_and(|address| patch_server(&address.origin) && ours(&address))
            };
            if is_legacy_set_alias(&alias) {
                if legacy_set_origin(&url).is_some_and(patch_server) {
                    owned.legacy_sets.insert(alias);
                }
            } else if let Some(digits) = alias_digits(&alias) {
                if !served(&|address| uuid_digits(&address.uuid).starts_with(digits)) {
                    owned.users.insert(alias);
                }
            } else if let Some(uuid) = legacy_patch_uuid(&alias) {
                if !served(&|address| address.uuid == uuid) {
                    owned.users.insert(alias);
                }
            }
        }
        owned
    }

    /// Whether the registry `alias` is hosted mode's.
    pub(crate) fn alias(&self, alias: &str) -> bool {
        if is_legacy_set_alias(alias) {
            return self.legacy_sets.contains(alias);
        }
        is_alias_name(alias) && !self.users.contains(alias)
    }

    /// The override entry `key: value` when it is one of ours:
    /// `name@version: <alias>:version`, or the long spelling an unreleased
    /// build wrote (`<alias>:name@version`).
    pub(crate) fn route(&self, key: &str, value: &str) -> Option<HostedOverride> {
        let (alias, target) = value.split_once(':')?;
        let at = key.rfind('@').filter(|&at| at > 0 && at + 1 < key.len())?;
        let (name, version) = (&key[..at], &key[at + 1..]);
        (self.alias(alias) && (target == version || target == key)).then(|| HostedOverride {
            name: name.to_string(),
            version: version.to_string(),
            alias: alias.to_string(),
        })
    }

    /// The name of the registry of the patch `uuid`: `socket-` and the
    /// first eight hex digits of the UUID, lengthened four digits at a
    /// time while another patch of the project (`others`, by UUID) starts
    /// with the same digits or the user declares that name for something
    /// else. `None` when every length is taken.
    pub(crate) fn name_for(&self, uuid: &str, others: &BTreeSet<&str>) -> Option<String> {
        let digits = uuid_digits(uuid);
        let (first, step, all) = ALIAS_DIGITS;
        (first..=all.min(digits.len()))
            .step_by(step)
            .map(|length| &digits[..length])
            .find(|head| {
                !self.users.contains(&format!("{ALIAS_HEAD}{head}"))
                    && !others
                        .iter()
                        .any(|other| *other != uuid && uuid_digits(other).starts_with(head))
            })
            .map(|head| format!("{ALIAS_HEAD}{head}"))
    }
}

/// Which of the two maps an entry is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MapKind {
    /// `namedRegistries`: alias → registry address.
    Registry,
    /// `overrides`: `name@version` → `<alias>:version`.
    Override,
}

impl MapKind {
    const BOTH: [MapKind; 2] = [MapKind::Registry, MapKind::Override];

    fn key(self) -> &'static str {
        match self {
            MapKind::Registry => NAMED_REGISTRIES,
            MapKind::Override => OVERRIDES,
        }
    }

    /// Whether the entry is one hosted mode owns.
    fn ours(self, owned: &Owned, key: &str, value: &str) -> bool {
        match self {
            MapKind::Registry => owned.alias(key),
            MapKind::Override => owned.route(key, value).is_some(),
        }
    }

    /// An entry line as hosted mode writes it.
    fn line(self, pad: &str, key: &str, value: &str) -> String {
        match self {
            MapKind::Registry => format!("{pad}{key}: {value}"),
            MapKind::Override => format!("{pad}'{key}': '{value}'"),
        }
    }

    /// The value as hosted mode spells it after a key that stays.
    fn value(self, value: &str) -> String {
        match self {
            MapKind::Registry => value.to_string(),
            MapKind::Override => format!("'{value}'"),
        }
    }
}

/// What the workspace file must hold for the hosted pins of the governing
/// locks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Wanted {
    /// Alias → registry address.
    pub(crate) registries: BTreeMap<String, String>,
    /// `name@version` → `<alias>:version`.
    pub(crate) overrides: BTreeMap<String, String>,
}

impl Wanted {
    /// Route one release.
    pub(crate) fn route(&mut self, pin: &HostedOverride) {
        self.overrides.insert(pin.key(), pin.value());
    }

    fn map(&self, kind: MapKind) -> &BTreeMap<String, String> {
        match kind {
            MapKind::Registry => &self.registries,
            MapKind::Override => &self.overrides,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.registries.is_empty() && self.overrides.is_empty()
    }
}

/// One entry a plan adds (`from` is `None`), rewrites, or removes (`to` is
/// `None`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Change {
    pub(crate) map: MapKind,
    pub(crate) key: String,
    pub(crate) from: Option<String>,
    pub(crate) to: Option<String>,
}

/// The planned pnpm-workspace.yaml edit.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Plan {
    /// No workspace file: create it (the root-only `packages` scaffold
    /// plus the maps).
    Create(String, Vec<Change>),
    /// A file with no key at all: the root-only `packages` scaffold goes
    /// in with the maps (pnpm 8.x–10.4 refuse a file holding a key but no
    /// `packages`).
    Scaffold(String, Vec<Change>),
    /// A file with keys: a map is added, or its entries change.
    Edit(String, Vec<Change>),
    /// Nothing to write.
    InSync,
    /// A shape a line splice cannot extend; the reason completes
    /// "pnpm-workspace.yaml …".
    Unsupported(String),
}

/// One entry of a map.
struct Entry {
    line: usize,
    key: String,
    /// The key as the file spells it (quotes included).
    repr: String,
    value: String,
}

/// A block-style map of a file.
struct Section {
    header: usize,
    /// The first line after the section.
    end: usize,
    indent: usize,
    entries: Vec<Entry>,
}

enum Located {
    Absent,
    Block(Section),
    Unsupported(String),
}

fn bare(line: &str) -> &str {
    line.strip_suffix('\r').unwrap_or(line)
}

/// The file's `name` map, when it is a block mapping of one-line
/// `key: value` entries.
fn locate(lines: &[String], name: &str) -> Located {
    let heads: Vec<(usize, bool)> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, line)| {
            top_level_key(line)
                .filter(|(key, _)| key == name)
                .map(|(_, value)| (i, value.is_empty()))
        })
        .collect();
    let header = match heads.as_slice() {
        [] => return Located::Absent,
        [(header, true)] => *header,
        [(_, false)] => {
            return Located::Unsupported(format!(
                "sets `{name}` on one line (a flow-style map or a scalar)"
            ))
        }
        _ => {
            return Located::Unsupported(format!("sets `{name}` more than once"));
        }
    };
    let Some((_, end)) = block_section_bounds(lines, name) else {
        return Located::Absent;
    };
    let unreadable = || {
        Located::Unsupported(format!(
            "holds a `{name}` line that is not a one-line `key: value` entry"
        ))
    };
    let mut indent = None;
    let mut entries = Vec::new();
    for (i, raw) in lines.iter().enumerate().take(end).skip(header + 1) {
        let line = bare(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let width = *indent.get_or_insert(line.len() - line.trim_start_matches(' ').len());
        if width == 0 {
            return unreadable();
        }
        let Some((key, repr, rest)) = parse_key_line(line, width) else {
            return unreadable();
        };
        let value = strip_comment(rest).trim();
        // An empty value is a nested block or a null, and `|` / `>` open a
        // block scalar: none is a one-line entry.
        if value.is_empty() || value.starts_with(['|', '>']) {
            return unreadable();
        }
        entries.push(Entry {
            line: i,
            key: key.to_string(),
            repr: repr.to_string(),
            value: yaml_scalar(value),
        });
    }
    Located::Block(Section {
        header,
        end,
        indent: indent.unwrap_or(ENTRY_INDENT),
        entries,
    })
}

/// The `(key, value)` entries of one block-style map of a
/// pnpm-workspace.yaml, the user's included. Empty for a missing map or
/// one this reader cannot follow.
fn entries_of(text: &str, kind: MapKind) -> Vec<(String, String)> {
    let lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    match locate(&lines, kind.key()) {
        Located::Block(section) => section
            .entries
            .into_iter()
            .map(|e| (e.key, e.value))
            .collect(),
        Located::Absent | Located::Unsupported(_) => Vec::new(),
    }
}

/// The `(alias, address)` entries of the `namedRegistries` map.
pub(crate) fn declared(text: &str) -> Vec<(String, String)> {
    entries_of(text, MapKind::Registry)
}

/// The registries `text` (a pnpm-workspace.yaml) declares in the shape of
/// a patch's registry, on hosts `patch_server` does not answer for: each
/// host's origin with how many, by origin. A registry counts when its name
/// is `socket-` and hex digits and its address is a directory named by a
/// UUID those digits start, the way hosted mode writes one.
///
/// Such a registry is the user's as far as a run can tell ([`Owned`]), and
/// is left alone. On a patch server the run was not told of it is in fact
/// hosted mode's, so a command that tidies from the files alone says which
/// hosts it passed over. An origin is all it may say: the rest of the
/// address holds a grant's token.
pub(crate) fn on_unknown_hosts(
    text: &str,
    patch_server: &dyn Fn(&str) -> bool,
) -> Vec<(String, usize)> {
    let mut hosts: BTreeMap<String, usize> = BTreeMap::new();
    for (alias, url) in declared(text) {
        let (Some(digits), Some(address)) = (alias_digits(&alias), Address::parse(&url)) else {
            continue;
        };
        if uuid_digits(&address.uuid).starts_with(digits) && !patch_server(&address.origin) {
            *hosts.entry(address.origin).or_default() += 1;
        }
    }
    hosts.into_iter().collect()
}

/// The releases `text` (a pnpm-workspace.yaml) routes through a registry of
/// ours that it declares at a registry address: each override of ours, with
/// the address of the registry it names, as written.
pub(crate) fn routes(text: &str, owned: &Owned) -> Vec<(HostedOverride, String)> {
    let registries = declared(text);
    entries_of(text, MapKind::Override)
        .into_iter()
        .filter_map(|(key, value)| {
            let route = owned.route(&key, &value)?;
            let (_, address) = registries.iter().find(|(alias, _)| *alias == route.alias)?;
            Address::parse(address)?;
            Some((route, address.clone()))
        })
        .collect()
}

/// Whether the file holds an entry of ours in either map.
pub(crate) fn holds_ours(text: &str, owned: &Owned) -> bool {
    MapKind::BOTH.into_iter().any(|kind| {
        entries_of(text, kind)
            .iter()
            .any(|(key, value)| kind.ours(owned, key, value))
    })
}

/// The package an override key targets: `[@scope/]name` of the last
/// segment of a `parent>child` chain, its version range dropped.
fn override_target(key: &str) -> &str {
    let last = key.rsplit('>').next().unwrap_or(key).trim();
    let at = last
        .get(1..)
        .and_then(|rest| rest.find('@'))
        .map_or(last.len(), |at| at + 1);
    &last[..at]
}

/// The user's override that would compete with a hosted one for one of
/// `packages` (by name): its key, or why the map cannot be read. pnpm
/// applies one override per dependency, the most specific that matches, so
/// a hosted override beside a user's for the same package would either
/// lose or take the user's place.
pub(crate) fn competing_override(
    text: &str,
    owned: &Owned,
    packages: &BTreeSet<&str>,
) -> Option<String> {
    let lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    let section = match locate(&lines, OVERRIDES) {
        Located::Absent => return None,
        Located::Unsupported(why) => return Some(why),
        Located::Block(section) => section,
    };
    section
        .entries
        .iter()
        .filter(|e| !MapKind::Override.ours(owned, &e.key, &e.value))
        .find(|e| packages.contains(override_target(&e.key)))
        .map(|e| format!("overrides `{}` itself", e.key))
}

/// The lines of the maps holding `wanted`: each map's key, then one entry
/// per line.
pub(crate) fn section_lines(wanted: &Wanted) -> Vec<String> {
    let pad = " ".repeat(ENTRY_INDENT);
    let mut out = Vec::new();
    for kind in MapKind::BOTH {
        let map = wanted.map(kind);
        if map.is_empty() {
            continue;
        }
        out.push(format!("{}:", kind.key()));
        out.extend(map.iter().map(|(key, value)| kind.line(&pad, key, value)));
    }
    out
}

fn added(wanted: &Wanted) -> Vec<Change> {
    MapKind::BOTH
        .into_iter()
        .flat_map(|kind| {
            wanted.map(kind).iter().map(move |(key, value)| Change {
                map: kind,
                key: key.clone(),
                from: None,
                to: Some(value.clone()),
            })
        })
        .collect()
}

/// Remove line `at`. When it was the file's unterminated last line, the
/// line before it becomes that: in a CRLF file it gives its `\r` back (the
/// inverse of [`splice_lines`] appending after an unterminated line).
fn remove_line(lines: &mut Vec<String>, at: usize, eol: &str) {
    lines.remove(at);
    if eol == "\r\n" && at == lines.len() && at > 0 {
        if let Some(stripped) = lines[at - 1].strip_suffix('\r') {
            lines[at - 1] = stripped.to_string();
        }
    }
}

/// Decide how to make a pnpm-workspace.yaml (`existing`; `None` when the
/// project has none) hold exactly `wanted` among the entries of ours.
///
/// Entries that are not ours (`owned`) are the user's and stay byte for
/// byte. An entry of ours already as wanted stays too, one with another
/// value is rewritten in place, and one that is not wanted is removed: it
/// serves no lock any more. A map left with nothing in it loses its key.
pub(crate) fn plan(existing: Option<&str>, wanted: &Wanted, owned: &Owned) -> Plan {
    let scaffolded = || -> Vec<String> {
        PACKAGES_SCAFFOLD
            .iter()
            .map(|line| line.to_string())
            .chain(section_lines(wanted))
            .collect()
    };
    let Some(text) = existing else {
        if wanted.is_empty() {
            return Plan::InSync;
        }
        return Plan::Create(format!("{}\n", scaffolded().join("\n")), added(wanted));
    };
    let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    // The lines added below end as the file's own lines do.
    let eol = terminator(text);
    // Refused when the document is not a single block mapping, so the scan
    // for the maps below is meaningful.
    let anchor = match block_insert_point(&lines) {
        Ok(anchor) => anchor,
        Err(why) => return Plan::Unsupported(why),
    };
    if is_keyless(text) {
        if wanted.is_empty() {
            return Plan::InSync;
        }
        let block = scaffolded();
        let block: Vec<&str> = block.iter().map(String::as_str).collect();
        splice_lines(&mut lines, anchor, &block, eol);
        return Plan::Scaffold(lines.join("\n"), added(wanted));
    }
    match edit_maps(&mut lines, eol, wanted, owned, false) {
        Err(why) => Plan::Unsupported(why),
        Ok(changes) if changes.is_empty() => Plan::InSync,
        Ok(changes) => Plan::Edit(lines.join("\n"), changes),
    }
}

/// [`plan`] for a file that has keys. With `readable_only`, a map this
/// reader cannot follow is left alone instead of refusing the file.
fn edit_maps(
    lines: &mut Vec<String>,
    eol: &str,
    wanted: &Wanted,
    owned: &Owned,
    readable_only: bool,
) -> Result<Vec<Change>, String> {
    let mut changes = Vec::new();
    for kind in MapKind::BOTH {
        match edit_map(lines, eol, kind, wanted.map(kind), owned) {
            Ok(edits) => changes.extend(edits),
            Err(_) if readable_only => {}
            Err(why) => return Err(why),
        }
    }
    Ok(changes)
}

/// [`plan`] for one map of a file that has keys.
fn edit_map(
    lines: &mut Vec<String>,
    eol: &str,
    kind: MapKind,
    wanted: &BTreeMap<String, String>,
    owned: &Owned,
) -> Result<Vec<Change>, String> {
    let change = |key: &str, from: Option<&str>, to: Option<&str>| Change {
        map: kind,
        key: key.to_string(),
        from: from.map(str::to_string),
        to: to.map(str::to_string),
    };
    let section = match locate(lines, kind.key()) {
        Located::Unsupported(why) => return Err(why),
        Located::Absent => {
            if wanted.is_empty() {
                return Ok(Vec::new());
            }
            // After the document's last non-empty line (no blank separator;
            // before a `...` end marker), like every other key hosted mode
            // adds.
            let anchor = block_insert_point(lines)?;
            let pad = " ".repeat(ENTRY_INDENT);
            let block: Vec<String> = std::iter::once(format!("{}:", kind.key()))
                .chain(wanted.iter().map(|(k, v)| kind.line(&pad, k, v)))
                .collect();
            let block: Vec<&str> = block.iter().map(String::as_str).collect();
            splice_lines(lines, anchor, &block, eol);
            return Ok(wanted
                .iter()
                .map(|(key, value)| change(key, None, Some(value)))
                .collect());
        }
        Located::Block(section) => section,
    };

    let pad = " ".repeat(section.indent);
    let mut changes = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut removed: Vec<usize> = Vec::new();
    let mut last_kept = section.header;
    for entry in &section.entries {
        if !kind.ours(owned, &entry.key, &entry.value) {
            // The user's own entry under a key we want: two entries of one
            // key are a duplicate pnpm refuses.
            if wanted.contains_key(&entry.key) {
                return Err(format!("already sets `{}` in `{}`", entry.key, kind.key()));
            }
            last_kept = entry.line;
            continue;
        }
        let want = wanted.get(&entry.key);
        // A second entry of one key is a duplicate key pnpm refuses.
        let duplicate = !seen.insert(entry.key.as_str());
        if duplicate || want.is_none() {
            removed.push(entry.line);
            changes.push(change(&entry.key, Some(&entry.value), None));
            continue;
        }
        last_kept = entry.line;
        let Some(value) = want.filter(|value| **value != entry.value) else {
            continue;
        };
        let cr = if lines[entry.line].ends_with('\r') {
            "\r"
        } else {
            ""
        };
        lines[entry.line] = format!("{pad}{}: {}{cr}", entry.repr, kind.value(value));
        changes.push(change(&entry.key, Some(&entry.value), Some(value)));
    }
    let missing: Vec<(&String, &String)> = wanted
        .iter()
        .filter(|(key, _)| !seen.contains(key.as_str()))
        .collect();
    if changes.is_empty() && missing.is_empty() {
        return Ok(changes);
    }

    let mut end = section.end;
    for &at in removed.iter().rev() {
        remove_line(lines, at, eol);
        end -= 1;
        if at < last_kept {
            last_kept -= 1;
        }
    }
    if !missing.is_empty() {
        let block: Vec<String> = missing
            .iter()
            .map(|(key, value)| kind.line(&pad, key, value))
            .collect();
        let block: Vec<&str> = block.iter().map(String::as_str).collect();
        splice_lines(lines, last_kept + 1, &block, eol);
        changes.extend(
            missing
                .iter()
                .map(|(key, value)| change(key, None, Some(value))),
        );
    } else if !removed.is_empty()
        && lines[section.header + 1..end.min(lines.len())]
            .iter()
            .all(|line| bare(line).trim().is_empty())
    {
        // Every entry went and nothing else is in the map: a key left
        // without a value would read as null.
        remove_line(lines, section.header, eol);
    }
    Ok(changes)
}

/// What taking entries of ours out does to a pnpm-workspace.yaml.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Unwound {
    /// The file is exactly what hosted mode creates: delete it.
    Delete,
    /// The file without the entries no lock needs any more, and the edits
    /// that take them out.
    Rewrite(String, Vec<Change>),
    /// Nothing of ours to take out.
    Unchanged,
}

/// Take out the entries of ours the governed locks no longer need: the
/// inverse of [`plan`], from the file's bytes alone. `routed` are the
/// releases those locks still key by a registry of ours: the override of
/// each stays as it is, and so does the registry each one's key names. A
/// registry no lock key names serves nothing any more and goes, with no
/// patch service to ask. A file left as hosted mode created it is deleted,
/// and the `packages` scaffold spliced into a file with no keys goes with
/// the maps.
pub(crate) fn unwind(text: &str, owned: &Owned, routed: &[HostedOverride]) -> Unwound {
    let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    let pad = " ".repeat(ENTRY_INDENT);
    let stays = |kind: MapKind, entry: &Entry| match kind {
        MapKind::Override => owned.route(&entry.key, &entry.value).is_some_and(|ours| {
            routed
                .iter()
                .any(|pin| pin.name == ours.name && pin.version == ours.version)
        }),
        MapKind::Registry => routed.iter().any(|pin| pin.alias == entry.key),
    };
    // What stays of ours, as the file spells it; and the lines hosted mode
    // wrote, while every map of ours goes whole and is spelled as it writes
    // them: the scaffold, then each map's key with its entries on the lines
    // right after, one map after the other.
    let mut kept = Wanted::default();
    let mut drops_any = false;
    let mut written: Option<Vec<&str>> = Some(PACKAGES_SCAFFOLD.to_vec());
    let mut follows = None;
    for kind in MapKind::BOTH {
        let Located::Block(section) = locate(&lines, kind.key()) else {
            continue;
        };
        let ours: Vec<&Entry> = section
            .entries
            .iter()
            .filter(|entry| kind.ours(owned, &entry.key, &entry.value))
            .collect();
        if ours.is_empty() {
            continue;
        }
        for entry in &ours {
            if stays(kind, entry) {
                let map = match kind {
                    MapKind::Registry => &mut kept.registries,
                    MapKind::Override => &mut kept.overrides,
                };
                map.insert(entry.key.clone(), entry.value.clone());
            } else {
                drops_any = true;
            }
        }
        let whole = ours.len() == section.entries.len()
            && !ours.iter().any(|entry| stays(kind, entry))
            && follows.is_none_or(|next| next == section.header)
            && bare(&lines[section.header]) == format!("{}:", kind.key())
            && section.entries.iter().enumerate().all(|(i, entry)| {
                entry.line == section.header + 1 + i
                    && bare(&lines[entry.line]) == kind.line(&pad, &entry.key, &entry.value)
            });
        let last = section.header + section.entries.len();
        match written.as_mut().filter(|_| whole) {
            Some(block) => block.extend(lines[section.header..=last].iter().map(|l| bare(l))),
            None => written = None,
        }
        follows = Some(last + 1);
    }
    if !drops_any {
        return Unwound::Unchanged;
    }
    if let Some(block) = written {
        let created = format!("{}\n", block.join("\n"));
        if eol_eq(text.as_bytes(), created.as_bytes()) {
            return Unwound::Delete;
        }
        if let Some(original) = strip_keyless_splice(text, &block) {
            let gone = match plan(Some(text), &Wanted::default(), owned) {
                Plan::Edit(_, changes) => changes,
                _ => Vec::new(),
            };
            return Unwound::Rewrite(original, gone);
        }
    }
    if block_insert_point(&lines).is_err() {
        return Unwound::Unchanged;
    }
    let eol = terminator(text);
    match edit_maps(&mut lines, eol, &kept, owned, true) {
        Ok(changes) if !changes.is_empty() => Unwound::Rewrite(lines.join("\n"), changes),
        _ => Unwound::Unchanged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGIN: &str = "https://patch.test";
    /// The patches of the tests' packages, by UUID.
    const LEAF: &str = "11111111-1111-4111-8111-111111111111";
    const MID: &str = "22222222-2222-4222-8222-222222222222";
    const SCOPED: &str = "33333333-3333-4333-8333-333333333333";

    /// The directory the patch `uuid` of `name` is served from.
    fn address(name: &str, uuid: &str) -> String {
        format!("{ORIGIN}/patch/npm/{name}/1.0.0/tok/{uuid}/")
    }

    /// The registry name of a patch no other shares eight digits with.
    fn alias(uuid: &str) -> String {
        format!("socket-{}", &uuid[..8])
    }

    /// The registries of a file, with `https://patch.test` the patch
    /// server.
    fn owned(text: Option<&str>) -> Owned {
        Owned::of(text, &|origin| origin == ORIGIN)
    }

    fn route(name: &str, uuid: &str) -> HostedOverride {
        HostedOverride {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            alias: alias(uuid),
        }
    }

    /// The registry and the override of each `(package, patch uuid)`.
    fn wanted(packages: &[(&str, &str)]) -> Wanted {
        let mut wanted = Wanted::default();
        for (name, uuid) in packages {
            wanted.registries.insert(alias(uuid), address(name, uuid));
            wanted.route(&route(name, uuid));
        }
        wanted
    }

    fn registry_line(name: &str, uuid: &str) -> String {
        format!("  {}: {}", alias(uuid), address(name, uuid))
    }

    fn override_line(name: &str, uuid: &str) -> String {
        format!("  '{name}@1.0.0': '{}:1.0.0'", alias(uuid))
    }

    fn planned(existing: Option<&str>, wanted: &Wanted) -> Plan {
        plan(existing, wanted, &owned(existing))
    }

    fn edited(existing: &str, wanted: &Wanted) -> String {
        match planned(Some(existing), wanted) {
            Plan::Edit(text, _) => text,
            other => panic!("expected an edit of {existing:?}, got {other:?}"),
        }
    }

    fn unwound(text: &str, routed: &[HostedOverride]) -> Unwound {
        match unwind(text, &owned(Some(text)), routed) {
            Unwound::Rewrite(text, changes) => {
                assert!(!changes.is_empty(), "a rewrite names its edits");
                Unwound::Rewrite(text, Vec::new())
            }
            other => other,
        }
    }

    fn rewritten(text: &str) -> Unwound {
        Unwound::Rewrite(text.to_string(), Vec::new())
    }

    #[test]
    fn a_registry_is_named_after_its_patch() {
        for (name, digits) in [
            ("socket-58f14d5a", Some("58f14d5a")),
            ("socket-58f14d5a9122", Some("58f14d5a9122")),
            (
                "socket-58f14d5a912245a8be405afbe988b306",
                Some("58f14d5a912245a8be405afbe988b306"),
            ),
            // Too few digits, too many, not lowercase hex, another word.
            ("socket-58f14d5", None),
            ("socket-58f14d5a912245a8be405afbe988b3060", None),
            ("socket-58F14D5A", None),
            ("socket-58f14d5g", None),
            ("socket-", None),
            ("socket", None),
            ("sockets-58f14d5a", None),
            ("corp", None),
        ] {
            assert_eq!(alias_digits(name), digits, "{name}");
        }
        // The names of unreleased builds: one registry per patch, by its
        // whole UUID, and one registry for a whole project.
        assert_eq!(
            legacy_patch_uuid(&format!("socket-patch-{LEAF}")),
            Some(LEAF)
        );
        assert_eq!(legacy_patch_uuid("socket-patch-mirror"), None);
        for (name, set) in [
            ("socket", true),
            ("socket-2", true),
            ("socket-17", true),
            ("socket-patch", true),
            ("socket-patch-3", true),
            ("socket-1", false),
            ("socket-0", false),
            ("socket-02", false),
            ("socket-two", false),
            ("socket-58f14d5a", false),
            ("Socket", false),
        ] {
            assert_eq!(is_legacy_set_alias(name), set, "{name}");
        }
        for name in ["socket-58f14d5a", "socket", "socket-patch-2"] {
            assert!(is_alias_name(name), "{name}");
        }
        assert!(is_alias_name(&format!("socket-patch-{LEAF}")));
        for name in ["socket-1", "socket-two", "sockets", "corp"] {
            assert!(!is_alias_name(name), "{name}");
        }
        assert_eq!(strip_alias("socket-58f14d5a:1.0.0"), "1.0.0");
        assert_eq!(
            strip_alias("socket-58f14d5a9122:1.0.0(a@1.0.0)"),
            "1.0.0(a@1.0.0)"
        );
        // By its name alone only today's shape is ours: the names of an
        // unreleased build may be registries of the project's own.
        for theirs in [
            "socket:1.0.0",
            "socket-2:1.0.0",
            "socket-patch:1.0.0",
            "corp:1.0.0",
        ] {
            assert_eq!(strip_alias(theirs), theirs);
        }
        let earlier = format!("socket-patch-{LEAF}:1.0.0");
        assert_eq!(strip_alias(&earlier), earlier);
        assert_eq!(strip_alias("1.0.0"), "1.0.0");
    }

    /// Eight digits of the patch UUID name its registry; a name another
    /// patch of the project would share, or one the user declares for
    /// something else, gets four more digits at a time.
    #[test]
    fn a_registry_name_is_lengthened_while_it_is_taken() {
        const A: &str = "58f14d5a-9122-45a8-be40-5afbe988b306";
        // The same first eight digits, then the same first twelve.
        const SHARES_8: &str = "58f14d5a-0000-4000-8000-000000000000";
        const SHARES_12: &str = "58f14d5a-9122-4000-8000-000000000000";
        let owned = owned(None);
        let name = |others: &[&str]| owned.name_for(A, &others.iter().copied().collect());
        assert_eq!(name(&[]).as_deref(), Some("socket-58f14d5a"));
        assert_eq!(name(&[A, LEAF, MID]).as_deref(), Some("socket-58f14d5a"));
        assert_eq!(name(&[SHARES_8]).as_deref(), Some("socket-58f14d5a9122"));
        assert_eq!(
            name(&[SHARES_8, SHARES_12]).as_deref(),
            Some("socket-58f14d5a912245a8")
        );
        // Both patches of a pair are lengthened, whichever is asked first.
        assert_eq!(
            owned.name_for(SHARES_8, &[A].into()).as_deref(),
            Some("socket-58f14d5a0000")
        );
        // The user's own registry under the short name.
        let taken = "namedRegistries:\n  socket-58f14d5a: https://npm.corp.example/\n";
        assert_eq!(
            super::Owned::of(Some(taken), &|origin| origin == ORIGIN)
                .name_for(A, &BTreeSet::new())
                .as_deref(),
            Some("socket-58f14d5a9122")
        );
        // Every length taken leaves no name.
        let all: String = (8..=32)
            .step_by(4)
            .map(|digits| {
                format!(
                    "  socket-{}: https://npm.corp.example/\n",
                    &A.replace('-', "")[..digits]
                )
            })
            .collect();
        let all = format!("namedRegistries:\n{all}");
        assert_eq!(
            super::Owned::of(Some(&all), &|origin| origin == ORIGIN).name_for(A, &BTreeSet::new()),
            None
        );
    }

    #[test]
    fn a_registry_address_is_the_directory_of_one_patch() {
        let leaf = address("leaf", LEAF);
        assert_eq!(
            Address::parse(&leaf),
            Some(Address {
                origin: ORIGIN.to_string(),
                uuid: LEAF.to_string(),
            })
        );
        // pnpm reads an address without its final `/` the same way; a
        // scoped package and a server that serves from another path.
        for url in [
            leaf.trim_end_matches('/').to_string(),
            format!("{ORIGIN}/patch/npm/@scope/pkg/1.0.0/tok/{LEAF}/"),
            format!("http://127.0.0.1:4873/serve/tok/{LEAF}/"),
        ] {
            assert_eq!(
                Address::parse(&url).map(|a| a.uuid),
                Some(LEAF.to_string()),
                "{url}"
            );
        }
        assert_eq!(
            Address::parse(&format!("http://127.0.0.1:4873/serve/tok/{LEAF}/"))
                .unwrap()
                .origin,
            "http://127.0.0.1:4873"
        );
        for not in [
            // The one address of a whole project an unreleased build used.
            format!("{ORIGIN}/patch/npm/~/11111111111141118111/"),
            format!("{ORIGIN}/patch/npm/leaf/1.0.0/tok/{LEAF}/extra/"),
            format!("{ORIGIN}/patch/npm/leaf/1.0.0/tok/"),
            format!(
                "{ORIGIN}/patch/npm/leaf/1.0.0/tok/{}/",
                LEAF.to_uppercase().replace('1', "A")
            ),
            format!("{ORIGIN}/patch/npm/leaf/1.0.0/tok/{LEAF}/?x=1"),
            format!("https://user@patch.test/patch/npm/leaf/1.0.0/tok/{LEAF}/"),
            format!("https:///patch/npm/leaf/1.0.0/tok/{LEAF}/"),
            format!("ftp://patch.test/patch/npm/leaf/1.0.0/tok/{LEAF}/"),
            "https://npm.corp.example/".to_string(),
        ] {
            assert_eq!(Address::parse(&not), None, "{not}");
        }
        // The tarball a lock entry resolves is a file of that directory.
        let tarball = format!("{leaf}leaf-1.0.0.tgz");
        assert!(Address::serves(&leaf, &tarball));
        assert!(Address::serves(leaf.trim_end_matches('/'), &tarball));
        for not in [
            leaf.clone(),
            format!("{leaf}nested/leaf-1.0.0.tgz"),
            format!("{}leaf-1.0.0.tgz", address("leaf", MID)),
            format!("{}x/leaf-1.0.0.tgz", leaf.trim_end_matches('/')),
        ] {
            assert!(!Address::serves(&leaf, &not), "{not}");
        }
        assert_eq!(
            legacy_set_origin(&format!(
                "{ORIGIN}/patch/npm/~/11111111111141118111.22222222222242228222/"
            )),
            Some(ORIGIN)
        );
        assert_eq!(legacy_set_origin(&leaf), None);
    }

    /// The registries a run passes over although they look like a patch's:
    /// the name and the directory of a patch whose UUID the name's digits
    /// start, on a host that is no patch server to the run. They are
    /// counted by origin, and nothing but the origin is told. A registry
    /// on a patch server, one under our name at any other address, and
    /// one whose digits name another patch are not among them.
    #[test]
    fn registries_of_our_shape_on_other_hosts_are_counted_by_origin() {
        const STAGING: &str = "https://patch.staging.example:8443";
        let on = |origin: &str, name: &str, uuid: &str| {
            format!(
                "  {}: {origin}/patch/npm/{name}/1.0.0/tok/{uuid}/\n",
                alias(uuid)
            )
        };
        let text = format!(
            "namedRegistries:\n{}{}{}{}  {}: https://npm.corp.example/\n  \
             socket-22222222: http://127.0.0.1:4873/patch/npm/x/1.0.0/tok/{LEAF}/\n  \
             corp: {STAGING}/patch/npm/y/1.0.0/tok/{MID}/\n",
            on(ORIGIN, "leaf", LEAF),
            on(STAGING, "mid", MID),
            on(STAGING, "leaf", "33333333-3333-4333-8333-333333333333"),
            on(
                "http://127.0.0.1:4873",
                "other",
                "44444444-4444-4444-8444-444444444444"
            ),
            alias("55555555-5555-4555-8555-555555555555"),
        );
        let patch_server = |origin: &str| origin == ORIGIN;
        assert_eq!(
            on_unknown_hosts(&text, &patch_server),
            [
                ("http://127.0.0.1:4873".to_string(), 1),
                (STAGING.to_string(), 2),
            ]
        );
        assert_eq!(on_unknown_hosts(&text, &|_| true), []);
        assert_eq!(on_unknown_hosts("packages:\n  - '.'\n", &patch_server), []);
    }

    /// A registry under a name of ours is the user's when the file
    /// declares it somewhere that is not the serve directory, on a patch
    /// server, of a patch its digits name.
    #[test]
    fn the_users_registry_under_our_name_stays_theirs() {
        let ours = format!(
            "namedRegistries:\n{}\n  corp: https://npm.corp.example/\n",
            registry_line("leaf", LEAF)
        );
        let owned_ours = owned(Some(&ours));
        assert!(owned_ours.alias(&alias(LEAF)));
        assert!(
            owned_ours.alias(&alias(MID)),
            "a name left with no declaration"
        );
        assert!(!owned_ours.alias("corp"));

        let name = alias(LEAF);
        for theirs in [
            format!("namedRegistries:\n  {name}: https://npm.corp.example/\n"),
            // Our kind of address on a host that is not a patch server.
            format!(
                "namedRegistries:\n  {name}: https://mirror.example/patch/npm/leaf/1.0.0/tok/{LEAF}/\n"
            ),
            // On a patch server, for a patch the name's digits do not start.
            format!("namedRegistries:\n  {name}: {}\n", address("leaf", MID)),
            // The address an unreleased build gave a whole project.
            format!("namedRegistries:\n  {name}: {ORIGIN}/patch/npm/~/11111111111141118111/\n"),
        ] {
            let owned = owned(Some(&theirs));
            assert!(!owned.alias(&name), "{theirs}");
            assert_eq!(owned.route("leaf@1.0.0", &format!("{name}:1.0.0")), None);
            assert_eq!(
                owned.name_for(LEAF, &BTreeSet::new()).as_deref(),
                Some("socket-111111111111"),
                "ours takes the next length: {theirs}"
            );
        }
        // A longer name is ours as long as its digits start the UUID.
        let long = format!(
            "namedRegistries:\n  socket-111111111111: {}\n",
            address("leaf", LEAF)
        );
        assert!(owned(Some(&long)).alias("socket-111111111111"));

        // The names of an unreleased build. One registry per patch, by its
        // whole UUID: ours unless declared somewhere else.
        let per_patch = format!("socket-patch-{LEAF}");
        assert!(owned(None).alias(&per_patch));
        let declared = format!(
            "namedRegistries:\n  {per_patch}: {}\n",
            address("leaf", LEAF)
        );
        assert!(owned(Some(&declared)).alias(&per_patch));
        let elsewhere = format!(
            "namedRegistries:\n  {per_patch}: {}\n",
            address("leaf", MID)
        );
        assert!(!owned(Some(&elsewhere)).alias(&per_patch));
        // One registry for the project: ours only as declared, at that
        // build's address on a patch server.
        for name in ["socket", "socket-patch", "socket-2"] {
            assert!(!owned(None).alias(name), "{name}");
            let set =
                format!("namedRegistries:\n  {name}: {ORIGIN}/patch/npm/~/11111111111141118111/\n");
            assert!(owned(Some(&set)).alias(name), "{name}");
            for theirs in [
                format!("namedRegistries:\n  {name}: https://npm.corp.example/\n"),
                format!("namedRegistries:\n  {name}: https://mirror.example/patch/npm/~/11111111111141118111/\n"),
                format!("namedRegistries:\n  {name}: {}\n", address("leaf", LEAF)),
            ] {
                assert!(!owned(Some(&theirs)).alias(name), "{theirs}");
            }
        }
    }

    #[test]
    fn hosted_overrides_are_told_from_the_users() {
        let owned = owned(None);
        let ours = owned
            .route("@scope/pkg@1.2.3", "socket-33333333:1.2.3")
            .expect("ours");
        assert_eq!(
            (
                ours.name.as_str(),
                ours.version.as_str(),
                ours.alias.as_str()
            ),
            ("@scope/pkg", "1.2.3", "socket-33333333")
        );
        assert_eq!(ours.key(), "@scope/pkg@1.2.3");
        assert_eq!(ours.value(), "socket-33333333:1.2.3");
        // The long value of an unreleased build.
        let legacy = format!("socket-patch-{LEAF}");
        let long = owned
            .route("leaf@1.0.0", &format!("{legacy}:leaf@1.0.0"))
            .expect("ours");
        assert_eq!(long.alias, legacy);
        for (key, value) in [
            ("leaf@1.0.0", "2.0.0"),
            ("leaf@1.0.0", "npm:other@1.0.0"),
            ("leaf@1.0.0", "corp:1.0.0"),
            ("leaf@1.0.0", "socket-11111111:2.0.0"),
            ("leaf@1.0.0", "socket-11111111:other@1.0.0"),
            ("leaf", "socket-11111111:1.0.0"),
            ("@scope/pkg", "socket-11111111:1.0.0"),
            ("leaf@1.0.0", "sockets-11111111:1.0.0"),
            // An undeclared `socket` is as likely the user's.
            ("leaf@1.0.0", "socket:1.0.0"),
        ] {
            assert_eq!(owned.route(key, value), None, "{key}: {value}");
        }
    }

    /// The releases a file routes, each with its registry's address: what
    /// lets a run that was not granted a patch leave its release routed.
    #[test]
    fn a_file_says_which_releases_it_routes_where() {
        let text = format!(
            "packages:\n  - '.'\nnamedRegistries:\n{}\n{}\n  corp: https://npm.corp.example/\n\
             overrides:\n{}\n{}\n  lodash: ^4.17.21\n  'gone@1.0.0': 'socket-99999999:1.0.0'\n  \
             'theirs@1.0.0': 'corp:1.0.0'\n",
            registry_line("leaf", LEAF),
            registry_line("mid", MID),
            override_line("leaf", LEAF),
            override_line("mid", MID),
        );
        assert_eq!(
            routes(&text, &owned(Some(&text))),
            [
                (route("leaf", LEAF), address("leaf", LEAF)),
                (route("mid", MID), address("mid", MID)),
            ],
            "an override whose registry the file does not declare routes nowhere"
        );
        assert_eq!(routes("packages:\n  - '.'\n", &owned(None)), []);
    }

    /// The workspace file the golden fixtures' pnpm ran with is the one the
    /// planner writes, and its unwind is the project's own file.
    #[test]
    fn the_planned_file_is_the_one_the_fixtures_were_locked_with() {
        use super::super::registry_alias::fixtures;
        for case in fixtures::cases()
            .into_iter()
            .chain(fixtures::refused().into_iter().map(|(case, _)| case))
        {
            let mut wanted = Wanted::default();
            for patch in fixtures::patches(&case) {
                let address = Address::parse(&patch.npm_registry_url).expect("an address");
                assert_eq!(address.origin, fixtures::ORIGIN, "{case}");
                let alias = fixtures::alias(&case, &patch);
                wanted
                    .registries
                    .insert(alias.clone(), patch.npm_registry_url.clone());
                wanted.route(&HostedOverride {
                    name: patch.name,
                    version: patch.version,
                    alias,
                });
            }
            let existing = fixtures::read(&case, "project/pnpm-workspace.yaml");
            let expected = fixtures::read(&case, "expected/pnpm-workspace.yaml").expect("expected");
            let written = match planned(existing.as_deref(), &wanted) {
                Plan::Create(text, _) | Plan::Scaffold(text, _) | Plan::Edit(text, _) => text,
                other => panic!("{case}: {other:?}"),
            };
            assert_eq!(written, expected, "{case}");
            assert_eq!(planned(Some(&written), &wanted), Plan::InSync, "{case}");
            let restored = match &existing {
                None => Unwound::Delete,
                Some(text) => rewritten(text),
            };
            assert_eq!(unwound(&written, &[]), restored, "{case}");
        }
    }

    #[test]
    fn no_file_creates_the_root_only_scaffold() {
        let want = wanted(&[("leaf", LEAF), ("@scope/pkg", SCOPED)]);
        let Plan::Create(text, changes) = planned(None, &want) else {
            panic!("a missing file is created");
        };
        assert_eq!(
            text,
            format!(
                "packages:\n  - '.'\nnamedRegistries:\n{}\n{}\noverrides:\n{}\n{}\n",
                registry_line("leaf", LEAF),
                registry_line("@scope/pkg", SCOPED),
                override_line("@scope/pkg", SCOPED),
                override_line("leaf", LEAF)
            ),
            "registries in name order, overrides in key order"
        );
        assert_eq!(changes, added(&want));
        assert_eq!(changes.len(), 4);
        // The created file is in sync, and its unwind deletes it.
        assert_eq!(planned(Some(&text), &want), Plan::InSync);
        assert_eq!(unwound(&text, &[]), Unwound::Delete);
        assert_eq!(unwound(&text.replace('\n', "\r\n"), &[]), Unwound::Delete);
        assert_eq!(planned(None, &Wanted::default()), Plan::InSync);

        // One release at a time: its override and its registry go
        // together, and the rest is still the file hosted mode creates.
        let kept = [route("leaf", LEAF)];
        let Unwound::Rewrite(partial, _) = unwound(&text, &kept) else {
            panic!("the other release's entries go");
        };
        assert_eq!(
            partial,
            format!(
                "packages:\n  - '.'\nnamedRegistries:\n{}\noverrides:\n{}\n",
                registry_line("leaf", LEAF),
                override_line("leaf", LEAF)
            )
        );
        assert_eq!(unwound(&partial, &kept), Unwound::Unchanged);
        assert_eq!(unwound(&partial, &[]), Unwound::Delete);
    }

    #[test]
    fn a_keyless_file_gets_the_scaffold_and_the_maps() {
        let want = wanted(&[("leaf", LEAF)]);
        for user in [
            "",
            "\n",
            "# shared settings\n",
            "# a\r\n# b\r\n",
            "---\n",
            "# a\n# b",
            "# a\r\n# b",
        ] {
            let Plan::Scaffold(text, _) = planned(Some(user), &want) else {
                panic!("a keyless file is scaffolded: {user:?}");
            };
            assert!(
                text.contains("packages:")
                    && text.contains(&registry_line("leaf", LEAF))
                    && text.contains(&override_line("leaf", LEAF)),
                "{text:?}"
            );
            if user.contains("\r\n") {
                assert!(!text.replace("\r\n", "").contains('\n'), "{text:?}");
            } else {
                assert!(!text.contains('\r'), "{text:?}");
            }
            assert_eq!(planned(Some(&text), &want), Plan::InSync);
            // An empty file with the splice is the file hosted mode creates.
            let restored = if user.is_empty() {
                Unwound::Delete
            } else {
                rewritten(user)
            };
            assert_eq!(unwound(&text, &[]), restored, "{user:?}");
        }
        let Plan::Scaffold(text, _) = planned(Some("# c\n"), &want) else {
            panic!("scaffolded");
        };
        assert_eq!(
            text,
            format!(
                "# c\npackages:\n  - '.'\nnamedRegistries:\n{}\noverrides:\n{}\n",
                registry_line("leaf", LEAF),
                override_line("leaf", LEAF)
            )
        );
        assert_eq!(planned(Some("# c\n"), &Wanted::default()), Plan::InSync);
    }

    #[test]
    fn a_file_without_the_maps_gets_them_appended() {
        let want = wanted(&[("leaf", LEAF)]);
        let maps = format!(
            "namedRegistries:\n{}\noverrides:\n{}",
            registry_line("leaf", LEAF),
            override_line("leaf", LEAF)
        );
        let user = "packages:\n  - 'apps/*'\n\n# keep me\ncatalog:\n  react: ^19.0.0\n";
        let text = edited(user, &want);
        assert_eq!(
            text,
            format!("{user}{maps}\n"),
            "appended after the last line, every user byte kept"
        );
        assert_eq!(unwound(&text, &[]), rewritten(user));
        // A file with no final newline keeps none; a `...` end marker stays
        // last.
        let text = edited("packages:\n  - 'apps/*'", &want);
        assert_eq!(text, format!("packages:\n  - 'apps/*'\n{maps}"));
        assert_eq!(unwound(&text, &[]), rewritten("packages:\n  - 'apps/*'"));
        let text = edited("packages:\n  - 'apps/*'\n...\n", &want);
        assert_eq!(text, format!("packages:\n  - 'apps/*'\n{maps}\n...\n"));
    }

    #[test]
    fn crlf_files_stay_crlf() {
        let want = wanted(&[("leaf", LEAF), ("mid", MID)]);
        for user in [
            "packages:\r\n  - 'apps/*'\r\n",
            "packages:\r\n  - 'apps/*'",
            "\u{feff}packages:\r\n  - 'apps/*'\r\ncatalog:\r\n  a: 1\r\n",
            "overrides:\r\n  lodash: ^4.17.21\r\npackages:\r\n  - 'apps/*'\r\n",
        ] {
            let text = edited(user, &want);
            assert!(
                !text.replace("\r\n", "").contains(['\r', '\n']),
                "every line ends CRLF: {text:?}"
            );
            assert_eq!(
                text.ends_with("\r\n"),
                user.ends_with("\r\n"),
                "the final-newline shape is kept: {text:?}"
            );
            assert_eq!(planned(Some(&text), &want), Plan::InSync);
            assert_eq!(unwound(&text, &[]), rewritten(user));
            // One release at a time takes the same bytes back out.
            let Unwound::Rewrite(one, _) = unwound(&text, &[route("mid", MID)]) else {
                panic!("the first release's entries go");
            };
            assert!(
                one.contains("'mid@1.0.0'")
                    && one.contains(&alias(MID))
                    && !one.contains("'leaf@1.0.0'")
                    && !one.contains(&alias(LEAF)),
                "{one:?}"
            );
            assert_eq!(unwound(&one, &[]), rewritten(user));
        }
    }

    #[test]
    fn existing_maps_keep_the_users_entries() {
        let user = "packages:\n  - '.'\nnamedRegistries:\n  # the company mirror\n  \
                    corp: https://npm.corp.example/   # internal\n  'gh': \"https://npm.pkg.github.com/\"\n  \
                    socket: https://npm.socket.example/\n\
                    overrides:\n    # security\n    lodash: ^4.17.21   # pinned\n    'left-pad@1': \"1.3.0\"\n    \
                    'theirs@2.0.0': 'socket:2.0.0'\ncatalog:\n  a: 1\n";
        let want = wanted(&[("leaf", LEAF)]);
        let text = edited(user, &want);
        assert_eq!(
            text,
            format!(
                "packages:\n  - '.'\nnamedRegistries:\n  # the company mirror\n  \
                 corp: https://npm.corp.example/   # internal\n  'gh': \"https://npm.pkg.github.com/\"\n  \
                 socket: https://npm.socket.example/\n{}\n\
                 overrides:\n    # security\n    lodash: ^4.17.21   # pinned\n    'left-pad@1': \"1.3.0\"\n    \
                 'theirs@2.0.0': 'socket:2.0.0'\n    \
                 'leaf@1.0.0': 'socket-11111111:1.0.0'\ncatalog:\n  a: 1\n",
                registry_line("leaf", LEAF)
            ),
            "each entry takes its map's indent, after the user's"
        );
        assert_eq!(
            declared(&text),
            vec![
                ("corp".to_string(), "https://npm.corp.example/".to_string()),
                ("gh".to_string(), "https://npm.pkg.github.com/".to_string()),
                (
                    "socket".to_string(),
                    "https://npm.socket.example/".to_string()
                ),
                (alias(LEAF), address("leaf", LEAF)),
            ]
        );
        assert!(holds_ours(&text, &owned(Some(&text))));
        assert!(
            !holds_ours(user, &owned(Some(user))),
            "the user's own `socket` registry and its override are theirs"
        );
        // Idempotent, and the unwind restores the user's bytes.
        assert_eq!(planned(Some(&text), &want), Plan::InSync);
        assert_eq!(unwound(&text, &[]), rewritten(user));
        assert_eq!(unwound(&text, &[route("leaf", LEAF)]), Unwound::Unchanged);
        assert_eq!(unwound(user, &[]), Unwound::Unchanged);
    }

    /// Each patch has its own registry line and override: a new pin adds
    /// both, a pin that left takes both with it, and a patch replaced by a
    /// new one renames the registry and repoints the override. Nothing
    /// accumulates.
    #[test]
    fn the_registries_follow_the_pins() {
        let Plan::Create(text, _) = planned(None, &wanted(&[("leaf", LEAF)])) else {
            panic!("created");
        };
        // A second pin: its registry and its override join the maps.
        let both = wanted(&[("leaf", LEAF), ("mid", MID)]);
        let Plan::Edit(text, changes) = planned(Some(&text), &both) else {
            panic!("edited");
        };
        assert_eq!(
            text,
            format!(
                "packages:\n  - '.'\nnamedRegistries:\n{}\n{}\noverrides:\n{}\n{}\n",
                registry_line("leaf", LEAF),
                registry_line("mid", MID),
                override_line("leaf", LEAF),
                override_line("mid", MID)
            )
        );
        assert_eq!(
            changes,
            vec![
                Change {
                    map: MapKind::Registry,
                    key: alias(MID),
                    from: None,
                    to: Some(address("mid", MID)),
                },
                Change {
                    map: MapKind::Override,
                    key: "mid@1.0.0".to_string(),
                    from: None,
                    to: Some(format!("{}:1.0.0", alias(MID))),
                },
            ]
        );
        // The first release left the lock.
        let Plan::Edit(text, changes) = planned(Some(&text), &wanted(&[("mid", MID)])) else {
            panic!("edited");
        };
        assert_eq!(
            text,
            format!(
                "packages:\n  - '.'\nnamedRegistries:\n{}\noverrides:\n{}\n",
                registry_line("mid", MID),
                override_line("mid", MID)
            )
        );
        assert_eq!(
            changes,
            vec![
                Change {
                    map: MapKind::Registry,
                    key: alias(LEAF),
                    from: Some(address("leaf", LEAF)),
                    to: None,
                },
                Change {
                    map: MapKind::Override,
                    key: "leaf@1.0.0".to_string(),
                    from: Some(format!("{}:1.0.0", alias(LEAF))),
                    to: None,
                },
            ]
        );
        // The patch of the release that is left is replaced by a new one:
        // the registry is the new patch's, under its name, and the
        // override names it.
        let Plan::Edit(replaced, changes) = planned(Some(&text), &wanted(&[("mid", SCOPED)]))
        else {
            panic!("edited");
        };
        assert_eq!(
            replaced,
            format!(
                "packages:\n  - '.'\nnamedRegistries:\n{}\noverrides:\n{}\n",
                registry_line("mid", SCOPED),
                override_line("mid", SCOPED)
            )
        );
        assert_eq!(changes.len(), 3, "{changes:?}");
        assert!(
            changes.contains(&Change {
                map: MapKind::Override,
                key: "mid@1.0.0".to_string(),
                from: Some(format!("{}:1.0.0", alias(MID))),
                to: Some(format!("{}:1.0.0", alias(SCOPED))),
            }),
            "{changes:?}"
        );
        // A new grant of the same patch (another token): the registry's
        // line is rewritten in place under the same name.
        let regranted = {
            let mut wanted = wanted(&[("mid", MID)]);
            wanted.registries.insert(
                alias(MID),
                format!("{ORIGIN}/patch/npm/mid/1.0.0/other-token/{MID}/"),
            );
            wanted
        };
        let Plan::Edit(moved, changes) = planned(Some(&text), &regranted) else {
            panic!("edited");
        };
        assert_eq!(
            moved,
            text.replace("/tok/", "/other-token/"),
            "only the address changes"
        );
        assert_eq!(changes.len(), 1, "{changes:?}");
        // The last one too: both maps lose their key, the user's file its
        // tail.
        let user = format!(
            "packages:\n  - 'apps/*'\n{}",
            &text["packages:\n  - '.'\n".len()..]
        );
        assert_eq!(
            edited(&user, &Wanted::default()),
            "packages:\n  - 'apps/*'\n"
        );
    }

    /// The shapes an unreleased build wrote are replaced whole: a registry
    /// per patch named by its whole UUID (without, then with, the long
    /// override value), and one registry for the whole project.
    #[test]
    fn earlier_shapes_are_replaced() {
        let legacy = format!("socket-patch-{LEAF}");
        let want = wanted(&[("leaf", LEAF)]);
        let new = format!(
            "packages:\n  - 'apps/*'\nnamedRegistries:\n{}\noverrides:\n{}\n",
            registry_line("leaf", LEAF),
            override_line("leaf", LEAF)
        );
        let bare = format!(
            "packages:\n  - 'apps/*'\nnamedRegistries:\n  {legacy}: {}\n",
            address("leaf", LEAF)
        );
        assert_eq!(edited(&bare, &want), new);
        let long = format!("{bare}overrides:\n  'leaf@1.0.0': '{legacy}:leaf@1.0.0'\n");
        let Plan::Edit(text, changes) = planned(Some(&long), &want) else {
            panic!("edited");
        };
        assert_eq!(text, new);
        assert!(
            changes.contains(&Change {
                map: MapKind::Override,
                key: "leaf@1.0.0".to_string(),
                from: Some(format!("{legacy}:leaf@1.0.0")),
                to: Some("socket-11111111:1.0.0".to_string()),
            }),
            "{changes:?}"
        );
        assert_eq!(unwound(&long, &[]), rewritten("packages:\n  - 'apps/*'\n"));

        // One registry for the project, in either of its names, with a
        // second one beside it.
        for name in ["socket", "socket-patch"] {
            let set = format!(
                "packages:\n  - 'apps/*'\nnamedRegistries:\n  {name}: {ORIGIN}/patch/npm/~/11111111111141118111.22222222222242228222/\n  \
                 {name}-2: {ORIGIN}/patch/npm/~/33333333333343338333/\n\
                 overrides:\n  'leaf@1.0.0': '{name}:1.0.0'\n  'gone@1.0.0': '{name}-2:1.0.0'\n"
            );
            let Plan::Edit(text, changes) = planned(Some(&set), &want) else {
                panic!("{name}: edited");
            };
            assert_eq!(text, new, "{name}");
            assert!(
                changes.contains(&Change {
                    map: MapKind::Override,
                    key: "leaf@1.0.0".to_string(),
                    from: Some(format!("{name}:1.0.0")),
                    to: Some("socket-11111111:1.0.0".to_string()),
                }),
                "{name}: {changes:?}"
            );
            assert_eq!(
                unwound(&set, &[]),
                rewritten("packages:\n  - 'apps/*'\n"),
                "{name}"
            );
        }
    }

    #[test]
    fn a_users_override_of_a_patched_package_competes() {
        let packages: BTreeSet<&str> = ["leaf", "@scope/pkg"].into();
        for (overrides, competes) in [
            ("  other: 1.0.0\n", None),
            ("  'leafy@1.0.0': 1.0.1\n", None),
            ("  '@scope/pkg-extra': 2.0.0\n", None),
            ("  'leaf@1.0.0': 1.0.1\n", Some("leaf@1.0.0")),
            ("  leaf: 1.0.1\n", Some("leaf")),
            ("  'leaf@<2': 1.0.1\n", Some("leaf@<2")),
            ("  'parent@2>leaf': 1.0.1\n", Some("parent@2>leaf")),
            ("  'leaf>other': 1.0.1\n", None),
            ("  '@scope/pkg@^1': 1.0.1\n", Some("@scope/pkg@^1")),
            ("  '@scope/pkg': 1.0.1\n", Some("@scope/pkg")),
            ("  'a>@scope/pkg@1': '-'\n", Some("a>@scope/pkg@1")),
            // An override of ours never competes with itself.
            ("  'leaf@1.0.0': 'socket-11111111:1.0.0'\n", None),
            // A plain `socket` the file does not declare is the user's.
            ("  'leaf@1.0.0': 'socket:1.0.0'\n", Some("leaf@1.0.0")),
        ] {
            let text = format!("packages:\n  - '.'\noverrides:\n{overrides}");
            let found = competing_override(&text, &owned(Some(&text)), &packages);
            match competes {
                None => assert_eq!(found, None, "{overrides:?}"),
                Some(key) => assert_eq!(
                    found,
                    Some(format!("overrides `{key}` itself")),
                    "{overrides:?}"
                ),
            }
        }
        // The same value through a registry of the user's under our name
        // is the user's.
        let theirs = "namedRegistries:\n  socket-11111111: https://npm.corp.example/\noverrides:\n  'leaf@1.0.0': 'socket-11111111:1.0.0'\n";
        assert_eq!(
            competing_override(theirs, &owned(Some(theirs)), &packages),
            Some("overrides `leaf@1.0.0` itself".to_string())
        );
        assert_eq!(
            competing_override("packages:\n  - '.'\n", &owned(None), &packages),
            None
        );
        // A map this reader cannot follow may hold anything.
        let flow = competing_override("overrides: {leaf: 1.0.1}\n", &owned(None), &packages)
            .expect("refused");
        assert!(flow.contains("on one line"), "{flow}");
    }

    #[test]
    fn a_users_entry_under_a_wanted_key_is_refused() {
        let want = wanted(&[("leaf", LEAF)]);
        let user = "packages:\n  - '.'\noverrides:\n  'leaf@1.0.0': 1.0.1\n";
        match planned(Some(user), &want) {
            Plan::Unsupported(why) => {
                assert!(why.contains("already sets `leaf@1.0.0`"), "{why}")
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(unwound(user, &[]), Unwound::Unchanged);
        // The registry's name, taken by the user: the caller asks for a
        // longer one ([`Owned::name_for`]), and a plan that does not is
        // refused.
        let taken =
            "packages:\n  - '.'\nnamedRegistries:\n  socket-11111111: https://npm.corp.example/\n";
        match planned(Some(taken), &want) {
            Plan::Unsupported(why) => {
                assert!(why.contains("already sets `socket-11111111`"), "{why}")
            }
            other => panic!("{other:?}"),
        }
        let name = owned(Some(taken))
            .name_for(LEAF, &BTreeSet::new())
            .expect("a longer name");
        let mut next = Wanted::default();
        next.registries.insert(name.clone(), address("leaf", LEAF));
        next.route(&HostedOverride {
            alias: name.clone(),
            ..route("leaf", LEAF)
        });
        assert_eq!(
            edited(taken, &next),
            format!(
                "{taken}  {name}: {}\noverrides:\n  'leaf@1.0.0': '{name}:1.0.0'\n",
                address("leaf", LEAF)
            )
        );
    }

    #[test]
    fn shapes_a_splice_cannot_extend_are_refused() {
        let want = wanted(&[("leaf", LEAF)]);
        for (text, why) in [
            ("{packages: [.]}\n", "flow-style"),
            ("packages:\n  - '.'\n---\nother: 1\n", "more than one YAML document"),
            ("  packages:\n    - '.'\n", "column 0"),
            (
                "packages:\n  - '.'\nnamedRegistries: {corp: https://npm.corp.example/}\n",
                "on one line",
            ),
            ("packages:\n  - '.'\nnamedRegistries: ~\n", "on one line"),
            ("packages:\n  - '.'\noverrides: {lodash: 4.17.21}\n", "on one line"),
            (
                "namedRegistries:\n  a: https://a.example/\nnamedRegistries:\n  b: https://b.example/\n",
                "more than once",
            ),
            (
                "namedRegistries:\n  corp:\n    url: https://npm.corp.example/\n",
                "not a one-line",
            ),
            (
                "namedRegistries:\n  corp: >-\n    https://npm.corp.example/\n",
                "not a one-line",
            ),
            ("namedRegistries:\n\tcorp: https://npm.corp.example/\n", "not a one-line"),
            ("overrides:\n  - lodash\n", "not a one-line"),
        ] {
            match planned(Some(text), &want) {
                Plan::Unsupported(reason) => assert!(reason.contains(why), "{text:?}: {reason}"),
                other => panic!("{text:?} must be refused, got {other:?}"),
            }
            assert_eq!(unwound(text, &[]), Unwound::Unchanged, "{text:?}");
        }
    }

    #[test]
    fn an_unreadable_map_does_not_keep_the_other_from_unwinding() {
        let text = format!(
            "packages:\n  - '.'\noverrides: {{other: 1.0.0}}\nnamedRegistries:\n{}\n",
            registry_line("leaf", LEAF)
        );
        assert_eq!(
            unwound(&text, &[]),
            rewritten("packages:\n  - '.'\noverrides: {other: 1.0.0}\n")
        );
    }

    #[test]
    fn a_file_with_other_content_is_never_deleted() {
        let user = format!(
            "packages:\n  - '.'\nnamedRegistries:\n{}\noverrides:\n{}\ntrustLockfile: false\n",
            registry_line("leaf", LEAF),
            override_line("leaf", LEAF)
        );
        assert_eq!(
            unwound(&user, &[]),
            rewritten("packages:\n  - '.'\ntrustLockfile: false\n")
        );
    }
}
