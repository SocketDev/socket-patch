//! Text primitives for vlt's `vlt-lock.json`, shared by the hosted
//! rewriter, the vendored backend, the crawler, lock inventory and VEX.
//!
//! vlt writes one node or edge per line (`save.ts` `extraFormat`), so every
//! write is a line splice under the strict grammar here; nothing is
//! re-serialized. DepIDs come in two encodings, decided by prefix only:
//! legacy (`·`, `encodeURIComponent` with `@` raw and `/` as `§`, vlt ≤
//! 1.0.0-rc.14) and tilde (`~`, `_X` escapes with `/` as `+`). The codec rows
//! in the tests are shared verbatim with depscan's `vlt-dep-id.test.ts`.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::value::RawValue;
use serde_json::{Map, Value};

use crate::patch::path_safety::is_canonical_uuid;
use crate::utils::uri::encode_uri_component;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DepIdEra {
    Legacy,
    Tilde,
}

impl DepIdEra {
    pub(crate) fn delimiter(self) -> char {
        match self {
            DepIdEra::Legacy => '·',
            DepIdEra::Tilde => '~',
        }
    }

    /// The grammar vlt uses for ids it writes into a lock of this version:
    /// `1` is tilde, `0` and an absent version are legacy.
    pub(crate) fn for_lockfile_version(version: Option<u64>) -> Self {
        if version == Some(1) {
            DepIdEra::Tilde
        } else {
            DepIdEra::Legacy
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DepIdKind {
    Registry,
    Git,
    File,
    Remote,
    Workspace,
}

const PREFIXED_KINDS: [(&str, DepIdKind); 4] = [
    ("git", DepIdKind::Git),
    ("file", DepIdKind::File),
    ("remote", DepIdKind::Remote),
    ("workspace", DepIdKind::Workspace),
];

/// A split DepID. `first` and `second` are decoded; `extra` is the raw
/// fourth (registry, git) or third (file, remote, workspace) field, which
/// must still decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DepId {
    pub(crate) era: DepIdEra,
    pub(crate) kind: DepIdKind,
    pub(crate) first: String,
    pub(crate) second: Option<String>,
    pub(crate) extra: Option<String>,
}

impl DepId {
    /// `(name, version)` of a registry id, from any registry segment.
    pub(crate) fn registry_identity(&self) -> Option<(&str, &str)> {
        match (self.kind, self.second.as_deref()) {
            (DepIdKind::Registry, Some(second)) => registry_name_version(second),
            _ => None,
        }
    }
}

pub(crate) fn dep_id_era(id: &str) -> Option<DepIdEra> {
    [DepIdEra::Legacy, DepIdEra::Tilde].into_iter().find(|era| {
        let d = era.delimiter();
        id.starts_with(d)
            || PREFIXED_KINDS.iter().any(|(kind, _)| {
                id.strip_prefix(kind)
                    .is_some_and(|rest| rest.starts_with(d))
            })
    })
}

/// Split a DepID into its fields, following vlt's `isDepID` shape: registry
/// and git ids carry two or three fields after the type, file, remote and
/// workspace ids one or two. Any other shape, an empty required field or an
/// undecodable segment is `None`, and an undecodable id never matches.
pub(crate) fn split_dep_id(id: &str) -> Option<DepId> {
    let era = dep_id_era(id)?;
    let fields: Vec<&str> = id.split(era.delimiter()).collect();
    let kind = match fields[0] {
        "" => DepIdKind::Registry,
        type_field => PREFIXED_KINDS
            .iter()
            .find(|(name, _)| *name == type_field)
            .map(|(_, kind)| *kind)?,
    };
    let first = decode_segment(fields.get(1)?, era)?;
    if kind != DepIdKind::Registry && first.is_empty() {
        return None;
    }
    let (second, extra) = match kind {
        DepIdKind::Registry | DepIdKind::Git => {
            if !(3..=4).contains(&fields.len()) {
                return None;
            }
            let second = decode_segment(fields[2], era).filter(|s| !s.is_empty())?;
            (Some(second), fields.get(3))
        }
        DepIdKind::File | DepIdKind::Remote | DepIdKind::Workspace => {
            if fields.len() > 3 {
                return None;
            }
            (None, fields.get(2))
        }
    };
    if let Some(extra) = extra {
        decode_segment(extra, era)?;
    }
    Some(DepId {
        era,
        kind,
        first,
        second,
        extra: extra.map(|e| (*e).to_string()),
    })
}

/// The `file` DepID vlt writes for a project-relative directory.
pub(crate) fn file_dep_id(path: &str, era: DepIdEra) -> String {
    format!("file{}{}", era.delimiter(), encode_segment(path, era))
}

/// Encode one DepID segment the way vlt spells lock keys and `.vlt/<DepID>`
/// store dir names.
pub(crate) fn encode_segment(s: &str, era: DepIdEra) -> String {
    match era {
        DepIdEra::Tilde => encode_tilde(s),
        DepIdEra::Legacy => encode_uri_component(s)
            .replace("%40", "@")
            .replace("%2F", "§"),
    }
}

/// Decode one DepID segment; `None` when a legacy segment holds a malformed
/// `%` escape or escapes that are not UTF-8 (`decodeURIComponent` throws).
pub(crate) fn decode_segment(s: &str, era: DepIdEra) -> Option<String> {
    match era {
        DepIdEra::Tilde => Some(decode_tilde(s)),
        DepIdEra::Legacy => decode_legacy(s),
    }
}

fn tilde_escape(c: char) -> Option<&'static str> {
    Some(match c {
        '_' => "__",
        '+' => "_p",
        '\\' => "_b",
        ':' => "_c",
        '~' => "_t",
        '<' => "_l",
        '>' => "_g",
        '"' => "_q",
        '|' => "_i",
        '?' => "_m",
        '*' => "_a",
        ' ' => "_s",
        _ => return None,
    })
}

fn tilde_unescape(c: char) -> Option<char> {
    Some(match c {
        '_' => '_',
        'p' => '+',
        'b' => '\\',
        'c' => ':',
        't' => '~',
        'l' => '<',
        'g' => '>',
        'q' => '"',
        'i' => '|',
        'm' => '?',
        'a' => '*',
        'd' => '.',
        's' => ' ',
        _ => return None,
    })
}

fn encode_tilde(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '/' {
            out.push('+');
        } else if let Some(escaped) = tilde_escape(c) {
            out.push_str(escaped);
        } else if (c as u32) <= 0x1f {
            out.push_str(&format!("_{:02X}", c as u32));
        } else {
            out.push(c);
        }
    }
    if out.ends_with('.') {
        out.pop();
        out.push_str("_d");
    }
    out
}

fn decode_tilde(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '+' {
            out.push('/');
            i += 1;
            continue;
        }
        if c != '_' {
            out.push(c);
            i += 1;
            continue;
        }
        if let Some(unescaped) = chars.get(i + 1).and_then(|n| tilde_unescape(*n)) {
            out.push(unescaped);
            i += 2;
            continue;
        }
        if let (Some(high @ ('0' | '1')), Some(low)) = (chars.get(i + 1), chars.get(i + 2)) {
            if let Some(low) = low.to_digit(16) {
                let high = high.to_digit(16).unwrap_or_default();
                out.push(char::from((high * 16 + low) as u8));
                i += 3;
                continue;
            }
        }
        out.push('_');
        i += 1;
    }
    out
}

/// `decodeURIComponent(s.replaceAll('@','%40').replaceAll('§','%2F'))`,
/// validating every `%XX` itself: a lenient percent decoder would pass a
/// malformed escape through where JS throws.
fn decode_legacy(s: &str) -> Option<String> {
    let s = s.replace('§', "%2F");
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let high = char::from(*bytes.get(i + 1)?).to_digit(16)?;
            let low = char::from(*bytes.get(i + 2)?).to_digit(16)?;
            out.push((high * 16 + low) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

static SEMVER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$",
    )
    .expect("semver regex")
});

const NPM_SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;

const NPM_BLOCKED_NAMES: [&str; 2] = ["node_modules", "favicon.ico"];

/// The semver.org 2.0.0 grammar exactly (build metadata allowed; no `v`,
/// `=`, ranges or leading zeros) with major, minor and patch at most
/// node-semver's `Number.MAX_SAFE_INTEGER`; the TS twin's `isNpmSemver`.
/// A numeric prerelease identifier stays unbounded.
pub(crate) fn is_npm_semver(version: &str) -> bool {
    SEMVER_RE.captures(version).is_some_and(|caps| {
        (1..=3).all(|i| {
            caps[i]
                .parse::<u64>()
                .is_ok_and(|n| n <= NPM_SAFE_INTEGER_MAX)
        })
    })
}

fn is_npm_url_safe(part: &str) -> bool {
    !part.is_empty()
        && part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.!~*'()".contains(c))
}

/// validate-npm-package-name's `validForOldPackages`, the TS twin's
/// `isNpmPackageName`: `@<scope>/<pkg>` with both parts URL-safe, or a
/// URL-safe name without a leading `.` or `_` that is not a blocked name.
/// No length cap, since published packages exceed 214 chars.
pub(crate) fn is_registry_package_name(name: &str) -> bool {
    if let Some((scope, bare)) = name.strip_prefix('@').and_then(|s| s.split_once('/')) {
        return is_npm_url_safe(scope) && is_npm_url_safe(bare);
    }
    is_npm_url_safe(name)
        && !name.starts_with(['.', '_'])
        && !NPM_BLOCKED_NAMES.contains(&name.to_ascii_lowercase().as_str())
}

/// `(name, version)` from a registry id's decoded `name@version`, split at
/// the last `@` past index 0. The DepID version is authoritative for
/// identity, so a version npm could not have published gives `None`.
pub(crate) fn registry_name_version(second: &str) -> Option<(&str, &str)> {
    let at = second.rfind('@').filter(|&i| i > 0)?;
    let (name, version) = (&second[..at], &second[at + 1..]);
    (is_registry_package_name(name) && is_npm_semver(version)).then_some((name, version))
}

/// The store decoder: `(full name, version)` of a `.vlt/<DepID>` entry,
/// from any registry segment (the store holds every installed copy) and
/// ignoring the extra. Git, remote, file, workspace and undecodable ids are
/// `None`; the crawler still probes those by package.json.
pub(crate) fn decode_vlt_dep_id(dir_name: &str) -> Option<(String, String)> {
    let id = split_dep_id(dir_name)?;
    let (name, version) = id.registry_identity()?;
    Some((name.to_string(), version.to_string()))
}

fn with_trailing_slash(url: &str) -> String {
    if url.ends_with('/') {
        url.to_string()
    } else {
        format!("{url}/")
    }
}

/// Does a decoded registry segment name vlt's default registry, given the
/// lock's `options` (vlt `usesDefaultRegistry`)? `''`, the default alias
/// (`default-registry-alias`, else `npm`), an alias whose URL is
/// `options.registry`, or `options.registry` itself as a URL segment.
/// Every other segment (named aliases, scoped registries, jsr) is foreign.
pub(crate) fn is_default_registry(segment: &str, options: Option<&Map<String, Value>>) -> bool {
    if segment.is_empty() {
        return true;
    }
    let alias = match options.and_then(|o| o.get("default-registry-alias")) {
        None | Some(Value::Null) => Some("npm"),
        Some(Value::String(alias)) => Some(alias.as_str()),
        Some(_) => None,
    };
    if alias == Some(segment) {
        return true;
    }
    let Some(registry) = options
        .and_then(|o| o.get("registry"))
        .and_then(Value::as_str)
    else {
        return false;
    };
    let registry = with_trailing_slash(registry);
    let aliased = options
        .and_then(|o| o.get("registries"))
        .and_then(|r| r.get(segment))
        .and_then(Value::as_str);
    if aliased.is_some_and(|url| with_trailing_slash(url) == registry) {
        return true;
    }
    reqwest::Url::parse(segment).is_ok_and(|url| matches!(url.scheme(), "http" | "https"))
        && with_trailing_slash(segment) == registry
}

// ── lock-level sniff ─────────────────────────────────────────────────────

/// A `vlt-lock.json` that parsed as a JSON object with a known version.
#[derive(Debug, Clone)]
pub(crate) struct ParsedLock {
    /// `None` when `lockfileVersion` is absent (vlt ≤ 0.0.0-18).
    pub(crate) version: Option<u64>,
    pub(crate) json: Map<String, Value>,
}

impl ParsedLock {
    pub(crate) fn options(&self) -> Option<&Map<String, Value>> {
        self.json.get("options").and_then(Value::as_object)
    }

    pub(crate) fn nodes(&self) -> Option<&Map<String, Value>> {
        self.json.get("nodes").and_then(Value::as_object)
    }

    pub(crate) fn edges(&self) -> Option<&Map<String, Value>> {
        self.json.get("edges").and_then(Value::as_object)
    }

    /// The grammar for ids written into this lock.
    pub(crate) fn new_id_era(&self) -> DepIdEra {
        DepIdEra::for_lockfile_version(self.version)
    }
}

/// What reading a `vlt-lock.json` found. vlt itself cannot read a BOM or a
/// non-object, and fails on any version but `0` and `1`, so none of those
/// is ever parsed around.
#[derive(Debug, Clone)]
pub(crate) enum LockSniff {
    Readable(ParsedLock),
    /// Starts with U+FEFF; never stripped.
    Bom,
    /// Not a JSON object. serde_json also refuses a lone surrogate escape,
    /// which JS `JSON.parse` would accept.
    NotJsonObject,
    /// `lockfileVersion` is present but not the integer token `0` or `1`
    /// (`1.0`, `1e0`, `"1"`, `2`, `null`, ...), as its raw JSON token.
    UnsupportedVersion(String),
}

fn raw_top_level_token(text: &str, key: &str) -> Option<String> {
    let members: HashMap<String, &RawValue> = serde_json::from_str(text).ok()?;
    members.get(key).map(|raw| raw.get().to_string())
}

pub(crate) fn sniff_lock(text: &str) -> LockSniff {
    if text.starts_with('\u{feff}') {
        return LockSniff::Bom;
    }
    let Ok(Value::Object(json)) = serde_json::from_str::<Value>(text) else {
        return LockSniff::NotJsonObject;
    };
    let version = match json.get("lockfileVersion") {
        None => None,
        Some(v) => match v.as_u64() {
            Some(n @ (0 | 1)) => Some(n),
            _ => {
                let raw = raw_top_level_token(text, "lockfileVersion");
                return LockSniff::UnsupportedVersion(raw.unwrap_or_else(|| v.to_string()));
            }
        },
    };
    LockSniff::Readable(ParsedLock { version, json })
}

// ── sections ─────────────────────────────────────────────────────────────

/// The lines of a lock, split on `\n`; each keeps its own trailing `\r`,
/// and joining with `\n` gives the text back.
pub(crate) fn split_lines(text: &str) -> Vec<&str> {
    text.split('\n').collect()
}

fn strip_cr(line: &str) -> (&str, bool) {
    match line.strip_suffix('\r') {
        Some(body) => (body, true),
        None => (line, false),
    }
}

/// Where a top-level `nodes` or `edges` section sits in the lock's lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SectionSpan {
    /// The one-line empty form `  "nodes": {},`.
    Inline { line: usize },
    /// `  "nodes": {` at `open`, entries strictly between, `  },` at `close`.
    Block { open: usize, close: usize },
}

impl SectionSpan {
    pub(crate) fn entry_lines(self) -> std::ops::Range<usize> {
        match self {
            SectionSpan::Inline { line } => line + 1..line + 1,
            SectionSpan::Block { open, close } => open + 1..close,
        }
    }
}

fn locate_section(lines: &[&str], name: &str) -> Option<SectionSpan> {
    let header = format!("  \"{name}\": {{");
    let (open, rest) = lines.iter().enumerate().find_map(|(i, line)| {
        let (body, _) = strip_cr(line);
        body.strip_prefix(header.as_str()).map(|rest| (i, rest))
    })?;
    match rest {
        "" => lines
            .iter()
            .enumerate()
            .skip(open + 1)
            .find(|(_, line)| matches!(strip_cr(line).0, "  }" | "  },"))
            .map(|(close, _)| SectionSpan::Block { open, close }),
        "}" | "}," => Some(SectionSpan::Inline { line: open }),
        _ => None,
    }
}

/// The nodes section in vlt's canonical layout. `None` when absent or laid
/// out any other way; a caller whose parsed lock has nodes refuses then.
pub(crate) fn nodes_block(lines: &[&str]) -> Option<SectionSpan> {
    locate_section(lines, "nodes")
}

pub(crate) fn edges_block(lines: &[&str]) -> Option<SectionSpan> {
    locate_section(lines, "edges")
}

// ── entry lines ──────────────────────────────────────────────────────────

const ENTRY_INDENT: &str = "    ";

/// Split entry text `"<key>": <value>` whose key has no JSON escapes.
fn split_entry_text(text: &str) -> Option<(&str, &str)> {
    let rest = text.strip_prefix('"')?;
    let close = rest.find(['"', '\\'])?;
    if rest.as_bytes()[close] != b'"' {
        return None;
    }
    let value = rest[close + 1..].strip_prefix(": ")?;
    Some((&rest[..close], value))
}

/// `(entry text, comma, cr)` of a 4-space-indented entry line.
fn split_entry_line(line: &str) -> Option<(&str, bool, bool)> {
    let (body, cr) = strip_cr(line);
    let body = body.strip_prefix(ENTRY_INDENT)?;
    if !body.starts_with('"') {
        return None;
    }
    let (text, comma) = match body.strip_suffix(',') {
        Some(text) => (text, true),
        None => (body, false),
    };
    Some((text, comma, cr))
}

/// Render an entry line: 4-space indent, the entry text, a comma on every
/// entry but a section's last, and the line's own `\r`.
pub(crate) fn render_entry_line(entry_text: &str, comma: bool, cr: bool) -> String {
    format!(
        "{ENTRY_INDENT}{entry_text}{}{}",
        if comma { "," } else { "" },
        if cr { "\r" } else { "" }
    )
}

pub(crate) fn entry_text(key: &str, raw_value: &str) -> String {
    format!("\"{key}\": {raw_value}")
}

/// One node: `"<DepID>": [E0,E1,E2?,E3?,E4…]` with every element kept as
/// its raw top-level slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeEntry<'a> {
    pub(crate) key: &'a str,
    pub(crate) tuple: &'a str,
    pub(crate) elems: Vec<&'a str>,
}

impl NodeEntry<'_> {
    pub(crate) fn name(&self) -> Option<String> {
        serde_json::from_str(self.elems[1]).ok()
    }

    /// `E2`/`E3` as raw slices; `None` when the tuple is shorter.
    pub(crate) fn slot(&self, index: usize) -> Option<&str> {
        self.elems.get(index).copied()
    }

    pub(crate) fn entry_text(&self) -> String {
        entry_text(self.key, self.tuple)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeLine<'a> {
    pub(crate) entry: NodeEntry<'a>,
    pub(crate) comma: bool,
    pub(crate) cr: bool,
}

pub(crate) fn parse_node_line(line: &str) -> Option<NodeLine<'_>> {
    let (text, comma, cr) = split_entry_line(line)?;
    Some(NodeLine {
        entry: parse_node_entry_text(text)?,
        comma,
        cr,
    })
}

/// Parse node entry text (a line minus indent, comma and `\r`), the form
/// ledgers record.
pub(crate) fn parse_node_entry_text(text: &str) -> Option<NodeEntry<'_>> {
    let (key, tuple) = split_entry_text(text)?;
    let elems = split_tuple_elements(tuple)?;
    let is_string = |raw: &str| raw.starts_with('"') && serde_json::from_str::<String>(raw).is_ok();
    let string_or_null = |raw: &&str| *raw == "null" || is_string(raw);
    let well_formed = elems.len() >= 2
        && matches!(elems[0], "0" | "1" | "2" | "3")
        && is_string(elems[1])
        && elems.get(2).is_none_or(string_or_null)
        && elems.get(3).is_none_or(string_or_null);
    well_formed.then_some(NodeEntry { key, tuple, elems })
}

/// Raw top-level elements of a tuple `[e0,e1,…]`: the text must parse as a
/// JSON array, and elements are separated by exactly one `,` with no
/// surrounding whitespace.
pub(crate) fn split_tuple_elements(tuple: &str) -> Option<Vec<&str>> {
    let parsed = serde_json::from_str::<Value>(tuple).ok()?;
    let expected = parsed.as_array()?.len();
    let interior = tuple.strip_prefix('[')?.strip_suffix(']')?;
    let bytes = interior.as_bytes();
    let mut elems = Vec::new();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            match b {
                b'\\' => i += 1,
                b'"' => in_string = false,
                _ => {}
            }
        } else {
            match b {
                b'"' => in_string = true,
                b'[' | b'{' => depth += 1,
                b']' | b'}' => depth = depth.checked_sub(1)?,
                b',' if depth == 0 => {
                    elems.push(&interior[start..i]);
                    start = i + 1;
                }
                _ => {}
            }
        }
        i += 1;
    }
    if !interior.is_empty() {
        elems.push(&interior[start..]);
    }
    let tight = |e: &&str| {
        !e.is_empty()
            && !e.starts_with(|c: char| c.is_ascii_whitespace())
            && !e.ends_with(|c: char| c.is_ascii_whitespace())
    };
    (elems.len() == expected && elems.iter().all(tight)).then_some(elems)
}

/// A tuple with slots [2] and [3] replaced and `E0`, `E1`, `E4…` kept raw.
/// An absent slot is `null` when a later element follows and is dropped
/// otherwise, which is how vlt lays out unused slots.
pub(crate) fn render_tuple_with_slots(
    elems: &[&str],
    slot2: Option<&str>,
    slot3: Option<&str>,
) -> String {
    let tail = elems.get(4..).unwrap_or_default();
    let mut out: Vec<&str> = elems.iter().take(2).copied().collect();
    let slots = [slot2, slot3];
    let kept = if tail.is_empty() {
        slots.iter().rposition(Option::is_some).map_or(0, |i| i + 1)
    } else {
        2
    };
    out.extend(slots[..kept].iter().map(|s| s.unwrap_or("null")));
    out.extend_from_slice(tail);
    format!("[{}]", out.join(","))
}

pub(crate) const EDGE_TYPES: [&str; 5] = ["prod", "dev", "optional", "peer", "peerOptional"];

/// One edge: `"<fromDepID> <depName>": "<type> <bareSpec> <toDepID|MISSING>"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EdgeEntry<'a> {
    pub(crate) key: &'a str,
    pub(crate) raw_value: &'a str,
    pub(crate) value: String,
}

impl EdgeEntry<'_> {
    pub(crate) fn from(&self) -> &str {
        self.key.split_once(' ').map_or(self.key, |(from, _)| from)
    }

    /// The dependency name (an alias when the spec is `npm:`).
    pub(crate) fn dep_name(&self) -> &str {
        self.key.split_once(' ').map_or("", |(_, name)| name)
    }

    pub(crate) fn edge_type(&self) -> &str {
        self.value.split_once(' ').map_or("", |(ty, _)| ty)
    }

    /// The bare spec, which may itself contain spaces.
    pub(crate) fn spec(&self) -> &str {
        let (_, rest) = self.value.split_once(' ').unwrap_or_default();
        rest.rsplit_once(' ').map_or("", |(spec, _)| spec)
    }

    /// The target DepID, or `MISSING`.
    pub(crate) fn target(&self) -> &str {
        self.value.rsplit_once(' ').map_or("", |(_, to)| to)
    }

    pub(crate) fn entry_text(&self) -> String {
        entry_text(self.key, self.raw_value)
    }

    pub(crate) fn sort_key(&self) -> EdgeSortKey<'_> {
        EdgeSortKey {
            from: self.from(),
            edge_type: self.edge_type(),
            to: self.target(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EdgeLine<'a> {
    pub(crate) entry: EdgeEntry<'a>,
    pub(crate) comma: bool,
    pub(crate) cr: bool,
}

pub(crate) fn parse_edge_line(line: &str) -> Option<EdgeLine<'_>> {
    let (text, comma, cr) = split_entry_line(line)?;
    Some(EdgeLine {
        entry: parse_edge_entry_text(text)?,
        comma,
        cr,
    })
}

pub(crate) fn parse_edge_entry_text(text: &str) -> Option<EdgeEntry<'_>> {
    let (key, raw_value) = split_entry_text(text)?;
    let (from, name) = key.split_once(' ')?;
    if from.is_empty()
        || name.is_empty()
        || !raw_value.starts_with('"')
        || !raw_value.ends_with('"')
    {
        return None;
    }
    let value: String = serde_json::from_str(raw_value).ok()?;
    let entry = EdgeEntry {
        key,
        raw_value,
        value,
    };
    let (_, rest) = entry.value.split_once(' ')?;
    let (spec, to) = rest.rsplit_once(' ')?;
    let well_formed = EDGE_TYPES.contains(&entry.edge_type()) && !spec.is_empty() && !to.is_empty();
    well_formed.then_some(entry)
}

/// Root (`file~_d`, `file·.`) and workspace (`workspace~…`, `workspace·…`)
/// importers: edge sources that are never nodes.
pub(crate) fn is_importer_dep_id(id: &str) -> bool {
    id == "file~_d"
        || id == "file·."
        || id.strip_prefix("workspace~").is_some_and(|p| !p.is_empty())
        || id.strip_prefix("workspace·").is_some_and(|p| !p.is_empty())
}

// ── ordering ─────────────────────────────────────────────────────────────

/// The primary order of vlt's `localeCompare(…, 'en')` over the DepID
/// alphabet (Node 24.21 ICU), lowest first; ASCII letters share a primary
/// with their uppercase twin. Pinned by `tests/fixtures/vlt/collation-golden.json`.
const COLLATION_PRIMARY: &str =
    " _-,;:!?.·'\"()[]{}§@*/\\&#%`^+<=>|~$0123456789abcdefghijklmnopqrstuvwxyz";

fn collation_weight(c: char) -> Option<(usize, bool)> {
    let upper = c.is_ascii_uppercase();
    let folded = c.to_ascii_lowercase();
    COLLATION_PRIMARY
        .chars()
        .position(|p| p == folded)
        .map(|primary| (primary, upper))
}

/// vlt's `a.localeCompare(b, 'en')`, restricted to the collation table:
/// primary weights first (a shorter prefix sorts first), then case
/// position by position, lowercase first. `None` is "Unknown": a character
/// outside the table (a tilde-era `file:` path with non-ASCII, say), for
/// which callers fall back to in-place placement.
pub(crate) fn vlt_collate(a: &str, b: &str) -> Option<Ordering> {
    let weigh = |s: &str| s.chars().map(collation_weight).collect::<Option<Vec<_>>>();
    let (wa, wb) = (weigh(a)?, weigh(b)?);
    let primary = wa.iter().map(|w| w.0).cmp(wb.iter().map(|w| w.0));
    Some(primary.then_with(|| wa.iter().map(|w| w.1).cmp(wb.iter().map(|w| w.1))))
}

/// The fields vlt's `formatEdges` sorts by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EdgeSortKey<'a> {
    pub(crate) from: &'a str,
    pub(crate) edge_type: &'a str,
    /// A target DepID or `MISSING`; vlt sorts a missing target as `''`.
    pub(crate) to: &'a str,
}

fn missing_as_empty(to: &str) -> &str {
    if to == "MISSING" {
        ""
    } else {
        to
    }
}

/// vlt's edge order: importer sources first, then `from`, `type` and `to`
/// by [`vlt_collate`]. The edge name is not a key. `None` when a needed
/// comparison is Unknown.
pub(crate) fn vlt_edge_cmp(a: EdgeSortKey<'_>, b: EdgeSortKey<'_>) -> Option<Ordering> {
    let importer = is_importer_dep_id(b.from).cmp(&is_importer_dep_id(a.from));
    if importer != Ordering::Equal {
        return Some(importer);
    }
    for (x, y) in [
        (a.from, b.from),
        (a.edge_type, b.edge_type),
        (missing_as_empty(a.to), missing_as_empty(b.to)),
    ] {
        match vlt_collate(x, y)? {
            Ordering::Equal => {}
            decided => return Some(decided),
        }
    }
    Some(Ordering::Equal)
}

// ── vendored path rule ───────────────────────────────────────────────────

const VENDOR_NPM_PREFIX: &str = ".socket/vendor/npm/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VendoredShape {
    /// `<uuid>/[@s/]<bare>-<version>/node_modules/[@s/]<bare>`, the directory
    /// artifact socket-patch writes for vlt.
    Dir,
    /// `<uuid>/[@s/]<bare>-<version>.tgz`, an npm-flavor artifact a user
    /// installed with vlt (read-only recognition).
    Tgz,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VendoredPath {
    pub(crate) uuid: String,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) shape: VendoredShape,
}

fn leaf_version<'l>(bare: &str, leaf: &'l str) -> Option<&'l str> {
    leaf.strip_prefix(bare)?
        .strip_prefix('-')
        .filter(|v| is_npm_semver(v))
}

/// A decoded `file` path of the vendored directory shape, with the name
/// read from its `node_modules/` segments.
pub(crate) fn parse_vendored_dir_path(path: &str) -> Option<VendoredPath> {
    let segments: Vec<&str> = path.strip_prefix(VENDOR_NPM_PREFIX)?.split('/').collect();
    let (uuid, scope, leaf, bare) = match segments.as_slice() {
        [uuid, leaf, "node_modules", bare] => (*uuid, None, *leaf, *bare),
        [uuid, scope, leaf, "node_modules", scope_again, bare] if scope == scope_again => {
            (*uuid, Some(*scope), *leaf, *bare)
        }
        _ => return None,
    };
    let name = match scope {
        Some(scope) if scope.starts_with('@') => format!("{scope}/{bare}"),
        Some(_) => return None,
        None => bare.to_string(),
    };
    if !is_canonical_uuid(uuid) || !is_registry_package_name(&name) {
        return None;
    }
    Some(VendoredPath {
        uuid: uuid.to_string(),
        version: leaf_version(bare, leaf)?.to_string(),
        name,
        shape: VendoredShape::Dir,
    })
}

/// The vendored path rule (hosted matching, vendored target analysis, VEX,
/// depscan): is a decoded `file` path a vendored vlt artifact of `name`?
pub(crate) fn parse_vendored_path(path: &str, name: &str) -> Option<VendoredPath> {
    if let Some(dir) = parse_vendored_dir_path(path) {
        return (dir.name == name).then_some(dir);
    }
    if !is_registry_package_name(name) {
        return None;
    }
    let rest = path.strip_prefix(VENDOR_NPM_PREFIX)?.strip_suffix(".tgz")?;
    let (uuid, leaf) = rest.split_once('/')?;
    let (leaf_scope, leaf) = match leaf.split_once('/') {
        Some((scope, leaf)) => (Some(scope), leaf),
        None => (None, leaf),
    };
    let (name_scope, bare) = match name.split_once('/') {
        Some((scope, bare)) => (Some(scope), bare),
        None => (None, name),
    };
    if leaf_scope != name_scope || !is_canonical_uuid(uuid) {
        return None;
    }
    Some(VendoredPath {
        uuid: uuid.to_string(),
        name: name.to_string(),
        version: leaf_version(bare, leaf)?.to_string(),
        shape: VendoredShape::Tgz,
    })
}

/// `rel` of the vendored directory artifact:
/// `.socket/vendor/npm/<uuid>/[@s/]<bare>-<version>/node_modules/<name>`.
pub(crate) fn vendored_dir_rel(uuid: &str, name: &str, version: &str) -> String {
    let leaf = match name.split_once('/') {
        Some((scope, bare)) => format!("{scope}/{bare}-{version}"),
        None => format!("{name}-{version}"),
    };
    format!("{VENDOR_NPM_PREFIX}{uuid}/{leaf}/node_modules/{name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::constants::npm_family::{
        VLT_CONFIG, VLT_HIDDEN_LOCK_REL, VLT_LEGACY_WORKSPACES, VLT_LOCK, VLT_SETUP_MARKERS,
        VLT_STORE_DIR,
    };

    const UUID: &str = "0b1f6e2a-3c4d-4e5f-8a9b-0c1d2e3f4a5b";

    use DepIdEra::{Legacy, Tilde};
    use DepIdKind::{File, Git, Registry, Remote, Workspace};

    type Split = (
        DepIdEra,
        DepIdKind,
        &'static str,
        Option<&'static str>,
        Option<&'static str>,
    );

    struct CodecRow {
        id: String,
        split: Option<Split>,
        identity: Option<(&'static str, &'static str)>,
    }

    fn row(
        id: impl Into<String>,
        split: Option<Split>,
        identity: Option<(&'static str, &'static str)>,
    ) -> CodecRow {
        CodecRow {
            id: id.into(),
            split,
            identity,
        }
    }

    fn reg(era: DepIdEra, first: &'static str, second: &'static str) -> Option<Split> {
        Some((era, Registry, first, Some(second), None))
    }

    fn reg_x(
        era: DepIdEra,
        first: &'static str,
        second: &'static str,
        extra: &'static str,
    ) -> Option<Split> {
        Some((era, Registry, first, Some(second), Some(extra)))
    }

    fn typed(era: DepIdEra, kind: DepIdKind, first: &'static str) -> Option<Split> {
        Some((era, kind, first, None, None))
    }

    // Verbatim from depscan `workspaces/lib/src/socket-patch/vlt-dep-id.test.ts`
    // CODEC_ROWS (cross-checked there against vlt 1.2.0 and rc.14
    // `splitDepID`). Its lone-surrogate row has no Rust `&str` spelling.
    fn codec_rows() -> Vec<CodecRow> {
        let d19 = |base: &str| base.replace("<uuid>", UUID);
        vec![
            row("··ms@2.1.3", reg(Legacy, "", "ms@2.1.3"), Some(("ms", "2.1.3"))),
            row(
                "·npm·@isaacs§string-locale-compare@1.1.0",
                reg(Legacy, "npm", "@isaacs/string-locale-compare@1.1.0"),
                Some(("@isaacs/string-locale-compare", "1.1.0")),
            ),
            row(
                "··@sindresorhus§is@4.6.0",
                reg(Legacy, "", "@sindresorhus/is@4.6.0"),
                Some(("@sindresorhus/is", "4.6.0")),
            ),
            row(
                "·npm·u@1.0.0%2Bbuild.1",
                reg(Legacy, "npm", "u@1.0.0+build.1"),
                Some(("u", "1.0.0+build.1")),
            ),
            row(
                "··ms@2.1.3·%3Aroot%20%3E%20%23debug%20%3E%20%23ms",
                reg_x(Legacy, "", "ms@2.1.3", "%3Aroot%20%3E%20%23debug%20%3E%20%23ms"),
                Some(("ms", "2.1.3")),
            ),
            row(
                "·npm·x@1.0.0·%E1%B9%97%3A3",
                reg_x(Legacy, "npm", "x@1.0.0", "%E1%B9%97%3A3"),
                Some(("x", "1.0.0")),
            ),
            row("~npm~@a+b@1.0.0", reg(Tilde, "npm", "@a/b@1.0.0"), Some(("@a/b", "1.0.0"))),
            row("~npm~a__b@1.0.0", reg(Tilde, "npm", "a_b@1.0.0"), Some(("a_b", "1.0.0"))),
            row(
                "~npm~u@1.0.0_pbuild.1",
                reg(Tilde, "npm", "u@1.0.0+build.1"),
                Some(("u", "1.0.0+build.1")),
            ),
            row(
                "~npm~is-number@6.0.0~_croot_s_g_s#to-regex-range_s_g_s#is-number",
                reg_x(
                    Tilde,
                    "npm",
                    "is-number@6.0.0",
                    "_croot_s_g_s#to-regex-range_s_g_s#is-number",
                ),
                Some(("is-number", "6.0.0")),
            ),
            row(
                "~npm~react-dom@18.2.0~peer.ace93b147498ef7a",
                reg_x(Tilde, "npm", "react-dom@18.2.0", "peer.ace93b147498ef7a"),
                Some(("react-dom", "18.2.0")),
            ),
            row("~npm~x@1~peer.2", reg_x(Tilde, "npm", "x@1", "peer.2"), None),
            row(
                "~acme~left-pad@1.3.0",
                reg(Tilde, "acme", "left-pad@1.3.0"),
                Some(("left-pad", "1.3.0")),
            ),
            row(
                "~http_c++127.0.0.1_c4873+~x@1.0.0",
                reg(Tilde, "http://127.0.0.1:4873/", "x@1.0.0"),
                Some(("x", "1.0.0")),
            ),
            row(
                "~jsr~@jsr+std____semver@1.0.8",
                reg(Tilde, "jsr", "@jsr/std__semver@1.0.8"),
                Some(("@jsr/std__semver", "1.0.8")),
            ),
            row(
                "git~github_cuser+proj~v1.0.0",
                Some((Tilde, Git, "github:user/proj", Some("v1.0.0"), None)),
                None,
            ),
            row("file~_d", typed(Tilde, File, "."), None),
            row(
                "remote~https_c++e.com+r-1.0.0.tgz",
                typed(Tilde, Remote, "https://e.com/r-1.0.0.tgz"),
                None,
            ),
            row("workspace~packages+a", typed(Tilde, Workspace, "packages/a"), None),
            row("··foo@1.2.3", reg(Legacy, "", "foo@1.2.3"), Some(("foo", "1.2.3"))),
            row("·npm·foo@1.2.3", reg(Legacy, "npm", "foo@1.2.3"), Some(("foo", "1.2.3"))),
            row("~npm~foo@1.2.3", reg(Tilde, "npm", "foo@1.2.3"), Some(("foo", "1.2.3"))),
            row(
                "··@scope§bar@2.0.0",
                reg(Legacy, "", "@scope/bar@2.0.0"),
                Some(("@scope/bar", "2.0.0")),
            ),
            row(
                "·npm·@scope§bar@2.0.0",
                reg(Legacy, "npm", "@scope/bar@2.0.0"),
                Some(("@scope/bar", "2.0.0")),
            ),
            row(
                "~npm~@scope+bar@2.0.0",
                reg(Tilde, "npm", "@scope/bar@2.0.0"),
                Some(("@scope/bar", "2.0.0")),
            ),
            row(
                "··u@1.0.0%2Bbuild.1",
                reg(Legacy, "", "u@1.0.0+build.1"),
                Some(("u", "1.0.0+build.1")),
            ),
            row("·acme·y@1.0.0", reg(Legacy, "acme", "y@1.0.0"), Some(("y", "1.0.0"))),
            row("~acme~y@1.0.0", reg(Tilde, "acme", "y@1.0.0"), Some(("y", "1.0.0"))),
            row(
                "·http%3A§§127.0.0.1%3A4873§·x@1.0.0",
                reg(Legacy, "http://127.0.0.1:4873/", "x@1.0.0"),
                Some(("x", "1.0.0")),
            ),
            row(
                "·npm·ms@2.1.3·%3Aroot%20%3E%20%23debug%20%3E%20%23ms",
                reg_x(Legacy, "npm", "ms@2.1.3", "%3Aroot%20%3E%20%23debug%20%3E%20%23ms"),
                Some(("ms", "2.1.3")),
            ),
            row(
                "~npm~ms@2.1.3~_croot_s_g_s#debug_s_g_s#ms",
                reg_x(Tilde, "npm", "ms@2.1.3", "_croot_s_g_s#debug_s_g_s#ms"),
                Some(("ms", "2.1.3")),
            ),
            row("·npm·x@1·%E1%B9%97%3A3", reg_x(Legacy, "npm", "x@1", "%E1%B9%97%3A3"), None),
            row(
                "~npm~x@1~peer.dbd5ca8b03a66489",
                reg_x(Tilde, "npm", "x@1", "peer.dbd5ca8b03a66489"),
                None,
            ),
            row(
                d19("file·.socket§vendor§npm§<uuid>§left-pad-1.3.0§node_modules§left-pad"),
                Some((
                    Legacy,
                    File,
                    ".socket/vendor/npm/0b1f6e2a-3c4d-4e5f-8a9b-0c1d2e3f4a5b/left-pad-1.3.0/node_modules/left-pad",
                    None,
                    None,
                )),
                None,
            ),
            row(
                d19("file~.socket+vendor+npm+<uuid>+left-pad-1.3.0+node__modules+left-pad"),
                Some((
                    Tilde,
                    File,
                    ".socket/vendor/npm/0b1f6e2a-3c4d-4e5f-8a9b-0c1d2e3f4a5b/left-pad-1.3.0/node_modules/left-pad",
                    None,
                    None,
                )),
                None,
            ),
            row(
                d19("file·.socket§vendor§npm§<uuid>§@sc§pkg-1.0.0§node_modules§@sc§pkg"),
                Some((
                    Legacy,
                    File,
                    ".socket/vendor/npm/0b1f6e2a-3c4d-4e5f-8a9b-0c1d2e3f4a5b/@sc/pkg-1.0.0/node_modules/@sc/pkg",
                    None,
                    None,
                )),
                None,
            ),
            row(
                d19("file~.socket+vendor+npm+<uuid>+@sc+pkg-1.0.0+node__modules+@sc+pkg"),
                Some((
                    Tilde,
                    File,
                    ".socket/vendor/npm/0b1f6e2a-3c4d-4e5f-8a9b-0c1d2e3f4a5b/@sc/pkg-1.0.0/node_modules/@sc/pkg",
                    None,
                    None,
                )),
                None,
            ),
            row("workspace·packages§a", typed(Legacy, Workspace, "packages/a"), None),
            row(
                "remote·https%3A§§e.com§r-1.0.0.tgz",
                typed(Legacy, Remote, "https://e.com/r-1.0.0.tgz"),
                None,
            ),
            row("file·.", typed(Legacy, File, "."), None),
            row(
                "git·github%3Auser§proj·v1.0.0",
                Some((Legacy, Git, "github:user/proj", Some("v1.0.0"), None)),
                None,
            ),
            row("file~.+packages+a", typed(Tilde, File, "./packages/a"), None),
            row("file·.§packages§a", typed(Legacy, File, "./packages/a"), None),
            row("file~a~peer.1", Some((Tilde, File, "a", None, Some("peer.1"))), None),
            row(
                "·jsr·@jsr§std__semver@1.0.8",
                reg(Legacy, "jsr", "@jsr/std__semver@1.0.8"),
                Some(("@jsr/std__semver", "1.0.8")),
            ),
            row(
                "·https%3A§§npm.jsr.io§·@jsr§std__semver@1.0.8",
                reg(Legacy, "https://npm.jsr.io/", "@jsr/std__semver@1.0.8"),
                Some(("@jsr/std__semver", "1.0.8")),
            ),
            row("~~a@1.0.0", reg(Tilde, "", "a@1.0.0"), Some(("a", "1.0.0"))),
            row("~npm~a@1.0.0~", reg_x(Tilde, "npm", "a@1.0.0", ""), Some(("a", "1.0.0"))),
            row("·npm·a~b@1.0.0", reg(Legacy, "npm", "a~b@1.0.0"), Some(("a~b", "1.0.0"))),
            row("~npm~a·b@1.0.0", reg(Tilde, "npm", "a·b@1.0.0"), None),
            row("~npm~a_@1.0.0", reg(Tilde, "npm", "a_@1.0.0"), Some(("a_", "1.0.0"))),
            row("~npm~_1f_0a_zz_@1.0.0", reg(Tilde, "npm", "\u{1f}\n_zz_@1.0.0"), None),
            row(
                "~npm~@__koii+web3.js@0.1.11",
                reg(Tilde, "npm", "@_koii/web3.js@0.1.11"),
                Some(("@_koii/web3.js", "0.1.11")),
            ),
            row(
                "·npm·@_koii§web3.js@0.1.11",
                reg(Legacy, "npm", "@_koii/web3.js@0.1.11"),
                Some(("@_koii/web3.js", "0.1.11")),
            ),
            row(
                "git~github_cu+p~v1~peer.1",
                Some((Tilde, Git, "github:u/p", Some("v1"), Some("peer.1"))),
                None,
            ),
            row(
                "git·github%3Au§p·v1·peer.1",
                Some((Legacy, Git, "github:u/p", Some("v1"), Some("peer.1"))),
                None,
            ),
            row(
                "remote~https_c++e.com+r.tgz~peer.1",
                Some((Tilde, Remote, "https://e.com/r.tgz", None, Some("peer.1"))),
                None,
            ),
            row(
                "workspace~packages+a~peer.1",
                Some((Tilde, Workspace, "packages/a", None, Some("peer.1"))),
                None,
            ),
            row("·npm·a@1.0.0%ZZ", None, None),
            row("·npm·a@1.0.0%4", None, None),
            row("·npm·a@1.0.0%C3", None, None),
            row("·npm·a@1.0.0%ED%A0%80", None, None),
            row("·npm%zz·a@1.0.0", None, None),
            row("··ms@2.1.3·%ZZ", None, None),
            row("file·.socket%2", None, None),
            row("file·a·%ZZ", None, None),
            row("workspace·a·%ZZ", None, None),
            row("remote·https%3A§§e.com§r.tgz·%ZZ", None, None),
            row("git·github%3Auser·v1%G0", None, None),
            row("npm~foo@1.0.0", None, None),
            row("foo@1.0.0", None, None),
            row("link~x", None, None),
            row("GIT~x~y", None, None),
            row("~npm~a@1.0.0~extra~more", None, None),
            row("file~a~b~c", None, None),
            row("~npm", None, None),
            row("~npm~", None, None),
            row("file~", None, None),
            row("git~~sel", None, None),
        ]
    }

    fn as_split(id: &DepId) -> (DepIdEra, DepIdKind, &str, Option<&str>, Option<&str>) {
        (
            id.era,
            id.kind,
            id.first.as_str(),
            id.second.as_deref(),
            id.extra.as_deref(),
        )
    }

    #[test]
    fn splits_and_identifies_every_codec_row() {
        for r in codec_rows() {
            let split = split_dep_id(&r.id);
            assert_eq!(split.as_ref().map(as_split), r.split, "split {}", r.id);
            assert_eq!(
                split.as_ref().and_then(DepId::registry_identity),
                r.identity,
                "identity {}",
                r.id
            );
            assert_eq!(
                decode_vlt_dep_id(&r.id),
                r.identity.map(|(n, v)| (n.to_string(), v.to_string())),
                "store decode {}",
                r.id
            );
        }
    }

    #[test]
    fn decides_the_era_by_prefix_only() {
        assert_eq!(split_dep_id("~npm~a·b@1.0.0").map(|d| d.era), Some(Tilde));
        assert_eq!(split_dep_id("·npm·a~b@1.0.0").map(|d| d.era), Some(Legacy));
        assert_eq!(split_dep_id("file~a·b").map(|d| d.era), Some(Tilde));
        assert_eq!(split_dep_id("file·a~b").map(|d| d.era), Some(Legacy));
        assert_eq!(
            split_dep_id("workspace·a~b~c").map(|d| d.first),
            Some("a~b~c".to_string())
        );
        assert_eq!(dep_id_era("filex~a"), None);
        assert_eq!(dep_id_era("Workspace~a"), None);
        assert_eq!(dep_id_era(""), None);
        assert_eq!(DepIdEra::for_lockfile_version(Some(1)), Tilde);
        assert_eq!(DepIdEra::for_lockfile_version(Some(0)), Legacy);
        assert_eq!(DepIdEra::for_lockfile_version(None), Legacy);
    }

    #[test]
    fn recovers_name_and_version_from_a_registry_second() {
        let long_name = "a".repeat(215);
        let long = format!("{long_name}@1.0.0");
        let rows: Vec<(&str, Option<(&str, &str)>)> = vec![
            ("a@1.0.0", Some(("a", "1.0.0"))),
            ("@s/p@1.0.0-rc.1+b.2", Some(("@s/p", "1.0.0-rc.1+b.2"))),
            ("JSONStream@1.3.5", Some(("JSONStream", "1.3.5"))),
            ("a-b.c@0.0.0-0", Some(("a-b.c", "0.0.0-0"))),
            ("@s/p", None),
            ("p", None),
            ("@1.0.0", None),
            ("a@", None),
            ("@s@1.0.0", None),
            ("a@b@1.0.0", None),
            ("a@v1.0.0", None),
            ("a@=1.0.0", None),
            ("a@01.0.0", None),
            ("a@1.0", None),
            ("a@1.0.0 ", None),
            ("a@^1.0.0", None),
            ("a@1.0.0-01", None),
            (
                "a@9007199254740991.0.0",
                Some(("a", "9007199254740991.0.0")),
            ),
            ("a@9007199254740992.0.0", None),
            ("a@99999999999999999999.0.0", None),
            ("a@1.9007199254740992.0", None),
            ("a@1.0.9007199254740992", None),
            (
                "a@1.0.0-99999999999999999999",
                Some(("a", "1.0.0-99999999999999999999")),
            ),
            (".a@1.0.0", None),
            ("_a@1.0.0", None),
            ("@s/.p@1.0.0", Some(("@s/.p", "1.0.0"))),
            ("@_s/p@1.0.0", Some(("@_s/p", "1.0.0"))),
            ("@s/_p@1.0.0", Some(("@s/_p", "1.0.0"))),
            ("@.s/p@1.0.0", Some(("@.s/p", "1.0.0"))),
            ("@_koii/web3.js@0.1.11", Some(("@_koii/web3.js", "0.1.11"))),
            ("a~'!()*@1.0.0", Some(("a~'!()*", "1.0.0"))),
            ("node_modules@1.0.0", None),
            ("Node_Modules@1.0.0", None),
            ("favicon.ico@1.0.0", None),
            ("@s/node_modules@1.0.0", Some(("@s/node_modules", "1.0.0"))),
            ("@/p@1.0.0", None),
            ("@s/@1.0.0", None),
            ("@s/p/q@1.0.0", None),
            ("@s/p q@1.0.0", None),
            ("a b@1.0.0", None),
            ("a/b@1.0.0", None),
            (long.as_str(), Some((long_name.as_str(), "1.0.0"))),
        ];
        for (second, expected) in rows {
            assert_eq!(registry_name_version(second), expected, "{second}");
        }
        assert!(is_npm_semver("1.0.0-0a.01b+001"));
        assert!(!is_npm_semver("1.0.0\n"));
        assert!(!is_npm_semver("١.0.0"));
        assert!(!is_npm_semver("18446744073709551616.0.0"));
    }

    #[test]
    fn encodes_segments_as_vlt_does_and_round_trips() {
        let d19 = format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0/node_modules/left-pad");
        let d19_tilde = format!(".socket+vendor+npm+{UUID}+left-pad-1.3.0+node__modules+left-pad");
        let d19_legacy = format!(".socket§vendor§npm§{UUID}§left-pad-1.3.0§node_modules§left-pad");
        let rows: Vec<(&str, &str, &str)> = vec![
            (".", "_d", "."),
            ("packages/my_lib", "packages+my__lib", "packages§my_lib"),
            ("a b+c:d~e", "a_sb_pc_cd_te", "a%20b%2Bc%3Ad~e"),
            ("trailing.", "trailing_d", "trailing."),
            ("ctl\n\u{1f}\u{0}", "ctl_0A_1F_00", "ctl%0A%1F%00"),
            ("@scope/pkg@1.0.0", "@scope+pkg@1.0.0", "@scope§pkg@1.0.0"),
            ("1.0.0+build.1", "1.0.0_pbuild.1", "1.0.0%2Bbuild.1"),
            (
                ":root > #debug > #ms",
                "_croot_s_g_s#debug_s_g_s#ms",
                "%3Aroot%20%3E%20%23debug%20%3E%20%23ms",
            ),
            ("ṗ:3", "ṗ_c3", "%E1%B9%97%3A3"),
            (
                "http://127.0.0.1:4873/",
                "http_c++127.0.0.1_c4873+",
                "http%3A§§127.0.0.1%3A4873§",
            ),
            (d19.as_str(), d19_tilde.as_str(), d19_legacy.as_str()),
            (
                "back\\slash<>\"|?*",
                "back_bslash_l_g_q_i_m_a",
                "back%5Cslash%3C%3E%22%7C%3F*",
            ),
            ("a·b§c", "a·b§c", "a%C2%B7b%C2%A7c"),
            ("naïve", "naïve", "na%C3%AFve"),
            ("\u{1F600}", "\u{1F600}", "%F0%9F%98%80"),
            ("x_", "x__", "x_"),
            ("_", "__", "_"),
            ("", "", ""),
        ];
        for (raw, tilde, legacy) in rows {
            for (era, expected) in [(Tilde, tilde), (Legacy, legacy)] {
                assert_eq!(encode_segment(raw, era), expected, "{era:?} {raw}");
                assert_eq!(
                    decode_segment(expected, era).as_deref(),
                    Some(raw),
                    "{era:?} {raw} back"
                );
            }
        }
    }

    #[test]
    fn decodes_tilde_escapes_the_way_vlt_does() {
        let rows = [
            ("_", "_"),
            ("a_", "a_"),
            ("_z", "_z"),
            ("_2A", "_2A"),
            ("_1f", "\u{1f}"),
            ("_0g", "_0g"),
            ("___", "__"),
            ("_d_d", ".."),
        ];
        for (encoded, decoded) in rows {
            assert_eq!(
                decode_segment(encoded, Tilde).as_deref(),
                Some(decoded),
                "{encoded}"
            );
        }
    }

    #[test]
    fn legacy_decode_validates_every_percent_escape() {
        for bad in [
            "%ZZ",
            "%4",
            "%C3",
            "%",
            "a%2",
            "%G0",
            "%ED%A0%80",
            "%C0%AF",
            "%80",
        ] {
            assert_eq!(decode_segment(bad, Legacy), None, "{bad}");
        }
        assert_eq!(decode_segment("%ZZ", Tilde).as_deref(), Some("%ZZ"));
        assert_eq!(decode_segment("%25%2f%2F", Legacy).as_deref(), Some("%//"));
        assert_eq!(decode_segment("%C2%A7", Legacy).as_deref(), Some("§"));
        assert_eq!(decode_segment("a§b@c", Legacy).as_deref(), Some("a/b@c"));
    }

    #[test]
    fn file_dep_id_matches_the_lock_spelling() {
        let rel = vendored_dir_rel(UUID, "@sc/pkg", "1.0.0");
        assert_eq!(
            file_dep_id(&rel, Tilde),
            format!("file~.socket+vendor+npm+{UUID}+@sc+pkg-1.0.0+node__modules+@sc+pkg")
        );
        assert_eq!(
            file_dep_id(&rel, Legacy),
            format!("file·.socket§vendor§npm§{UUID}§@sc§pkg-1.0.0§node_modules§@sc§pkg")
        );
        assert_eq!(file_dep_id(".", Tilde), "file~_d");
        assert_eq!(file_dep_id(".", Legacy), "file·.");
    }

    #[test]
    fn test_decode_vlt_dep_id_store_entries() {
        let owned = |n: &str, v: &str| Some((n.to_string(), v.to_string()));
        let rows = [
            ("··ms@2.1.3", owned("ms", "2.1.3")),
            (
                "·npm·@isaacs§string-locale-compare@1.1.0",
                owned("@isaacs/string-locale-compare", "1.1.0"),
            ),
            (
                "··@sindresorhus§is@4.6.0",
                owned("@sindresorhus/is", "4.6.0"),
            ),
            ("·npm·u@1.0.0%2Bbuild.1", owned("u", "1.0.0+build.1")),
            (
                "··ms@2.1.3·%3Aroot%20%3E%20%23debug%20%3E%20%23ms",
                owned("ms", "2.1.3"),
            ),
            ("·npm·x@1.0.0·%E1%B9%97%3A3", owned("x", "1.0.0")),
            ("~npm~@a+b@1.0.0", owned("@a/b", "1.0.0")),
            ("~npm~a__b@1.0.0", owned("a_b", "1.0.0")),
            ("~npm~u@1.0.0_pbuild.1", owned("u", "1.0.0+build.1")),
            (
                "~npm~is-number@6.0.0~_croot_s_g_s#to-regex-range_s_g_s#is-number",
                owned("is-number", "6.0.0"),
            ),
            (
                "~npm~react-dom@18.2.0~peer.ace93b147498ef7a",
                owned("react-dom", "18.2.0"),
            ),
            ("~npm~x@1~peer.2", None),
            ("~npm~x@1.0.0~peer.2", owned("x", "1.0.0")),
            ("~acme~left-pad@1.3.0", owned("left-pad", "1.3.0")),
            ("~http_c++127.0.0.1_c4873+~x@1.0.0", owned("x", "1.0.0")),
            (
                "~jsr~@jsr+std____semver@1.0.8",
                owned("@jsr/std__semver", "1.0.8"),
            ),
            ("git~github_cuser+proj~v1.0.0", None),
            ("file~.socket+vendor+npm+x+a-1.0.0.tgz", None),
            ("remote~https_c++e.com+r-1.0.0.tgz", None),
            ("workspace~packages+a", None),
            ("·npm·a@1.0.0%ZZ", None),
            ("node_modules", None),
            (".VLT.DELETE.1.~npm~ms@2.1.3", None),
        ];
        for (dir, expected) in rows {
            assert_eq!(decode_vlt_dep_id(dir), expected, "{dir}");
        }
    }

    fn options(json: &str) -> Map<String, Value> {
        serde_json::from_str(json).expect("options json")
    }

    #[test]
    fn default_registry_predicate() {
        let none = None;
        let empty = options("{}");
        let scalar = options(r#"{"registry":"http://127.0.0.1:4873"}"#);
        let scalar_slash = options(r#"{"registry":"http://127.0.0.1:4873/"}"#);
        let alias = options(r#"{"default-registry-alias":"corp"}"#);
        let alias_url = options(
            r#"{"registry":"https://r.example/npm/","registries":{"corp":"https://r.example/npm","acme":"https://acme.example/"}}"#,
        );
        let odd_alias = options(r#"{"default-registry-alias":5}"#);
        let null_alias = options(r#"{"default-registry-alias":null}"#);
        type Case<'a> = (&'a str, Option<&'a Map<String, Value>>, bool);
        let cases: Vec<Case<'_>> = vec![
            ("", none, true),
            ("npm", none, true),
            ("npm", Some(&empty), true),
            ("acme", Some(&empty), false),
            ("jsr", Some(&empty), false),
            ("https://npm.jsr.io/", Some(&empty), false),
            ("http://127.0.0.1:4873/", none, false),
            ("http://127.0.0.1:4873/", Some(&empty), false),
            ("http://127.0.0.1:4873/", Some(&scalar), true),
            ("http://127.0.0.1:4873", Some(&scalar), true),
            ("http://127.0.0.1:4873/", Some(&scalar_slash), true),
            ("http://127.0.0.1:4873", Some(&scalar_slash), true),
            ("http://127.0.0.1:4874/", Some(&scalar), false),
            ("https://127.0.0.1:4873/", Some(&scalar), false),
            ("", Some(&scalar), true),
            ("npm", Some(&scalar), true),
            ("corp", Some(&alias), true),
            ("npm", Some(&alias), false),
            ("", Some(&alias), true),
            ("corp", Some(&alias_url), true),
            ("acme", Some(&alias_url), false),
            ("https://r.example/npm", Some(&alias_url), true),
            ("https://acme.example/", Some(&alias_url), false),
            ("npm", Some(&odd_alias), false),
            ("5", Some(&odd_alias), false),
            ("npm", Some(&null_alias), true),
        ];
        for (segment, opts, expected) in cases {
            assert_eq!(
                is_default_registry(segment, opts),
                expected,
                "{segment:?} with {opts:?}"
            );
        }
        let not_a_url = options(r#"{"registry":"corp"}"#);
        assert!(!is_default_registry("corp", Some(&not_a_url)));
        for registry in ["file:///r/", "ftp://h/", "git+https://h/"] {
            let not_http = options(&format!(r#"{{"registry":"{registry}"}}"#));
            assert!(
                !is_default_registry(registry, Some(&not_http)),
                "{registry}"
            );
        }
    }

    fn readable(text: &str) -> ParsedLock {
        match sniff_lock(text) {
            LockSniff::Readable(lock) => lock,
            other => panic!("{text:?} sniffed as {other:?}"),
        }
    }

    #[test]
    fn sniff_decides_on_the_raw_version_token() {
        assert_eq!(readable(r#"{"lockfileVersion":0}"#).version, Some(0));
        assert_eq!(
            readable(r#"{"lockfileVersion": 1, "nodes": {}}"#).version,
            Some(1)
        );
        assert_eq!(readable(r#"{"nodes":{}}"#).version, None);
        assert_eq!(readable(r#"{"lockfileVersion":1}"#).new_id_era(), Tilde);
        assert_eq!(readable(r#"{"lockfileVersion":0}"#).new_id_era(), Legacy);
        assert_eq!(readable("{}").new_id_era(), Legacy);
        for token in [
            "1.0",
            "1e0",
            "1E0",
            "1.0000000000000001",
            "\"1\"",
            "\"\\u0031\"",
            "2",
            "-1",
            "-0",
            "null",
            "true",
            "[1]",
            "{\"v\": 1}",
        ] {
            for text in [
                format!("{{\"lockfileVersion\":{token}}}"),
                format!("{{\n  \"lockfileVersion\" :  {token} ,\n  \"nodes\": {{}}\n}}"),
                format!("{{\"options\":{{\"lockfileVersion\":1}},\"lockfileVersion\":{token}}}"),
                format!("{{\"lockfileVersion\":1,\"lockfileVersion\":{token}}}"),
            ] {
                match sniff_lock(&text) {
                    LockSniff::UnsupportedVersion(v) => assert_eq!(v, token, "{text}"),
                    other => panic!("{text} sniffed as {other:?}"),
                }
            }
        }
        assert_eq!(
            readable(r#"{"lockfileVersion":2,"lockfileVersion":1}"#).version,
            Some(1)
        );
    }

    #[test]
    fn sniff_refuses_bom_non_objects_and_lone_surrogates() {
        assert!(matches!(
            sniff_lock("\u{feff}{\"lockfileVersion\":1}"),
            LockSniff::Bom
        ));
        for text in [
            "",
            "[]",
            "1",
            "\"x\"",
            "{",
            "{\"a\":1,}",
            r#"{"lockfileVersion":1,"nodes":{"\ud800":[0,"a"]}}"#,
            r#"{"lockfileVersion":1,"x":"\udc00"}"#,
        ] {
            assert!(
                matches!(sniff_lock(text), LockSniff::NotJsonObject),
                "{text:?}"
            );
        }
        let paired = readable(r#"{"lockfileVersion":1,"x":"😀"}"#);
        assert_eq!(paired.json["x"], "\u{1F600}");
    }

    const CANONICAL: &str = concat!(
        "{\n",
        "  \"lockfileVersion\": 1,\n",
        "  \"options\": {\n",
        "    \"registries\": {\n",
        "      \"npm\": \"https://registry.npmjs.org/\"\n",
        "    }\n",
        "  },\n",
        "  \"nodes\": {\n",
        "    \"~npm~a@1.0.0\": [0,\"a\",\"sha512-a\"],\n",
        "    \"~npm~b@1.0.0\": [2,\"b\",\"sha512-b\",null,null,null,null,null,{  \"b\": \"cli.js\"}]\n",
        "  },\n",
        "  \"edges\": {\n",
        "    \"file~_d a\": \"prod ^1.0.0 ~npm~a@1.0.0\",\n",
        "    \"file~_d b\": \"dev >=1 <2 ~npm~b@1.0.0\"\n",
        "  }\n",
        "}\n",
    );

    #[test]
    fn locates_canonical_sections() {
        let lines = split_lines(CANONICAL);
        assert_eq!(lines.join("\n"), CANONICAL);
        let nodes = nodes_block(&lines).expect("nodes");
        assert_eq!(nodes, SectionSpan::Block { open: 7, close: 10 });
        assert_eq!(nodes.entry_lines(), 8..10);
        let edges = edges_block(&lines).expect("edges");
        assert_eq!(
            edges,
            SectionSpan::Block {
                open: 11,
                close: 14
            }
        );

        let crlf = CANONICAL.replace('\n', "\r\n");
        let crlf_lines = split_lines(&crlf);
        assert_eq!(nodes_block(&crlf_lines), Some(nodes));
        assert_eq!(edges_block(&crlf_lines), Some(edges));
        assert_eq!(crlf_lines.join("\n"), crlf);

        let empty = "{\n  \"nodes\": {},\n  \"edges\": {}\n}\n";
        let lines = split_lines(empty);
        assert_eq!(nodes_block(&lines), Some(SectionSpan::Inline { line: 1 }));
        assert_eq!(edges_block(&lines), Some(SectionSpan::Inline { line: 2 }));
        assert!(SectionSpan::Inline { line: 1 }.entry_lines().is_empty());
    }

    #[test]
    fn non_canonical_sections_are_not_found() {
        for text in [
            "{\n\t\"nodes\": {\n    \"~npm~a@1.0.0\": [0,\"a\"]\n\t}\n}\n",
            "{\n  \"nodes\" : {\n    \"~npm~a@1.0.0\": [0,\"a\"]\n  }\n}\n",
            "{\n    \"nodes\": {\n    \"~npm~a@1.0.0\": [0,\"a\"]\n    }\n}\n",
            "{\n  \"nodes\": {\n    \"~npm~a@1.0.0\": [0,\"a\"]\n",
            "{\n  \"nodes\": { \"~npm~a@1.0.0\": [0,\"a\"] },\n}\n",
            "{\"nodes\":{\"~npm~a@1.0.0\":[0,\"a\"]}}",
        ] {
            assert_eq!(nodes_block(&split_lines(text)), None, "{text:?}");
        }
    }

    fn node(line: &str) -> NodeLine<'_> {
        parse_node_line(line).unwrap_or_else(|| panic!("{line:?} is outside the grammar"))
    }

    #[test]
    fn node_line_grammar_accepts_vlt_shapes() {
        let plain = node("    \"~npm~a@1.0.0\": [0,\"a\",\"sha512-x\"],");
        assert_eq!(plain.entry.key, "~npm~a@1.0.0");
        assert_eq!(plain.entry.elems, ["0", "\"a\"", "\"sha512-x\""]);
        assert_eq!(plain.entry.name().as_deref(), Some("a"));
        assert!(plain.comma && !plain.cr);
        assert_eq!(
            plain.entry.entry_text(),
            "\"~npm~a@1.0.0\": [0,\"a\",\"sha512-x\"]"
        );
        assert_eq!(plain.entry.slot(3), None);

        let nested = node(concat!(
            "    \"~npm~@esbuild+linux-x64@0.19.12\": [1,\"@esbuild/linux-x64\",\"sha512-A==\",",
            "\"http://127.0.0.1:4873/x.tgz\",null,null,null,{  \"engines\": {    \"node\": \">=12\"  },",
            "  \"os\": [    \"linux\"  ],  \"cpu\": [    \"x64\"  ]}]\r"
        ));
        assert_eq!(nested.entry.elems.len(), 8);
        assert_eq!(nested.entry.slot(4), Some("null"));
        assert!(nested.entry.elems[7].starts_with("{  \"engines\""));
        assert!(!nested.comma && nested.cr);

        let two = node("    \"file~.socket+vendor\": [3,\"x\"]");
        assert_eq!(two.entry.elems, ["3", "\"x\""]);
        let nulls = node("    \"~npm~a@1.0.0\": [0,\"a\",null,null,\"node_modules/.vlt/x\"]");
        assert_eq!(nulls.entry.slot(2), Some("null"));
        let escaped =
            node("    \"~npm~a@1.0.0\": [0,\"a\\\"b\",\"s,]\\\\\",null,[1,[2]],{\"k\":[\",\"]}]");
        assert_eq!(
            escaped.entry.elems,
            [
                "0",
                "\"a\\\"b\"",
                "\"s,]\\\\\"",
                "null",
                "[1,[2]]",
                "{\"k\":[\",\"]}"
            ]
        );
        assert_eq!(escaped.entry.name().as_deref(), Some("a\"b"));
    }

    #[test]
    fn node_line_grammar_rejects_deviations() {
        for line in [
            "     \"~npm~a@1.0.0\": [0,\"a\"]",
            "   \"~npm~a@1.0.0\": [0,\"a\"]",
            "\t\"~npm~a@1.0.0\": [0,\"a\"]",
            "    \"~npm~a@1.0.0\" : [0,\"a\"]",
            "    \"~npm~a@1.0.0\":[0,\"a\"]",
            "    \"~npm~a@1.0.0\": [0, \"a\"]",
            "    \"~npm~a@1.0.0\": [0 ,\"a\"]",
            "    \"~npm~a@1.0.0\": [ 0,\"a\"]",
            "    \"~npm~a@1.0.0\": [0,\"a\" ]",
            "    \"~npm~a@1.0.0\": [0,\"a\"] ",
            "    \"~npm~a@1.0.0\": [0,\"a\"],,",
            "    \"~npm~a@1.0.0\": [0,\"a\"],\r\r",
            "    \"~npm~a@1.0.0\": [0,\"a\",]",
            "    \"~npm~a@1.0.0\": [0,,\"a\"]",
            "    \"~npm~a@1.0.0\": []",
            "    \"~npm~a@1.0.0\": [0]",
            "    \"~npm~a@1.0.0\": [4,\"a\"]",
            "    \"~npm~a@1.0.0\": [\"0\",\"a\"]",
            "    \"~npm~a@1.0.0\": [0.0,\"a\"]",
            "    \"~npm~a@1.0.0\": [0,null]",
            "    \"~npm~a@1.0.0\": [0,\"a\",1]",
            "    \"~npm~a@1.0.0\": [0,\"a\",null,{}]",
            "    \"~npm~a@1.0.0\": {\"0\":\"a\"}",
            "    \"~npm~a@1.0.0\": [0,\"a\"",
            "    \"~npm~a@1.0.0\": [0,\"a\"]]",
            "    \"~npm~a\\u0040.0.0\": [0,\"a\"]",
            "    \"~npm~a@1.0.0: [0,\"a\"]",
            "    ~npm~a@1.0.0: [0,\"a\"]",
            "",
            "  },",
        ] {
            assert_eq!(parse_node_line(line), None, "{line:?}");
        }
    }

    #[test]
    fn element_splitter_tracks_strings_and_nesting() {
        assert_eq!(
            split_tuple_elements("[\"a,b\",\"c\\\"]\",[1,{\"x\":[2,3]}],{}]"),
            Some(vec!["\"a,b\"", "\"c\\\"]\"", "[1,{\"x\":[2,3]}]", "{}"])
        );
        assert_eq!(split_tuple_elements("[]"), Some(vec![]));
        assert_eq!(
            split_tuple_elements("[{  \"k\": 1}]"),
            Some(vec!["{  \"k\": 1}"])
        );
        for bad in [
            "[1, 2]", "[1,2 ]", "[\n1]", "[1,,2]", "[1,]", "{}", "1", "[1", "[1]x", " [1]",
        ] {
            assert_eq!(split_tuple_elements(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn renders_tuples_with_slots() {
        let three = ["0", "\"a\"", "\"sha512-old\""];
        let four = ["0", "\"a\"", "\"sha512-new\"", "\"https://h/a.tgz\""];
        let five = [
            "2",
            "\"a\"",
            "\"sha512-new\"",
            "\"https://h/a.tgz\"",
            "null",
            "null",
            "null",
            "null",
            "{  \"a\": \"cli.js\"}",
        ];
        let s2 = Some("\"sha512-new\"");
        let s3 = Some("\"https://h/a.tgz\"");
        assert_eq!(
            render_tuple_with_slots(&["0", "\"a\""], s2, s3),
            "[0,\"a\",\"sha512-new\",\"https://h/a.tgz\"]"
        );
        assert_eq!(
            render_tuple_with_slots(&three, s2, s3),
            "[0,\"a\",\"sha512-new\",\"https://h/a.tgz\"]"
        );
        assert_eq!(
            render_tuple_with_slots(&five[..6], Some("\"sha512-x\""), Some("\"u\"")),
            "[2,\"a\",\"sha512-x\",\"u\",null,null]"
        );
        let old = Some("\"sha512-old\"");
        assert_eq!(
            render_tuple_with_slots(&four, old, None),
            "[0,\"a\",\"sha512-old\"]"
        );
        assert_eq!(
            render_tuple_with_slots(&five, old, None),
            "[2,\"a\",\"sha512-old\",null,null,null,null,null,{  \"a\": \"cli.js\"}]"
        );
        assert_eq!(render_tuple_with_slots(&four, None, None), "[0,\"a\"]");
        assert_eq!(
            render_tuple_with_slots(&four, None, Some("\"rel\"")),
            "[0,\"a\",null,\"rel\"]"
        );
        assert_eq!(
            render_tuple_with_slots(&three, Some("null"), Some("\"rel\"")),
            "[0,\"a\",null,\"rel\"]"
        );
    }

    #[test]
    fn entry_text_round_trips_through_lines() {
        let text = "\"~npm~a@1.0.0\": [0,\"a\",\"sha512-x\"]";
        let entry = parse_node_entry_text(text).expect("entry text");
        assert_eq!(entry.entry_text(), text);
        for (comma, cr) in [(false, false), (true, false), (false, true), (true, true)] {
            let line = render_entry_line(text, comma, cr);
            let parsed = node(&line);
            assert_eq!((parsed.comma, parsed.cr), (comma, cr));
            assert_eq!(parsed.entry, entry);
        }
        assert_eq!(
            render_entry_line(text, true, true),
            format!("    {text},\r")
        );
        assert_eq!(parse_node_entry_text(&format!("    {text}")), None);
        assert_eq!(parse_node_entry_text(&format!("{text},")), None);
        assert_eq!(entry_text("k", "\"v\""), "\"k\": \"v\"");
    }

    #[test]
    fn edge_line_grammar() {
        let line = "    \"~npm~loose-envify@1.4.0 js-tokens\": \"prod ^3.0.0 || ^4.0.0 ~npm~js-tokens@4.0.0\",\r";
        let edge = parse_edge_line(line).expect("edge");
        assert!(edge.comma && edge.cr);
        assert_eq!(edge.entry.from(), "~npm~loose-envify@1.4.0");
        assert_eq!(edge.entry.dep_name(), "js-tokens");
        assert_eq!(edge.entry.edge_type(), "prod");
        assert_eq!(edge.entry.spec(), "^3.0.0 || ^4.0.0");
        assert_eq!(edge.entry.target(), "~npm~js-tokens@4.0.0");
        assert_eq!(
            edge.entry.entry_text(),
            "\"~npm~loose-envify@1.4.0 js-tokens\": \"prod ^3.0.0 || ^4.0.0 ~npm~js-tokens@4.0.0\""
        );
        let missing = parse_edge_line("    \"~npm~tap@15.2.3~peer.6f88d0ccf17dbbdc ts-node\": \"peerOptional >=8.5.2 MISSING\"")
            .expect("missing edge");
        assert_eq!(missing.entry.target(), "MISSING");
        assert_eq!(missing.entry.sort_key().to, "MISSING");
        let alias = parse_edge_line(
            "    \"file·. my-alias\": \"prod npm:left-pad@^1.3.0 ·npm·left-pad@1.3.0\"",
        )
        .expect("alias edge");
        assert_eq!(alias.entry.dep_name(), "my-alias");
        assert_eq!(alias.entry.spec(), "npm:left-pad@^1.3.0");
        let escaped =
            parse_edge_line("    \"file~_d g\": \"prod github:a/b#\\\"x\\\" git~github_ca+b~x\"")
                .expect("escaped edge");
        assert_eq!(escaped.entry.spec(), "github:a/b#\"x\"");

        for bad in [
            "    \"file~_d a\": \"build ^1 ~npm~a@1.0.0\"",
            "    \"file~_d a\": \"prod ~npm~a@1.0.0\"",
            "    \"file~_d a\": \"prod\"",
            "    \"file~_d\": \"prod ^1 ~npm~a@1.0.0\"",
            "    \" a\": \"prod ^1 ~npm~a@1.0.0\"",
            "    \"file~_d a\": [0,\"a\"]",
            "    \"file~_d a\": \"prod ^1 ~npm~a@1.0.0\" ",
            "    \"file~_d a\": \"prod ^1 ~npm~a@1.0.0\"x",
            "    \"file~_d a\" : \"prod ^1 ~npm~a@1.0.0\"",
        ] {
            assert_eq!(parse_edge_line(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn importer_sources() {
        for id in [
            "file~_d",
            "file·.",
            "workspace~packages+a",
            "workspace·packages§a",
        ] {
            assert!(is_importer_dep_id(id), "{id}");
        }
        for id in [
            "file~.",
            "file·_d",
            "file~packages+a",
            "workspace~",
            "~npm~a@1.0.0",
            "file~_d~x",
        ] {
            assert!(!is_importer_dep_id(id), "{id}");
        }
    }

    #[derive(serde::Deserialize)]
    struct CollationGolden {
        alphabet: String,
        nodes: Vec<String>,
        edges: Vec<(String, String)>,
    }

    fn collation_golden() -> CollationGolden {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/vlt/collation-golden.json");
        let text = std::fs::read_to_string(&path).expect("read collation golden");
        serde_json::from_str(&text).expect("parse collation golden")
    }

    fn scrambled<T: Clone>(items: &[T]) -> Vec<T> {
        let n = items.len();
        (0..n).map(|i| items[(i * 7919 + 13) % n].clone()).collect()
    }

    #[test]
    fn collation_matches_node_icu_golden() {
        let golden = collation_golden();
        let alphabet: Vec<char> = golden.alphabet.chars().collect();
        assert_eq!(alphabet.len(), 97);
        for pair in alphabet.windows(2) {
            let (a, b) = (pair[0].to_string(), pair[1].to_string());
            assert_eq!(vlt_collate(&a, &b), Some(Ordering::Less), "{a:?} < {b:?}");
        }
        for c in &alphabet {
            assert!(collation_weight(*c).is_some(), "{c:?} in the table");
        }

        assert!(golden.nodes.len() >= 400);
        let mut ids = scrambled(&golden.nodes);
        assert_ne!(ids, golden.nodes);
        ids.sort_by(|a, b| vlt_collate(a, b).expect("in-table ids"));
        assert_eq!(ids, golden.nodes);
        for pair in golden.nodes.windows(2) {
            assert_eq!(vlt_collate(&pair[0], &pair[1]), Some(Ordering::Less));
            assert_eq!(vlt_collate(&pair[1], &pair[0]), Some(Ordering::Greater));
        }
    }

    #[test]
    fn edge_comparator_matches_vlt_format_edges_golden() {
        let golden = collation_golden();
        assert!(golden.edges.len() >= 100);
        let texts: Vec<String> = golden
            .edges
            .iter()
            .map(|(k, v)| entry_text(k, &serde_json::to_string(v).expect("json value")))
            .collect();
        let entries: Vec<EdgeEntry<'_>> = texts
            .iter()
            .map(|t| parse_edge_entry_text(t).unwrap_or_else(|| panic!("{t} is an edge")))
            .collect();
        let mut sorted = scrambled(&entries);
        sorted.sort_by(|a, b| vlt_edge_cmp(a.sort_key(), b.sort_key()).expect("in-table edges"));
        assert_eq!(sorted, entries);
        assert!(entries
            .iter()
            .any(|e| e.target() == "MISSING" && is_importer_dep_id(e.from())));
    }

    #[test]
    fn edge_comparator_keys_and_unknown() {
        let key = |from, edge_type, to| EdgeSortKey {
            from,
            edge_type,
            to,
        };
        let root = key("file~_d", "prod", "~npm~z@1.0.0");
        let member = key("workspace~packages+a", "dev", "~npm~a@1.0.0");
        let node = key("~npm~a@1.0.0", "dev", "~npm~a@1.0.0");
        assert_eq!(vlt_edge_cmp(root, node), Some(Ordering::Less));
        assert_eq!(vlt_edge_cmp(node, member), Some(Ordering::Greater));
        assert_eq!(vlt_edge_cmp(root, member), Some(Ordering::Less));
        assert_eq!(
            vlt_edge_cmp(
                key("~npm~a@1.0.0", "peer", "~npm~z@1.0.0"),
                key("~npm~a@1.0.0", "prod", "~npm~b@1.0.0")
            ),
            Some(Ordering::Less)
        );
        assert_eq!(
            vlt_edge_cmp(
                key("~npm~a@1.0.0", "prod", "MISSING"),
                key("~npm~a@1.0.0", "prod", "~~a@1.0.0")
            ),
            Some(Ordering::Less)
        );
        assert_eq!(vlt_edge_cmp(node, node), Some(Ordering::Equal));

        let unicode = key("file~packages+naïve", "prod", "~npm~a@1.0.0");
        assert_eq!(vlt_edge_cmp(root, unicode), Some(Ordering::Less));
        assert_eq!(vlt_edge_cmp(unicode, node), None);
        let unknown_target = key("~npm~a@1.0.0", "dev", "file~ünï");
        assert_eq!(
            vlt_edge_cmp(unknown_target, key("~npm~a@1.0.0", "prod", "~npm~b@1.0.0")),
            Some(Ordering::Less)
        );
        assert_eq!(vlt_edge_cmp(unknown_target, node), None);
    }

    #[test]
    fn collate_is_unknown_outside_the_table() {
        // Reachable from real locks: the tilde encoding leaves non-ASCII
        // raw, so a `file:` or `remote` path with it lands in a node key.
        let tilde_path = file_dep_id("packages/naïve", Tilde);
        assert_eq!(tilde_path, "file~packages+naïve");
        assert_eq!(vlt_collate(&tilde_path, "file~packages+a"), None);
        assert_eq!(vlt_collate("~npm~a@1.0.0", &tilde_path), None);
        // The legacy encoding percent-escapes it, so the same path is known.
        let legacy_path = file_dep_id("packages/naïve", Legacy);
        assert_eq!(
            vlt_collate(&legacy_path, "file·packages§a"),
            Some(Ordering::Greater)
        );
        assert_eq!(vlt_collate("a\tb", "a b"), None);
        assert_eq!(vlt_collate("", ""), Some(Ordering::Equal));
        assert_eq!(vlt_collate("", "a"), Some(Ordering::Less));
    }

    #[test]
    fn collate_primary_then_case() {
        let cases = [
            ("a", "A", Ordering::Less),
            ("aB", "Ab", Ordering::Less),
            ("ab", "aB", Ordering::Less),
            ("Ab", "b", Ordering::Less),
            ("A", "a-b", Ordering::Less),
            ("~npm~A@1.0.0", "~npm~a@1.0.0-rc.1", Ordering::Less),
            ("~npm~a_b@1.0.0", "~npm~a-b@1.0.0", Ordering::Less),
            ("~npm~a__b@1.0.0", "~npm~a_b@1.0.0", Ordering::Less),
            ("··ms@2.1.3", "·npm·ms@2.1.3", Ordering::Less),
            ("~npm~z@1.0.0", "file~_d", Ordering::Less),
            ("file·x", "file~x", Ordering::Less),
            (
                "~npm~is-number@7.0.0",
                "~npm~is-number@7.0.0~peer.1",
                Ordering::Less,
            ),
        ];
        for (a, b, expected) in cases {
            assert_eq!(vlt_collate(a, b), Some(expected), "{a} vs {b}");
            assert_eq!(vlt_collate(b, a), Some(expected.reverse()), "{b} vs {a}");
        }
    }

    // Captured with vlt 1.2.0 and rc.14 (design probes peerprobe/t2 and
    // e1c/base): every entry line is inside the grammar and both sections
    // are in the order the comparators compute.
    const CAPTURED_1_2_0: &str = r#"{
  "lockfileVersion": 1,
  "options": {
    "registries": {
      "npm": "https://registry.npmjs.org/"
    }
  },
  "nodes": {
    "~npm~js-tokens@4.0.0": [0,"js-tokens","sha512-RdJUflcE3cUzKiMqQgsCu06FPu9UdIJO0beYbPhHN4k6apgJtifcoCtT9bcxOpYBtpD2kCM6Sbzg4CausW/PKQ==","https://registry.npmjs.org/js-tokens/-/js-tokens-4.0.0.tgz"],
    "~npm~loose-envify@1.4.0": [0,"loose-envify","sha512-lyuxPGr/Wfhrlem2CL/UcnUc1zcqKAImBDzukY7Y5F/yQiNdko6+fRLevlw1HgMySw7f611UIY408EtxRSoK3Q==","https://registry.npmjs.org/loose-envify/-/loose-envify-1.4.0.tgz",null,null,null,null,{  "loose-envify": "cli.js"}],
    "~npm~react-dom@18.2.0~peer.ace93b147498ef7a": [0,"react-dom","sha512-6IMTriUmvsjHUjNtEDudZfuDQUoWXVxKHhlEGSk81n4YFS+r/Kl99wXiwlVXtPBtJenozv2P+hxDsw9eA7Xo6g==","https://registry.npmjs.org/react-dom/-/react-dom-18.2.0.tgz"],
    "~npm~react@18.2.0": [0,"react","sha512-/3IjMdb2L9QbBdWiW5e3P2/npwMBaU9mHCSCUzNln0ZCYbcfTsGbTJrU/kGemdH2IWmB2ioZ+zkxtmq6g09fGQ==","https://registry.npmjs.org/react/-/react-18.2.0.tgz"],
    "~npm~react@18.3.1": [0,"react","sha512-wS+hAgJShR0KhEvPJArfuPVN1+Hz1t0Y6n5jLrGQbkb4urgPE/0Rve+1kMB1v/oWgHgm4WIcV+i7F2pTVj+2iQ==","https://registry.npmjs.org/react/-/react-18.3.1.tgz"],
    "~npm~scheduler@0.23.2": [0,"scheduler","sha512-UOShsPwz7NrMUqhR6t0hWjFduvOzbtv7toDH1/hIrfRNIDBnnBWd0CwJTGvTpngVlmwGCdP9/Zl/tVrDqcuYzQ==","https://registry.npmjs.org/scheduler/-/scheduler-0.23.2.tgz"]
  },
  "edges": {
    "workspace~packages+a react-dom": "prod 18.2.0 ~npm~react-dom@18.2.0~peer.ace93b147498ef7a",
    "workspace~packages+a react": "prod 18.2.0 ~npm~react@18.2.0",
    "workspace~packages+b react-dom": "prod 18.2.0 ~npm~react-dom@18.2.0~peer.ace93b147498ef7a",
    "workspace~packages+b react": "prod 18.3.1 ~npm~react@18.3.1",
    "~npm~loose-envify@1.4.0 js-tokens": "prod ^3.0.0 || ^4.0.0 ~npm~js-tokens@4.0.0",
    "~npm~react-dom@18.2.0~peer.ace93b147498ef7a react": "peer ^18.2.0 ~npm~react@18.2.0",
    "~npm~react-dom@18.2.0~peer.ace93b147498ef7a loose-envify": "prod ^1.1.0 ~npm~loose-envify@1.4.0",
    "~npm~react-dom@18.2.0~peer.ace93b147498ef7a scheduler": "prod ^0.23.0 ~npm~scheduler@0.23.2",
    "~npm~react@18.2.0 loose-envify": "prod ^1.1.0 ~npm~loose-envify@1.4.0",
    "~npm~react@18.3.1 loose-envify": "prod ^1.1.0 ~npm~loose-envify@1.4.0",
    "~npm~scheduler@0.23.2 loose-envify": "prod ^1.1.0 ~npm~loose-envify@1.4.0"
  }
}
"#;

    const CAPTURED_RC_14: &str = r#"{
  "lockfileVersion": 0,
  "options": {
    "registries": {}
  },
  "nodes": {
    "·npm·d@1.0.2": [0,"d","sha512-MOqHvMWF9/9MX6nza0KgvFH4HpMU0EF5uUDXqX/BtxtU8NfB0QzRtJ8Oe/6SuS4kbhyzVJwjd97EA4PKrzJ8bw=="],
    "·npm·debug@4.3.4": [0,"debug","sha512-PRWFHuSU3eDtQJPvnNY7Jcket1j0t5OuOsFzPPzsekD52Zl8qUfFIPEiswXqIvHWGVHOgX+7G/vCNNhehwxfkQ=="],
    "·npm·es5-ext@0.10.64": [0,"es5-ext","sha512-p2snDhiLaXe6dahss1LddxqEm+SkuDvV8dnIQG0MWjyHpcMNfXKPE+/Cc0y+PhxJX3A4xGNeFCj5oc0BUh6deg=="],
    "·npm·es6-iterator@2.0.3": [0,"es6-iterator","sha512-zw4SRzoUkd+cl+ZoE15A9o1oQd920Bb0iOJMQkQhl3jNc03YqVjAhG7scf9C5KWRU/R13Orf588uCC6525o02g=="],
    "·npm·es6-symbol@3.1.4": [0,"es6-symbol","sha512-U9bFFjX8tFiATgtkJ1zg25+KviIXpgRvRHS8sau3GfhVzThRQrOeksPeT0BWW2MNZs1OEWJ1DPXOQMn0KKRkvg=="],
    "·npm·esniff@2.0.1": [0,"esniff","sha512-kTUIGKQ/mDPFoJ0oVfcmyJn4iBDRptjNVIzwIFR7tqWXdVI9xfA2RMwY/gbSpJG3lkdWNEjLap/NqVHZiJsdfg=="],
    "·npm·event-emitter@0.3.5": [0,"event-emitter","sha512-D9rRn9y7kLPnJ+hMq7S/nhvoKwwvVJahBi2BPmx3bvbsEdK3W9ii8cBSGjP+72/LnM4n6fo3+dkCX5FeTQruXA=="],
    "·npm·ext@1.7.0": [0,"ext","sha512-6hxeJYaL110a9b5TEJSj0gojyHQAmA2ch5Os+ySCiA1QGdS697XWY1pzsrSjqA9LDEEgdB/KypIlR59RcLuHYw=="],
    "·npm·left-pad@1.3.0": [0,"left-pad","sha512-bUnDPt4lr1/bnysTf7XK7sg0vTNA27PJ5/BNeRNBoU+h9u5ZY/USq4c/DoM4KWWXt7e08tO7bZbIEavJzyTjUg=="],
    "·npm·ms@2.1.2": [0,"ms","sha512-/fZHSQ+GyiEzhN3UXH54WwVflJQXgI75oNXQa8ikM+rDUrERt2tYR9uliVbPIHf6XrOXwTpw+hkrMsC7MPhPgg=="],
    "·npm·next-tick@1.1.0": [0,"next-tick","sha512-CXdUiJembsNjuToQvxayPZF9Vqht7hewsvy2sOWafLvi2awflj9mOC6bHIg50orX8IJvWKY9wYQ/zB2kogPslQ=="],
    "·npm·type@2.7.3": [0,"type","sha512-8j+1QmAbPvLZow5Qpi6NCaN8FB60p/6x8/vfNqOk/hC+HuvFZhL4+WfekuhQLiqFZXOgQdrs3B+XxEmCc6b3FQ=="]
  },
  "edges": {
    "file·. debug": "prod 4.3.4 ·npm·debug@4.3.4",
    "file·. es5-ext": "prod 0.10.64 ·npm·es5-ext@0.10.64",
    "file·. left-pad": "prod 1.3.0 ·npm·left-pad@1.3.0",
    "·npm·d@1.0.2 es5-ext": "prod ^0.10.64 ·npm·es5-ext@0.10.64",
    "·npm·d@1.0.2 type": "prod ^2.7.2 ·npm·type@2.7.3",
    "·npm·debug@4.3.4 ms": "prod 2.1.2 ·npm·ms@2.1.2",
    "·npm·es5-ext@0.10.64 es6-iterator": "prod ^2.0.3 ·npm·es6-iterator@2.0.3",
    "·npm·es5-ext@0.10.64 es6-symbol": "prod ^3.1.3 ·npm·es6-symbol@3.1.4",
    "·npm·es5-ext@0.10.64 esniff": "prod ^2.0.1 ·npm·esniff@2.0.1",
    "·npm·es5-ext@0.10.64 next-tick": "prod ^1.1.0 ·npm·next-tick@1.1.0",
    "·npm·es6-iterator@2.0.3 d": "prod 1 ·npm·d@1.0.2",
    "·npm·es6-iterator@2.0.3 es5-ext": "prod ^0.10.35 ·npm·es5-ext@0.10.64",
    "·npm·es6-iterator@2.0.3 es6-symbol": "prod ^3.1.1 ·npm·es6-symbol@3.1.4",
    "·npm·es6-symbol@3.1.4 d": "prod ^1.0.2 ·npm·d@1.0.2",
    "·npm·es6-symbol@3.1.4 ext": "prod ^1.7.0 ·npm·ext@1.7.0",
    "·npm·esniff@2.0.1 d": "prod ^1.0.1 ·npm·d@1.0.2",
    "·npm·esniff@2.0.1 es5-ext": "prod ^0.10.62 ·npm·es5-ext@0.10.64",
    "·npm·esniff@2.0.1 event-emitter": "prod ^0.3.5 ·npm·event-emitter@0.3.5",
    "·npm·esniff@2.0.1 type": "prod ^2.7.2 ·npm·type@2.7.3",
    "·npm·event-emitter@0.3.5 d": "prod 1 ·npm·d@1.0.2",
    "·npm·event-emitter@0.3.5 es5-ext": "prod ~0.10.14 ·npm·es5-ext@0.10.64",
    "·npm·ext@1.7.0 type": "prod ^2.7.2 ·npm·type@2.7.3"
  }
}
"#;

    #[test]
    fn captured_locks_parse_and_are_in_vlt_order() {
        for (label, text, version) in [("1.2.0", CAPTURED_1_2_0, 1), ("rc.14", CAPTURED_RC_14, 0)] {
            let lock = readable(text);
            assert_eq!(lock.version, Some(version), "{label}");
            let options = lock.options();
            let lines = split_lines(text);

            let span = nodes_block(&lines).expect("nodes block");
            let nodes: Vec<NodeLine<'_>> = lines[span.entry_lines()]
                .iter()
                .map(|l| parse_node_line(l).unwrap_or_else(|| panic!("{label}: {l}")))
                .collect();
            let json_keys: Vec<&str> = lock
                .nodes()
                .expect("nodes")
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(
                nodes.iter().map(|n| n.entry.key).collect::<Vec<_>>(),
                json_keys
            );
            assert!(nodes[..nodes.len() - 1].iter().all(|n| n.comma));
            assert!(!nodes[nodes.len() - 1].comma);
            for pair in nodes.windows(2) {
                assert_eq!(
                    vlt_collate(pair[0].entry.key, pair[1].entry.key),
                    Some(Ordering::Less),
                    "{label}"
                );
            }
            for n in &nodes {
                let id = split_dep_id(n.entry.key).expect("decodable");
                let (name, _) = id.registry_identity().expect("registry node");
                assert_eq!(n.entry.name().as_deref(), Some(name));
                assert!(
                    is_default_registry(&id.first, options),
                    "{label} {}",
                    n.entry.key
                );
                assert_eq!(id.era, DepIdEra::for_lockfile_version(lock.version));
            }

            let span = edges_block(&lines).expect("edges block");
            let edges: Vec<EdgeLine<'_>> = lines[span.entry_lines()]
                .iter()
                .map(|l| parse_edge_line(l).unwrap_or_else(|| panic!("{label}: {l}")))
                .collect();
            assert_eq!(edges.len(), lock.edges().expect("edges").len());
            for pair in edges.windows(2) {
                assert_ne!(
                    vlt_edge_cmp(pair[0].entry.sort_key(), pair[1].entry.sort_key()),
                    Some(Ordering::Greater),
                    "{label}: {} before {}",
                    pair[0].entry.key,
                    pair[1].entry.key
                );
            }
        }
    }

    #[test]
    fn vendored_path_rule() {
        let dir = |p: &str| p.replace("<u>", UUID);
        let expect = |path: &str, name: &str, version: &str, shape| {
            let got = parse_vendored_path(path, name).unwrap_or_else(|| panic!("{path}"));
            assert_eq!(
                got,
                VendoredPath {
                    uuid: UUID.to_string(),
                    name: name.to_string(),
                    version: version.to_string(),
                    shape,
                }
            );
        };
        let d = ".socket/vendor/npm/<u>/left-pad-1.3.0/node_modules/left-pad";
        expect(&dir(d), "left-pad", "1.3.0", VendoredShape::Dir);
        expect(
            &dir(".socket/vendor/npm/<u>/@sc/pkg-1.0.0-rc.1+b/node_modules/@sc/pkg"),
            "@sc/pkg",
            "1.0.0-rc.1+b",
            VendoredShape::Dir,
        );
        expect(
            &dir(".socket/vendor/npm/<u>/a-1.0.0-1.0.0/node_modules/a-1.0.0"),
            "a-1.0.0",
            "1.0.0",
            VendoredShape::Dir,
        );
        expect(
            &dir(".socket/vendor/npm/<u>/@_koii/web3.js-0.1.11/node_modules/@_koii/web3.js"),
            "@_koii/web3.js",
            "0.1.11",
            VendoredShape::Dir,
        );
        expect(
            &dir(".socket/vendor/npm/<u>/left-pad-1.3.0.tgz"),
            "left-pad",
            "1.3.0",
            VendoredShape::Tgz,
        );
        expect(
            &dir(".socket/vendor/npm/<u>/@sindresorhus/is-4.6.0.tgz"),
            "@sindresorhus/is",
            "4.6.0",
            VendoredShape::Tgz,
        );
        expect(
            &dir(".socket/vendor/npm/<u>/pkg2-1.0.0-2.tgz"),
            "pkg2",
            "1.0.0-2",
            VendoredShape::Tgz,
        );
        assert_eq!(
            parse_vendored_dir_path(&dir(d)).map(|p| p.name),
            Some("left-pad".to_string())
        );

        for (path, name) in [
            (d, "right-pad"),
            (
                ".socket/vendor/npm/<u>/@a/pkg-1.0.0/node_modules/@b/pkg",
                "@a/pkg",
            ),
            (
                ".socket/vendor/npm/<u>/pkg-1.0.0/node_modules/@a/pkg",
                "@a/pkg",
            ),
            (
                ".socket/vendor/npm/<u>/@a/pkg-1.0.0/node_modules/pkg",
                "pkg",
            ),
            (
                ".socket/vendor/npm/<u>/sc/pkg-1.0.0/node_modules/sc/pkg",
                "sc/pkg",
            ),
            (
                ".socket/vendor/npm/<u>/left-pad-1.3/node_modules/left-pad",
                "left-pad",
            ),
            (
                ".socket/vendor/npm/<u>/left-pad-v1.3.0/node_modules/left-pad",
                "left-pad",
            ),
            (
                ".socket/vendor/npm/<u>/left-pad/node_modules/left-pad",
                "left-pad",
            ),
            (
                ".socket/vendor/npm/<u>/left-pad-1.3.0/node_modules/left-pad/",
                "left-pad",
            ),
            (
                ".socket/vendor/npm/<u>/left-pad-1.3.0/node_modules/left-pad/x",
                "left-pad",
            ),
            (".socket/vendor/npm/<u>/left-pad-1.3.0/left-pad", "left-pad"),
            (".socket/vendor/npm/<u>/left-pad-1.3.0", "left-pad"),
            (".socket/vendor/npm/<u>/@sc/pkg-1.0.0.tgz", "pkg"),
            (".socket/vendor/npm/<u>/pkg-1.0.0.tgz", "@sc/pkg"),
            (".socket/vendor/npm/<u>/@x/pkg-1.0.0.tgz", "@sc/pkg"),
            (".socket/vendor/npm/<u>/left-pad-1.3.tgz", "left-pad"),
            (".socket/vendor/npm/<u>/x/left-pad-1.3.0.tgz", "left-pad"),
            (
                ".socket/vendor/cargo/<u>/left-pad-1.3.0/node_modules/left-pad",
                "left-pad",
            ),
            (
                "./.socket/vendor/npm/<u>/left-pad-1.3.0/node_modules/left-pad",
                "left-pad",
            ),
            (".socket/vendor/npm/<u>/.a-1.0.0/node_modules/.a", ".a"),
            (
                ".socket/vendor/npm/<u>/node_modules-1.0.0/node_modules/node_modules",
                "node_modules",
            ),
            (
                ".socket/vendor/npm/<u>/favicon.ico-1.0.0.tgz",
                "favicon.ico",
            ),
            (
                ".socket/vendor/npm/<u>/a-9007199254740992.0.0/node_modules/a",
                "a",
            ),
            (".socket/vendor/npm/<u>/a-1.0.9007199254740992.tgz", "a"),
            (
                "vendor/npm/<u>/left-pad-1.3.0/node_modules/left-pad",
                "left-pad",
            ),
        ] {
            assert_eq!(
                parse_vendored_path(&dir(path), name),
                None,
                "{path} as {name}"
            );
        }
        let upper = d.replace("<u>", &UUID.to_uppercase());
        assert_eq!(parse_vendored_path(&upper, "left-pad"), None);
        assert_eq!(
            parse_vendored_path(&d.replace("<u>", "not-a-uuid"), "left-pad"),
            None
        );
    }

    #[test]
    fn vendored_dir_rel_is_the_d19_layout() {
        for (name, version) in [
            ("left-pad", "1.3.0"),
            ("@sc/pkg", "1.0.0-rc.1"),
            ("a-1.0.0", "1.0.0"),
        ] {
            let rel = vendored_dir_rel(UUID, name, version);
            let parsed = parse_vendored_dir_path(&rel).expect("round trip");
            assert_eq!(
                (parsed.name.as_str(), parsed.version.as_str()),
                (name, version)
            );
            assert_eq!(parse_vendored_path(&rel, name), Some(parsed));
            let tilde = file_dep_id(&rel, Tilde);
            let legacy = file_dep_id(&rel, Legacy);
            for id in [tilde, legacy] {
                let split = split_dep_id(&id).expect("file id");
                assert_eq!((split.kind, split.first.as_str()), (File, rel.as_str()));
            }
        }
        assert_eq!(
            vendored_dir_rel(UUID, "left-pad", "1.3.0"),
            format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0/node_modules/left-pad")
        );
    }

    #[test]
    fn vlt_file_names_are_pinned() {
        assert_eq!(VLT_LOCK, "vlt-lock.json");
        assert_eq!(VLT_CONFIG, "vlt.json");
        assert_eq!(VLT_HIDDEN_LOCK_REL, "node_modules/.vlt-lock.json");
        assert_eq!(VLT_STORE_DIR, "node_modules/.vlt");
        assert_eq!(VLT_LEGACY_WORKSPACES, "vlt-workspaces.json");
        assert_eq!(
            VLT_SETUP_MARKERS,
            [
                "vlt-lock.json",
                "vlt.json",
                "node_modules/.vlt-lock.json",
                "node_modules/.vlt"
            ]
        );
    }
}
