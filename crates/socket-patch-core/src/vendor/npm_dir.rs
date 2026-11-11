//! Directory artifacts for the vlt backend.
//!
//! vlt installs a `file:` directory dependency by linking it, so the vendored
//! artifact is the patched package directory itself, laid out as
//! `.socket/vendor/npm/<uuid>/[@s/]<bare>-<version>/node_modules/<name>/`:
//! Node resolves a package's `require('<own name>')` by walking up from its
//! realpath, and only a `node_modules/<name>` ancestor makes that work for
//! root, workspace-member and alias edges alike. The `<bare>-<version>`
//! level keeps the version in the path, because a committed `file` node
//! records none. vlt writes the dependency links under the package's own
//! `node_modules/`, which socket-patch never inventories, reads or creates.
//!
//! `<uuid>/.gitignore` re-includes the payload against the user's ignores
//! (JS repos routinely ignore `dist/`, `lib/` and `*.map`, exactly what
//! packages publish) while keeping vlt's links out, and `<uuid>/.gitattributes`
//! stops EOL conversion from rewriting the payload on a Windows checkout.
//!
//! One deterministic transform runs on every tree, downloaded from the service:
//! the top-level `devDependencies` member is cut out of `package.json` (vlt
//! installs a `file` node's devDependencies), and nothing else changes. The
//! verifiers then apply the vlt manifest exemption ([`super::verify`]).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{normalize_file_path, ApplyResult};
use crate::patch::copy_tree::{fresh_copy, remove_tree};
use crate::utils::fs::atomic_write_bytes;

use super::common::{already_patched_result, refused, service_offline_conflict};
use super::npm_common::{
    declares_bundled_deps, done_failure, done_failure_unstage, guard_coordinates,
};
use super::service_fetch::{fetch_verified_archive, ServicePolicy};
use super::state::VENDOR_MARKER_FILE;
use super::vlt_lock_text::vendored_dir_rel;
use super::{VendorOutcome, VendorServiceConfig, VendorWarning};

/// `<uuid>/.gitignore`, exactly.
pub(crate) const UUID_GITIGNORE: &str =
    "!*\n**/node_modules/*/node_modules/\n**/node_modules/@*/*/node_modules/\n";
/// `<uuid>/.gitattributes`, exactly. It unsets every attribute that lets
/// git store or check out other bytes than the artifact's: EOL conversion
/// (`text`), clean/smudge filters such as a repository's `*.tgz
/// filter=lfs` rule (#1541), `ident` expansion and re-encoding. It beats
/// every `.gitattributes` above the uuid dir, but not `.git/info/attributes`
/// or a `.gitattributes` deeper in a vendored directory payload.
pub(crate) const UUID_GITATTRIBUTES: &str = "* -text -filter -ident -working-tree-encoding\n";
/// The `<uuid>/.gitattributes` releases before #1541 wrote: still ours,
/// and rewritten to [`UUID_GITATTRIBUTES`] by the next vendored run.
pub(crate) const LEGACY_UUID_GITATTRIBUTES: &str = "* -text\n";

/// `bytes` is a `<uuid>/.gitattributes` socket-patch wrote, current or legacy.
pub(crate) fn is_uuid_gitattributes(bytes: &[u8]) -> bool {
    bytes == UUID_GITATTRIBUTES.as_bytes() || bytes == LEGACY_UUID_GITATTRIBUTES.as_bytes()
}

const GITIGNORE: &str = ".gitignore";
const GITATTRIBUTES: &str = ".gitattributes";
const NODE_MODULES: &str = "node_modules";

/// The staged directory artifact the vlt wiring consumes.
pub(super) struct NpmStagedDir {
    /// `.socket/vendor/npm/<uuid>/<leaf>/node_modules/<name>`.
    pub rel_dir: String,
    /// Every regular file under `rel_dir` but its `node_modules/`.
    pub inventory: BTreeMap<String, String>,
    /// The uuid dir existed before this run wrote into it.
    pub uuid_dir_preexisted: bool,
    /// The patched manifest, when the patch rewrote `package.json`.
    pub staged_pkg_json: Option<Value>,
    /// The committed dir passed the reuse check; nothing was written.
    pub reused: bool,
    /// A rebuild discarded the old dir's `node_modules/` (it held more
    /// than vlt's links), so the package needs `vlt ci` to re-link.
    pub links_dropped: bool,
}

// ── package.json spans ───────────────────────────────────────────────────

/// One member of a JSON object: its decoded key and byte offsets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JsonMember {
    pub(crate) key: String,
    pub(crate) key_start: usize,
    pub(crate) value_start: usize,
    pub(crate) value_end: usize,
    /// The comma right after the value, when one follows.
    pub(crate) comma: Option<usize>,
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    i
}

/// The index just past the string token starting at `i`.
fn scan_string(b: &[u8], i: usize) -> Option<usize> {
    if b.get(i) != Some(&b'"') {
        return None;
    }
    let mut j = i + 1;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 2,
            b'"' => return Some(j + 1),
            _ => j += 1,
        }
    }
    None
}

/// The index just past the value starting at `i`.
fn scan_value(b: &[u8], i: usize) -> Option<usize> {
    match b.get(i)? {
        b'"' => scan_string(b, i),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut j = i;
            while j < b.len() {
                match b[j] {
                    b'"' => {
                        j = scan_string(b, j)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(j + 1);
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            None
        }
        _ => {
            let mut j = i;
            while j < b.len() && !matches!(b[j], b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
            {
                j += 1;
            }
            (j > i).then_some(j)
        }
    }
}

/// The members of the object whose `{` is at `open`.
fn object_members(text: &str, open: usize) -> Option<Vec<JsonMember>> {
    let b = text.as_bytes();
    if b.get(open) != Some(&b'{') {
        return None;
    }
    let mut members = Vec::new();
    let mut i = skip_ws(b, open + 1);
    if b.get(i) == Some(&b'}') {
        return Some(members);
    }
    loop {
        let key_start = i;
        let key_end = scan_string(b, key_start)?;
        let key: String = serde_json::from_str(&text[key_start..key_end]).ok()?;
        i = skip_ws(b, key_end);
        if b.get(i) != Some(&b':') {
            return None;
        }
        let value_start = skip_ws(b, i + 1);
        let value_end = scan_value(b, value_start)?;
        i = skip_ws(b, value_end);
        let comma = (b.get(i) == Some(&b',')).then_some(i);
        members.push(JsonMember {
            key,
            key_start,
            value_start,
            value_end,
            comma,
        });
        match b.get(i)? {
            b',' => i = skip_ws(b, i + 1),
            b'}' => return Some(members),
            _ => return None,
        }
    }
}

/// The top-level members of a JSON object document (a leading BOM is kept
/// out of the offsets' way, never stripped from the text).
pub(crate) fn root_members(text: &str) -> Option<Vec<JsonMember>> {
    let body = crate::formats::text::strip_bom(text);
    serde_json::from_str::<serde_json::Map<String, Value>>(body).ok()?;
    let open = skip_ws(text.as_bytes(), text.len() - body.len());
    object_members(text, open)
}

/// The one member named `key`; `Err` when it appears more than once.
fn unique_member<'m>(members: &'m [JsonMember], key: &str) -> Result<Option<&'m JsonMember>, ()> {
    let mut found = members.iter().filter(|m| m.key == key);
    let first = found.next();
    if found.next().is_some() {
        return Err(());
    }
    Ok(first)
}

/// Why a package.json span edit could not be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SpanError {
    NotJson,
    Duplicate(String),
    Missing,
    NotString,
}

/// `package.json` with its top-level `devDependencies` member
/// cut out as a byte span (key, colon, value and the whitespace between
/// them, plus the following comma and the run up to the next token, else
/// the preceding comma). `Ok(None)` when the member is absent.
pub(crate) fn strip_dev_dependencies(text: &str) -> Result<Option<String>, SpanError> {
    let members = root_members(text).ok_or(SpanError::NotJson)?;
    let member = match unique_member(&members, "devDependencies") {
        Ok(Some(member)) => member,
        Ok(None) => return Ok(None),
        Err(()) => return Err(SpanError::Duplicate("devDependencies".into())),
    };
    let index = members.iter().position(|m| m == member).unwrap_or_default();
    let (start, end) = match member.comma {
        Some(comma) => (
            member.key_start,
            skip_ws(text.as_bytes(), comma + 1).min(
                members
                    .get(index + 1)
                    .map_or(text.len(), |next| next.key_start),
            ),
        ),
        None => match index.checked_sub(1).and_then(|i| members[i].comma) {
            Some(prev_comma) => (prev_comma, member.value_end),
            None => (member.key_start, member.value_end),
        },
    };
    Ok(Some(format!("{}{}", &text[..start], &text[end..])))
}

/// The raw string token at `[field][name]` of a package.json and its byte
/// span.
fn dependency_span(text: &str, field: &str, name: &str) -> Result<(usize, usize), SpanError> {
    let members = root_members(text).ok_or(SpanError::NotJson)?;
    let table = unique_member(&members, field)
        .map_err(|()| SpanError::Duplicate(field.into()))?
        .ok_or(SpanError::Missing)?;
    let inner = object_members(text, table.value_start).ok_or(SpanError::Missing)?;
    let dep = unique_member(&inner, name)
        .map_err(|()| SpanError::Duplicate(format!("{field}.{name}")))?
        .ok_or(SpanError::Missing)?;
    if text.as_bytes()[dep.value_start] != b'"' {
        return Err(SpanError::NotString);
    }
    Ok((dep.value_start, dep.value_end))
}

/// The raw JSON token of `[field][name]` (quotes included).
pub(crate) fn dependency_token(text: &str, field: &str, name: &str) -> Result<String, SpanError> {
    let (start, end) = dependency_span(text, field, name)?;
    Ok(text[start..end].to_string())
}

/// `text` with the string token at `[field][name]` replaced by `raw` (a JSON
/// string token), nothing else re-serialized.
pub(crate) fn replace_dependency_token(
    text: &str,
    field: &str,
    name: &str,
    raw: &str,
) -> Result<String, SpanError> {
    let (start, end) = dependency_span(text, field, name)?;
    Ok(format!("{}{raw}{}", &text[..start], &text[end..]))
}

// ── in-place document edits ──────────────────────────────────────────────

/// One item of a JSON container: an object member (from its key) or an
/// array element.
struct JsonItem {
    /// The member's decoded key; `None` for an array element.
    key: Option<String>,
    /// Where the item starts: its key, or its value in an array.
    start: usize,
    value_start: usize,
    value_end: usize,
    /// The comma right after the value, when one follows.
    comma: Option<usize>,
}

/// An object or array and its items, by byte offset.
struct JsonContainer {
    open: usize,
    close: usize,
    items: Vec<JsonItem>,
}

impl JsonContainer {
    /// The container whose `{` or `[` is at `open`.
    fn scan(text: &str, open: usize) -> Option<Self> {
        let b = text.as_bytes();
        let items: Vec<JsonItem> = match b.get(open)? {
            b'{' => object_members(text, open)?
                .into_iter()
                .map(|m| JsonItem {
                    key: Some(m.key),
                    start: m.key_start,
                    value_start: m.value_start,
                    value_end: m.value_end,
                    comma: m.comma,
                })
                .collect(),
            b'[' => array_elements(b, open)?,
            _ => return None,
        };
        let close = skip_ws(b, items.last().map_or(open + 1, |last| last.value_end));
        matches!(b.get(close)?, b'}' | b']').then_some(Self { open, close, items })
    }

    /// Where the whitespace ahead of item `i` starts: after the previous
    /// item's comma, or after the opening bracket.
    fn lead_start(&self, i: usize) -> usize {
        match i.checked_sub(1).and_then(|prev| self.items[prev].comma) {
            Some(comma) => comma + 1,
            None => self.open + 1,
        }
    }

    /// How item `i` is placed: on a line of its own, or beside its
    /// neighbours.
    fn place_of(&self, text: &str, i: usize) -> JsonPlace {
        let lead = &text[self.lead_start(i)..self.items[i].start];
        match lead.rfind('\n') {
            Some(at) => JsonPlace::Line {
                eol: if lead.contains("\r\n") { "\r\n" } else { "\n" },
                indent: lead[at + 1..].to_string(),
            },
            None => JsonPlace::Inline {
                pad: self.pad(text).to_string(),
            },
        }
    }

    /// The whitespace between the opening bracket and the first item of a
    /// one-line container (`{ "a": 1 }` pads with a space).
    fn pad<'t>(&self, text: &'t str) -> &'t str {
        let first = self.items.first().map_or(self.close, |item| item.start);
        let pad = &text[self.open + 1..first];
        if pad.contains('\n') {
            ""
        } else {
            pad
        }
    }
}

/// The elements of the array whose `[` is at `open`.
fn array_elements(b: &[u8], open: usize) -> Option<Vec<JsonItem>> {
    let mut items = Vec::new();
    let mut i = skip_ws(b, open + 1);
    if b.get(i) == Some(&b']') {
        return Some(items);
    }
    loop {
        let value_end = scan_value(b, i)?;
        let next = skip_ws(b, value_end);
        items.push(JsonItem {
            key: None,
            start: i,
            value_start: i,
            value_end,
            comma: (b.get(next) == Some(&b',')).then_some(next),
        });
        match b.get(next)? {
            b',' => i = skip_ws(b, next + 1),
            b']' => return Some(items),
            _ => return None,
        }
    }
}

/// Where a value sits, which decides how a container written there lays
/// out its own items.
#[derive(Clone)]
enum JsonPlace {
    /// On a line indented by `indent`, in a file whose lines end `eol`: its
    /// items go one indent unit deeper, one per line.
    Line { eol: &'static str, indent: String },
    /// Inside a one-line container that pads its brackets with `pad`: its
    /// items stay on that line.
    Inline { pad: String },
}

/// The spellings a document uses where an edit has to write new ones.
struct JsonStyle {
    /// One level of indentation.
    unit: String,
    /// What separates a key from its value (`": "`, or `":"` when compact).
    colon: String,
    /// What follows the comma between two items of a one-line container.
    inline_sep: &'static str,
    eol: &'static str,
}

impl JsonStyle {
    /// The style of `body`, a document whose root `{` is at `open`.
    fn of(body: &str, open: usize) -> Self {
        let b = body.as_bytes();
        let colon = object_members(body, open)
            .and_then(|members| {
                let first = members.first()?;
                Some(body[scan_string(b, first.key_start)?..first.value_start].to_string())
            })
            .unwrap_or_else(|| ": ".to_string());
        Self {
            unit: super::common::detect_indent(body),
            inline_sep: if colon.ends_with(':') { "" } else { " " },
            colon,
            eol: if body.contains("\r\n") { "\r\n" } else { "\n" },
        }
    }

    /// `key: value` (or the bare value of an array element) as written at
    /// `place`.
    fn item(&self, key: Option<&str>, value: &Value, place: &JsonPlace) -> String {
        let value = self.value(value, place);
        match key {
            Some(key) => format!("{}{}{value}", Value::from(key), self.colon),
            None => value,
        }
    }

    /// `value` as written at `place`: a scalar or an empty container in
    /// serde_json's spelling, a container with its items laid out the way
    /// the place asks.
    fn value(&self, value: &Value, place: &JsonPlace) -> String {
        let (open, close, items): (char, char, Vec<(Option<&str>, &Value)>) = match value {
            Value::Object(map) if !map.is_empty() => (
                '{',
                '}',
                map.iter().map(|(k, v)| (Some(k.as_str()), v)).collect(),
            ),
            Value::Array(list) if !list.is_empty() => {
                ('[', ']', list.iter().map(|v| (None, v)).collect())
            }
            scalar => return scalar.to_string(),
        };
        let mut out = String::from(open);
        match place {
            JsonPlace::Line { eol, indent } => {
                let inner = JsonPlace::Line {
                    eol,
                    indent: format!("{indent}{}", self.unit),
                };
                for (i, (key, item)) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(eol);
                    out.push_str(indent);
                    out.push_str(&self.unit);
                    out.push_str(&self.item(*key, item, &inner));
                }
                out.push_str(eol);
                out.push_str(indent);
            }
            JsonPlace::Inline { pad } => {
                out.push_str(pad);
                for (i, (key, item)) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                        out.push_str(self.inline_sep);
                    }
                    out.push_str(&self.item(*key, item, place));
                }
                out.push_str(pad);
            }
        }
        out.push(close);
        out
    }
}

/// One span edit: `[start, end)` of the text becomes `with`.
struct Splice {
    start: usize,
    end: usize,
    with: String,
}

/// Take item `i` out of `container`, with the comma and the whitespace
/// that belong to it — the exact inverse of [`insert_item`], so an item
/// this module put in comes out leaving the bytes it found.
fn remove_item(container: &JsonContainer, i: usize) -> Option<Splice> {
    let item = &container.items[i];
    let (start, end) = match (item.comma, i.checked_sub(1)) {
        // Followed by another item: everything up to that item goes.
        (Some(_), _) => (item.start, container.items.get(i + 1)?.start),
        // The last of several: the comma that introduced it goes with it.
        (None, Some(prev)) => (container.items[prev].comma?, item.value_end),
        // The only item. One written flush against the opening bracket
        // ahead of whitespace was put into `{<whitespace>}`, which comes
        // back; any other leaves the container empty.
        (None, None) => {
            let flush = item.start == container.open + 1;
            let kept_tail = flush && item.value_end < container.close;
            let end = if kept_tail {
                item.value_end
            } else {
                container.close
            };
            (container.open + 1, end)
        }
    };
    Some(Splice {
        start,
        end,
        with: String::new(),
    })
}

/// Put `key: value` (an element when `key` is `None`) into `container` as
/// its item number `at`, written the way the item beside it is: on its own
/// line at that item's indentation, or on the same line. Nothing already
/// in the text is moved or respelled. `place` is how the container itself
/// sits, which lays out the first item of an empty one.
fn insert_item(
    text: &str,
    container: &JsonContainer,
    at: usize,
    key: Option<&str>,
    value: &Value,
    place: &JsonPlace,
    style: &JsonStyle,
) -> Splice {
    let count = container.items.len();
    let insert = |start: usize, with: String| Splice {
        start,
        end: start,
        with,
    };
    if count == 0 {
        let (lead, inner, tail) = match place {
            JsonPlace::Line { eol, indent } => {
                let deeper = format!("{indent}{}", style.unit);
                let inner = JsonPlace::Line {
                    eol,
                    indent: deeper.clone(),
                };
                (format!("{eol}{deeper}"), inner, format!("{eol}{indent}"))
            }
            JsonPlace::Inline { pad } => (pad.clone(), place.clone(), pad.clone()),
        };
        let item = style.item(key, value, &inner);
        // Whitespace already inside the empty container stays where it is,
        // behind the item, so [`remove_item`] gives it back.
        let with = match container.close == container.open + 1 {
            true => format!("{lead}{item}{tail}"),
            false => item,
        };
        return insert(container.open + 1, with);
    }
    // The neighbour whose placement the new item copies: the one it goes
    // in front of, or the last when it is appended.
    let neighbour = at.min(count - 1);
    let inner = container.place_of(text, neighbour);
    // What goes between the comma and the item after it.
    let gap = match &inner {
        JsonPlace::Line { eol, indent } => format!("{eol}{indent}"),
        // On one line: what follows a comma there already, copied from an
        // item that has one in front of it.
        JsonPlace::Inline { .. } => {
            let after_comma = neighbour.max(1);
            match container.items.get(after_comma) {
                Some(item) => text[container.lead_start(after_comma)..item.start].to_string(),
                None => style.inline_sep.to_string(),
            }
        }
    };
    let item = style.item(key, value, &inner);
    match container.items.get(at) {
        Some(next) => insert(next.start, format!("{item},{gap}")),
        None => insert(
            container.items[count - 1].value_end,
            format!(",{gap}{item}"),
        ),
    }
}

/// The next span edit that moves the value at `at` — which parses as
/// `before` — toward `after`: one member or element removed, inserted or
/// replaced. `None` when the text cannot be followed.
fn next_splice(
    text: &str,
    at: usize,
    before: &Value,
    after: &Value,
    place: &JsonPlace,
    style: &JsonStyle,
) -> Option<Splice> {
    match (before, after) {
        (Value::Object(was), Value::Object(now)) => {
            let container = JsonContainer::scan(text, at)?;
            // A repeated key reads as its last member, as `JSON.parse` and
            // serde_json both read it.
            let find = |key: &str| {
                container
                    .items
                    .iter()
                    .rposition(|item| item.key.as_deref() == Some(key))
            };
            if let Some(gone) = was.keys().find(|key| !now.contains_key(*key)) {
                return remove_item(&container, find(gone)?);
            }
            let mut prev: Option<&String> = None;
            for (key, value) in now {
                if !was.contains_key(key) {
                    let at = match prev {
                        Some(prev) => find(prev)? + 1,
                        None => 0,
                    };
                    return Some(insert_item(
                        text,
                        &container,
                        at,
                        Some(key),
                        value,
                        place,
                        style,
                    ));
                }
                prev = Some(key);
            }
            let (key, value) = now
                .iter()
                .find(|(key, value)| was.get(key.as_str()) != Some(*value))?;
            let i = find(key)?;
            next_splice(
                text,
                container.items[i].value_start,
                was.get(key)?,
                value,
                &container.place_of(text, i),
                style,
            )
        }
        (Value::Array(was), Value::Array(now)) => {
            let container = JsonContainer::scan(text, at)?;
            if container.items.len() != was.len() {
                return None;
            }
            let i = (0..was.len().max(now.len())).find(|&i| was.get(i) != now.get(i))?;
            let insert =
                |value: &Value| Some(insert_item(text, &container, i, None, value, place, style));
            match (was.get(i), now.get(i)) {
                (Some(_), None) => remove_item(&container, i),
                (None, Some(value)) => insert(value),
                // An element that is wanted further on stays, so the new
                // one goes in front of it; one the new list has no place
                // for goes; otherwise the element itself changed.
                (Some(old), Some(value)) if now[i + 1..].contains(old) => insert(value),
                (Some(_), Some(value)) if was[i + 1..].contains(value) => {
                    remove_item(&container, i)
                }
                (Some(_), Some(value)) if was.len() < now.len() => insert(value),
                (Some(_), Some(_)) if was.len() > now.len() => remove_item(&container, i),
                (Some(old), Some(value)) => next_splice(
                    text,
                    container.items[i].value_start,
                    old,
                    value,
                    &container.place_of(text, i),
                    style,
                ),
                (None, None) => None,
            }
        }
        _ => Some(Splice {
            start: at,
            end: scan_value(text.as_bytes(), at)?,
            with: style.value(after, place),
        }),
    }
}

/// The most span edits one [`splice_json`] call makes. A manifest edit
/// takes a handful; the bound only stops a scanner fault from looping.
const MAX_SPLICES: usize = 4096;

/// `text` — a JSON object document — edited in place until it parses as
/// `after`: each member or element `after` adds, drops or changes becomes
/// one span edit, and every other byte stays as it is (formatting,
/// escapes, number spellings, repeated keys, line endings, a BOM, the
/// trailing newline). An added item copies the indentation and line ending
/// of the item beside it, and taking it out again restores the bytes it
/// was put into, so a caller that undoes its own additions round-trips the
/// document exactly.
///
/// This is how socket-patch edits a file the user owns. Printing the
/// parsed document instead reflows it and changes values serde_json does
/// not read exactly (a long float, an integer past `u64`).
///
/// `Err` says why the document was left alone; the result is only ever
/// returned once it parses as `after`.
pub(crate) fn splice_json(text: &str, after: &Value) -> Result<String, String> {
    let bom = text.len() - crate::formats::text::strip_bom(text).len();
    let parse = |text: &str| {
        serde_json::from_str::<Value>(&text[bom..])
            .ok()
            .filter(Value::is_object)
            .ok_or("is not a JSON object")
    };
    let mut before = parse(text)?;
    if !after.is_object() {
        return Err("is not a JSON object".to_string());
    }
    let open = skip_ws(text.as_bytes(), bom);
    let style = JsonStyle::of(&text[bom..], open - bom);
    let root = JsonPlace::Line {
        eol: style.eol,
        indent: String::new(),
    };
    let mut out = text.to_string();
    for _ in 0..MAX_SPLICES {
        if before == *after {
            return Ok(out);
        }
        let splice = next_splice(&out, open, &before, after, &root, &style)
            .filter(|s| out.is_char_boundary(s.start) && out.is_char_boundary(s.end))
            .ok_or("has a layout the in-place editor cannot follow")?;
        out.replace_range(splice.start..splice.end, &splice.with);
        before = parse(&out).map_err(|_| "could not be edited in place")?;
    }
    Err("needs more edits than the in-place editor makes".to_string())
}

/// [`splice_json`] over the bytes of the manifest `file`, with the reason
/// it was left alone spelled as the failure a vendor or revert reports.
pub(crate) fn splice_manifest(file: &str, bytes: &[u8], after: &Value) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| format!("{file} is not UTF-8"))?;
    splice_json(text, after)
        .map(String::into_bytes)
        .map_err(|why| format!("{file} {why}, so it cannot be edited without rewriting it"))
}

/// The `devDependencies` strip on a staged tree's `package.json`. A
/// refusal is the ready outcome.
pub(super) async fn apply_transforms(
    stage: &Path,
    name: &str,
    version: &str,
) -> Result<(), Box<VendorOutcome>> {
    let path = stage.join("package.json");
    let Ok(text) = crate::utils::fs::read_regular_to_string(&path).await else {
        return Ok(());
    };
    match strip_dev_dependencies(&text) {
        Ok(None) => Ok(()),
        Ok(Some(stripped)) => tokio::fs::write(&path, stripped).await.map_err(|e| {
            Box::new(done_failure(
                &format!("pkg:npm/{name}@{version}"),
                format!("cannot write the staged package.json: {e}"),
            ))
        }),
        Err(SpanError::Duplicate(_)) => Err(Box::new(refused(
            "vendor_lock_entry_unsupported",
            format!("{name}@{version}'s package.json declares duplicate devDependencies"),
        ))),
        Err(_) => Err(Box::new(refused(
            "vendor_lock_entry_unsupported",
            format!("{name}@{version}'s package.json is not a JSON object"),
        ))),
    }
}

// ── tree checks ──────────────────────────────────────────────────────────

/// The structure rule: `<uuid>/<leaf>/node_modules/` holds exactly
/// the package dir (for a scoped name, exactly `@scope/` holding exactly
/// `<bare>`). `rel_abs` is the package dir.
pub(crate) async fn structure_rule_holds(rel_abs: &Path, name: &str) -> bool {
    let levels: Vec<&str> = name.split('/').collect();
    let mut dir = rel_abs.to_path_buf();
    for _ in &levels {
        dir.pop();
    }
    for level in levels {
        let entries = crate::utils::fs::list_dir_entries(&dir).await;
        if entries.len() != 1 || entries[0].file_name().to_str() != Some(level) {
            return false;
        }
        match tokio::fs::symlink_metadata(entries[0].path()).await {
            Ok(meta) if meta.is_dir() => {}
            _ => return false,
        }
        dir.push(level);
    }
    true
}

/// vlt's `node_modules/` inside the package dir holds only links, dirs and
/// `.bin/` scripts; anything else there was planted.
pub(crate) async fn node_modules_holds_only_links(rel_abs: &Path) -> bool {
    let root = rel_abs.join(NODE_MODULES);
    tokio::task::spawn_blocking(move || {
        let Ok(meta) = std::fs::symlink_metadata(&root) else {
            return true;
        };
        if !meta.is_dir() {
            return false;
        }
        let mut stack = vec![(root.clone(), false)];
        while let Some((dir, in_bin)) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                return false;
            };
            for entry in entries {
                let Ok(entry) = entry else {
                    return false;
                };
                let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                    return false;
                };
                let ty = meta.file_type();
                if ty.is_symlink() {
                    continue;
                }
                if ty.is_dir() {
                    let bin = in_bin || (dir == root && entry.file_name() == ".bin");
                    stack.push((entry.path(), bin));
                    continue;
                }
                if !(ty.is_file() && in_bin) {
                    return false;
                }
            }
        }
        true
    })
    .await
    .unwrap_or(false)
}

/// Rewrite `<uuid>/.gitignore` and `<uuid>/.gitattributes` when absent or
/// different; neither is part of the artifact. `true` when either was
/// rewritten.
pub(crate) async fn restore_uuid_metadata(uuid_dir: &Path) -> std::io::Result<bool> {
    write_uuid_metadata(uuid_dir, UUID_GITIGNORE).await
}

/// [`restore_uuid_metadata`] with the backend's own `.gitignore` text.
pub(crate) async fn write_uuid_metadata(uuid_dir: &Path, gitignore: &str) -> std::io::Result<bool> {
    let mut rewritten = false;
    for (name, want) in [(GITIGNORE, gitignore), (GITATTRIBUTES, UUID_GITATTRIBUTES)] {
        let path = uuid_dir.join(name);
        let current = crate::utils::fs::read_regular_to_bytes(&path).await.ok();
        if current.as_deref() != Some(want.as_bytes()) {
            atomic_write_bytes(&path, want.as_bytes()).await?;
            rewritten = true;
        }
    }
    Ok(rewritten)
}

// ── gitignore probe ──────────────────────────────────────────────────────

async fn git_output(
    git: &Path,
    root: &Path,
    args: &[&str],
    stdin: Option<String>,
) -> Option<(i32, String)> {
    use tokio::io::AsyncWriteExt as _;
    let mut child = tokio::process::Command::from(crate::utils::process::command_for(git))
        .arg("-C")
        .arg(root)
        .args(args)
        .stdin(if stdin.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    let pipe = child.stdin.take();
    // `check-ignore -v` answers each path as it reads it, so stdout must
    // drain while stdin is written or both pipes fill and neither side moves.
    let write_input = async move {
        if let (Some(input), Some(mut pipe)) = (stdin, pipe) {
            pipe.write_all(input.as_bytes()).await?;
        }
        Ok::<(), std::io::Error>(())
    };
    let exchange = async {
        let (written, output) = tokio::join!(write_input, child.wait_with_output());
        written.ok()?;
        output.ok()
    };
    let output = tokio::time::timeout(std::time::Duration::from_secs(30), exchange)
        .await
        .ok()??;
    Some((
        output.status.code()?,
        String::from_utf8_lossy(&output.stdout).into_owned(),
    ))
}

/// `git check-ignore -v --no-index` over `paths`
/// (project-relative). `Some(rules)` names what ignores them; `None` when
/// nothing is ignored, git is absent or the root is not a work tree, and
/// also when git could not answer (see [`gitignore_probe`] for the
/// distinction).
pub(crate) async fn gitignored(project_root: &Path, paths: &[String]) -> Option<String> {
    gitignore_probe(project_root, paths).await.ok().flatten()
}

/// [`gitignored`], telling "git could not answer" apart: `Err(why)` when
/// git is installed but failed to start, timed out, or `rev-parse` /
/// `check-ignore` exited with an error (128: a broken repository, an
/// unreadable ignore file). Git absent, or a root outside any work tree,
/// is `Ok(None)`: nothing there will commit the artifact.
pub(crate) async fn gitignore_probe(
    project_root: &Path,
    paths: &[String],
) -> Result<Option<String>, String> {
    Ok(ignoring_rule_lines(project_root, paths, true)
        .await?
        .map(|lines| summarize_rules(&lines)))
}

/// The ignoring rules `git check-ignore -v` reports for `paths`, one
/// `<source>:<linenum>:<pattern>\t<pathname>` line each (see
/// [`ignoring_rules`]), or `Ok(None)` when none matches, git is absent or
/// the root is not a work tree. `no_index` asks about the paths as if
/// nothing were tracked (the right question for files this run creates);
/// without it a tracked file is never ignored, because git keeps
/// committing changes to it whatever the ignore rules say.
pub(crate) async fn ignoring_rule_lines(
    project_root: &Path,
    paths: &[String],
    no_index: bool,
) -> Result<Option<Vec<String>>, String> {
    let Some(git) = crate::utils::process::resolve_tool("git") else {
        return Ok(None);
    };
    let (code, inside) = git_output(
        &git,
        project_root,
        &["rev-parse", "--is-inside-work-tree"],
        None,
    )
    .await
    .ok_or("`git rev-parse` did not run to completion")?;
    if inside.trim() != "true" {
        return match code {
            0 | 128 => Ok(None),
            code => Err(format!("`git rev-parse` exited {code}")),
        };
    }
    let input: String = paths.iter().map(|p| format!("{p}\0")).collect();
    let mut check = vec!["check-ignore", "-v", "-z", "--stdin"];
    if no_index {
        check.push("--no-index");
    }
    let (code, out) = git_output(&git, project_root, &check, Some(input))
        .await
        .ok_or("`git check-ignore` did not run to completion")?;
    if code != 0 && code != 1 {
        return Err(format!("`git check-ignore` exited {code}"));
    }
    let lines = ignoring_rules(&out);
    Ok((code == 0 && !lines.is_empty()).then_some(lines))
}

/// Up to three of `lines` joined for a message, with a count of the rest.
pub(crate) fn summarize_rules(lines: &[String]) -> String {
    let shown: Vec<&str> = lines.iter().take(3).map(String::as_str).collect();
    let more = lines.len().saturating_sub(shown.len());
    let mut detail = shown.join("; ");
    if more > 0 {
        detail.push_str(&format!("; and {more} more"));
    }
    detail
}

/// The non-negated matches of `git check-ignore -v -z` output
/// (`<source> NUL <linenum> NUL <pattern> NUL <pathname> NUL` per path), as
/// `<source>:<linenum>:<pattern>\t<pathname>`. A source may hold a colon
/// (a Windows drive letter), so the fields are split on NUL only.
fn ignoring_rules(out: &str) -> Vec<String> {
    let fields: Vec<&str> = out.split('\0').collect();
    fields
        .chunks_exact(4)
        .filter(|f| !f[2].is_empty() && !f[2].starts_with('!'))
        .map(|f| format!("{}:{}:{}\t{}", f[0], f[1], f[2], f[3]))
        .collect()
}

fn gitignored_refusal(rel_dir: &str, rules: &str) -> VendorOutcome {
    refused(GITIGNORED, gitignored_detail(rel_dir, rules))
}

/// The `vendor_artifact_gitignored` refusal (code, detail) for a vendored
/// artifact root (`dir_rel`, project-relative) that git ignores as a
/// directory: a `.socket/` or `.socket/vendor/` rule no `.gitignore` inside
/// the root can override (#831, #1061). `None` when git would look inside
/// it, so the root's own `!*` `.gitignore` re-includes file rules such as
/// `*.jar`.
pub(crate) async fn ignored_root_refusal(
    project_root: &Path,
    dir_rel: &str,
) -> Option<(&'static str, String)> {
    let rules = gitignored(project_root, &[format!("{dir_rel}/")]).await?;
    Some((GITIGNORED, gitignored_detail(dir_rel, &rules)))
}

pub(crate) const GITIGNORED: &str = "vendor_artifact_gitignored";

/// The vendored dir was written, but git could not say whether it would
/// commit it.
pub(crate) const GITIGNORE_UNCHECKED: &str = "vendor_artifact_gitignore_unchecked";

pub(crate) fn gitignore_unchecked_detail(rel: &str, why: &str) -> String {
    format!(
        "could not check whether git would commit the vendored artifact at {rel} ({why}); \
         make sure no ignore rule covers .socket/ before committing it"
    )
}

pub(crate) fn gitignored_detail(rel: &str, rules: &str) -> String {
    format!(
        "git would not commit the vendored artifact at {rel} ({rules}); remove the rule that \
         ignores .socket/ (or .socket/vendor/) and vendor again"
    )
}

// ── pipeline ─────────────────────────────────────────────────────────────

/// Reuse a verified committed directory, or acquire one from the patch service. Same result
/// shape as [`super::npm_common::stage_patch_pack`]: `Err` is a refusal or
/// a failure with the project untouched, `Ok((None, _))` a failed patch or
/// a dry run, `Ok((Some(dir), _))` the artifact on disk.
pub(super) async fn stage_patch_dir(
    purl: &str,
    project_root: &Path,
    record: &PatchRecord,
    dry_run: bool,
    warnings: &mut Vec<VendorWarning>,
    service: Option<&VendorServiceConfig>,
) -> Result<(Option<NpmStagedDir>, ApplyResult), Box<VendorOutcome>> {
    let coords = guard_coordinates(purl, record)?;
    let rel_dir = vendored_dir_rel(&record.uuid, &coords.name, &coords.version);
    let uuid_dir = project_root.join(&coords.uuid_dir_rel);
    let rel_abs = project_root.join(&rel_dir);
    let touches_manifest = record
        .files
        .keys()
        .any(|k| normalize_file_path(k) == "package.json");

    match super::reuse::reusable_committed_dir(project_root, record, &rel_dir).await {
        Ok(inventory) => {
            // A dir committed before a build-step refusal existed (the
            // prepare-family scripts, #1633) is refused on reuse too, or
            // the next `vlt ci` keeps rewriting it.
            if let Ok(pkg) = read_manifest(&rel_abs).await {
                if let Some(refusal) =
                    build_steps_refusal(&rel_abs, &pkg, &coords.name, &coords.version).await
                {
                    return Err(Box::new(refusal));
                }
            }
            if !dry_run {
                if let Err(e) = restore_uuid_metadata(&uuid_dir).await {
                    return Err(Box::new(done_failure(
                        purl,
                        format!("cannot restore {}/.gitignore: {e}", coords.uuid_dir_rel),
                    )));
                }
                let staged_pkg_json = if touches_manifest {
                    read_manifest(&rel_abs).await.ok()
                } else {
                    None
                };
                let result = already_patched_result(purl, &rel_abs, &record.files);
                return Ok((
                    Some(NpmStagedDir {
                        rel_dir,
                        inventory,
                        uuid_dir_preexisted: true,
                        staged_pkg_json,
                        reused: true,
                        links_dropped: false,
                    }),
                    result,
                ));
            }
            return Ok((None, already_patched_result(purl, &rel_abs, &record.files)));
        }
        Err(miss) => super::reuse::log_miss(purl, &miss),
    }

    if let Some(refusal) = service_offline_conflict(service) {
        return Err(Box::new(refusal));
    }

    let stage_tmp = tempfile::tempdir().map_err(|e| {
        Box::new(done_failure(
            purl,
            format!("cannot create staging tempdir: {e}"),
        ))
    })?;
    let stage = stage_tmp.path().join("stage");
    let cfg = service
        .filter(|cfg| cfg.service_enabled())
        .ok_or_else(|| Box::new(super::service_fetch::required()))?;
    try_service_dir(
        purl,
        record,
        cfg,
        &stage,
        &coords.name,
        &coords.version,
        warnings,
    )
    .await?;
    let result = already_patched_result(purl, &rel_abs, &record.files);
    prune_staged_node_modules(purl, &stage, &coords.name, &coords.version).await?;
    apply_transforms(&stage, &coords.name, &coords.version).await?;
    if dry_run {
        return Ok((None, result));
    }

    let uuid_dir_preexisted = tokio::fs::metadata(&uuid_dir).await.is_ok();
    let unstage = |error: String| {
        done_failure_unstage(
            purl,
            error,
            project_root,
            &coords.uuid_dir_rel,
            uuid_dir_preexisted,
        )
    };
    let links_dropped = match write_into_place(&stage, &uuid_dir, &rel_abs, &coords.name).await {
        Ok(dropped) => dropped,
        Err(e) => {
            return Err(Box::new(
                unstage(format!("cannot write {rel_dir}: {e}")).await,
            ))
        }
    };
    if let Err(e) = restore_uuid_metadata(&uuid_dir).await {
        return Err(Box::new(
            unstage(format!(
                "cannot write {}/.gitignore: {e}",
                coords.uuid_dir_rel
            ))
            .await,
        ));
    }
    let inventory = match super::verify::compute_package_dir_inventory(&rel_abs).await {
        Ok(inventory) => inventory,
        Err(e) => {
            return Err(Box::new(
                unstage(format!("cannot inventory {rel_dir}: {e}")).await,
            ))
        }
    };
    let mut probe: Vec<String> = inventory.keys().map(|k| format!("{rel_dir}/{k}")).collect();
    for name in [VENDOR_MARKER_FILE, GITIGNORE, GITATTRIBUTES] {
        probe.push(format!("{}/{name}", coords.uuid_dir_rel));
    }
    match gitignore_probe(project_root, &probe).await {
        Ok(Some(rules)) => {
            let _ = unstage(String::new()).await;
            return Err(Box::new(gitignored_refusal(&rel_dir, &rules)));
        }
        Ok(None) => {}
        Err(why) => warnings.push(VendorWarning::new(
            GITIGNORE_UNCHECKED,
            gitignore_unchecked_detail(&rel_dir, &why),
        )),
    }
    let staged_pkg_json = if touches_manifest {
        match read_manifest(&rel_abs).await {
            Ok(pkg) => Some(pkg),
            Err(e) => return Err(Box::new(unstage(e).await)),
        }
    } else {
        None
    };
    Ok((
        Some(NpmStagedDir {
            rel_dir,
            inventory,
            uuid_dir_preexisted,
            staged_pkg_json,
            reused: false,
            links_dropped,
        }),
        result,
    ))
}

/// On any staged tree: prune its `node_modules/` and
/// refuse a package that bundles dependencies.
async fn prune_staged_node_modules(
    purl: &str,
    stage: &Path,
    name: &str,
    version: &str,
) -> Result<(), Box<VendorOutcome>> {
    if let Err(e) = remove_tree(&stage.join(NODE_MODULES)).await {
        return Err(Box::new(done_failure(
            purl,
            format!("cannot prune staged node_modules: {e}"),
        )));
    }
    if let Ok(pkg) = read_manifest(stage).await {
        if declares_bundled_deps(&pkg) {
            return Err(Box::new(refused(
                "vendor_bundled_deps_unsupported",
                format!(
                    "{name}@{version} declares bundleDependencies; vendoring would drop its \
                     bundled node_modules and break installs"
                ),
            )));
        }
        if let Some(refusal) = build_steps_refusal(stage, &pkg, name, version).await {
            return Err(Box::new(refusal));
        }
    }
    Ok(())
}

/// `vendor_vlt_build_scripts_unsupported` when `vlt build` would run
/// something inside `dir`, the package directory whose manifest is `pkg`.
async fn build_steps_refusal(
    dir: &Path,
    pkg: &Value,
    name: &str,
    version: &str,
) -> Option<VendorOutcome> {
    let gyp = tokio::fs::symlink_metadata(dir.join(BINDING_GYP))
        .await
        .is_ok();
    let steps = vlt_build_steps(pkg, gyp);
    (!steps.is_empty()).then(|| {
        refused(
            BUILD_STEPS_UNSUPPORTED,
            build_steps_detail(name, version, &steps),
        )
    })
}

pub(crate) const BUILD_STEPS_UNSUPPORTED: &str = "vendor_vlt_build_scripts_unsupported";
pub(crate) const BINDING_GYP: &str = "binding.gyp";

/// What `vlt build` runs in a package's own directory: its `preinstall`,
/// `install` and `postinstall` scripts, its `preprepare`, `prepare` and
/// `postprepare` scripts (each on its own, as vlt's `nodeNeedsBuild` checks
/// them for a `file:` node), and node-gyp for a `binding.gyp`. vlt builds a
/// registry copy in the untracked store, but a vendored `file:` dependency
/// in place, inside the committed artifact.
pub(crate) fn vlt_build_steps(pkg: &Value, has_binding_gyp: bool) -> Vec<String> {
    let scripts = pkg.get("scripts").and_then(Value::as_object);
    let mut steps: Vec<String> = [
        "preinstall",
        "install",
        "postinstall",
        "preprepare",
        "prepare",
        "postprepare",
    ]
    .iter()
    .filter(|k| {
        scripts
            .and_then(|s| s.get(**k))
            .and_then(Value::as_str)
            .is_some_and(|v| !v.trim().is_empty())
    })
    .map(|k| format!("a `{k}` script"))
    .collect();
    if has_binding_gyp {
        steps.push(format!("node-gyp for its {BINDING_GYP}"));
    }
    steps
}

pub(crate) fn build_steps_detail(name: &str, version: &str, steps: &[String]) -> String {
    let list = match steps {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    };
    format!(
        "{name}@{version} has {list}, which `vlt build` runs inside a vendored package's \
         committed directory, rewriting the artifact; use --mode hosted"
    )
}

async fn read_manifest(dir: &Path) -> Result<Value, String> {
    let text = crate::utils::fs::read_regular_to_string(&dir.join("package.json"))
        .await
        .map_err(|e| format!("package.json unreadable: {e}"))?;
    serde_json::from_str(crate::formats::text::strip_bom(&text))
        .map_err(|e| format!("package.json is not parseable JSON: {e}"))
}

/// Build the whole `<leaf>` level in `<uuid>/.tmp-*` and rename it over
/// the old one, so nothing but the package dir survives beside it. The old
/// dir's `node_modules/` moves along when it holds only vlt's links;
/// `Ok(true)` when it held anything else and was discarded.
async fn write_into_place(
    stage: &Path,
    uuid_dir: &Path,
    rel_abs: &Path,
    name: &str,
) -> std::io::Result<bool> {
    let mut leaf_abs = rel_abs.to_path_buf();
    for _ in name.split('/') {
        leaf_abs.pop();
    }
    leaf_abs.pop();
    let parent: PathBuf = leaf_abs
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| std::io::Error::other("artifact path has no parent"))?;
    tokio::fs::create_dir_all(uuid_dir).await?;
    tokio::fs::create_dir_all(&parent).await?;
    let tmp = tempfile::Builder::new()
        .prefix(".tmp-")
        .tempdir_in(uuid_dir)?
        .keep();
    let tmp_pkg = tmp.join(NODE_MODULES).join(name);
    if let Err(e) = fresh_copy(stage, &tmp_pkg, None).await {
        let _ = remove_tree(&tmp).await;
        return Err(e);
    }
    let old_links = rel_abs.join(NODE_MODULES);
    let mut dropped = false;
    if tokio::fs::symlink_metadata(&old_links).await.is_ok() {
        if node_modules_holds_only_links(rel_abs).await {
            if let Err(e) = tokio::fs::rename(&old_links, tmp_pkg.join(NODE_MODULES)).await {
                let _ = remove_tree(&tmp).await;
                return Err(e);
            }
        } else {
            dropped = true;
        }
    }
    if tokio::fs::symlink_metadata(&leaf_abs).await.is_ok() {
        remove_tree(&leaf_abs).await?;
    }
    if let Err(e) = tokio::fs::rename(&tmp, &leaf_abs).await {
        let _ = remove_tree(&tmp).await;
        return Err(e);
    }
    Ok(dropped)
}

/// Every record file of the extracted tree hashes to its afterHash (the
/// archive check, run on the tree the first-component strip produced).
async fn tree_matches_after_hashes(stage: &Path, record: &PatchRecord) -> bool {
    for (file_name, info) in &record.files {
        let rel = normalize_file_path(file_name);
        if !crate::patch::path_safety::is_safe_multi_segment(rel) {
            return false;
        }
        let Ok(bytes) = crate::utils::fs::read_regular_to_bytes(&stage.join(rel)).await else {
            return false;
        };
        if !crate::hash::git_sha256::compute_git_sha256_from_bytes(&bytes)
            .eq_ignore_ascii_case(&info.after_hash)
        {
            return false;
        }
    }
    true
}

/// The service fast path: the prebuilt tarball, integrity- and
/// afterHash-verified, extracted into `stage` with its first path component
/// stripped whatever it is called. The fallback policy is the tarball
/// backends' (`try_service_pack`).
pub(super) async fn try_service_dir(
    purl: &str,
    record: &PatchRecord,
    cfg: &VendorServiceConfig,
    stage: &Path,
    name: &str,
    version: &str,
    warnings: &mut Vec<VendorWarning>,
) -> Result<(), Box<VendorOutcome>> {
    let policy = ServicePolicy::Failure(purl);
    let fetched = fetch_verified_archive(cfg, &record.uuid).await;
    let archive = policy.settle(fetched, "artifact", "artifact")?;
    let downloaded = archive.downloaded_warning(format_args!("{name}@{version}"));
    let (bytes, dest) = (archive.bytes, stage.to_path_buf());
    let extracted = tokio::task::spawn_blocking(move || {
        super::registry_fetch::extract_tgz_strict(&bytes, &dest)
    })
    .await
    .map_err(|e| e.to_string())
    .and_then(|r| r);
    if let Err(e) = extracted {
        return Err(policy.hard(
            "vendor_prebuilt_extract_failed",
            format!("prebuilt tarball for {name}@{version} is unsafe: {e}"),
        ));
    }
    if !tree_matches_after_hashes(stage, record).await {
        let _ = remove_tree(stage).await;
        return Err(policy.miss(format!(
            "prebuilt tarball for {name}@{version} does not carry the patched files \
                 at their recorded paths"
        )));
    }
    warnings.push(downloaded);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dev_dependencies_are_cut_out_as_one_span() {
        let cases = [
            (
                "{\n  \"name\": \"x\",\n  \"devDependencies\": {\n    \"a\": \"1\"\n  },\n  \"main\": \"i.js\"\n}\n",
                Some("{\n  \"name\": \"x\",\n  \"main\": \"i.js\"\n}\n"),
            ),
            (
                "{\n  \"name\": \"x\",\n  \"devDependencies\": {}\n}\n",
                Some("{\n  \"name\": \"x\"\n}\n"),
            ),
            ("{\"devDependencies\": {\"a\": \"1\"}}", Some("{}")),
            (
                "\u{feff}{\"devDependencies\":{},\"main\":\"i\"}",
                Some("\u{feff}{\"main\":\"i\"}"),
            ),
            (
                "{\"name\":\"x\",\"scripts\":{\"devDependencies\":\"y\"}}",
                None,
            ),
            ("{\"name\":\"x\"}", None),
        ];
        for (input, want) in cases {
            assert_eq!(
                strip_dev_dependencies(input).unwrap().as_deref(),
                want,
                "{input}"
            );
        }
        assert_eq!(
            strip_dev_dependencies("{\"devDependencies\":{},\"devDependencies\":{}}"),
            Err(SpanError::Duplicate("devDependencies".into()))
        );
        assert_eq!(strip_dev_dependencies("[1]"), Err(SpanError::NotJson));
        // A second BOM is content (#905): not a JSON object document.
        assert_eq!(
            strip_dev_dependencies("\u{feff}\u{feff}{\"devDependencies\":{}}"),
            Err(SpanError::NotJson)
        );
    }

    #[test]
    fn dependency_tokens_are_replaced_in_place() {
        let text = "{\n  \"dependencies\": {\n    \"a\": \"1\",\n    \"@s/b\" :  \"^2\"\n  },\n  \"x\": [\"dependencies\"]\n}\n";
        assert_eq!(
            dependency_token(text, "dependencies", "@s/b").unwrap(),
            "\"^2\""
        );
        assert_eq!(
            replace_dependency_token(text, "dependencies", "@s/b", "\"file:./v\"").unwrap(),
            text.replace("\"^2\"", "\"file:./v\"")
        );
        assert_eq!(
            dependency_token(text, "devDependencies", "a"),
            Err(SpanError::Missing)
        );
        assert_eq!(
            dependency_token("{\"dependencies\":{\"a\":1}}", "dependencies", "a"),
            Err(SpanError::NotString)
        );
        assert_eq!(
            dependency_token(
                "{\"dependencies\":{\"a\":\"1\",\"a\":\"2\"}}",
                "dependencies",
                "a"
            ),
            Err(SpanError::Duplicate("dependencies.a".into()))
        );
    }

    /// `text` parsed, changed by `edit`, and spliced back.
    fn spliced(text: &str, edit: impl FnOnce(&mut Value)) -> Result<String, String> {
        let mut doc: Value = serde_json::from_str(crate::formats::text::strip_bom(text))
            .map_err(|e| e.to_string())?;
        edit(&mut doc);
        splice_json(text, &doc)
    }

    fn set(doc: &mut Value, path: &[&str], value: Value) {
        let (last, parents) = path.split_last().unwrap();
        let mut at = doc;
        for key in parents {
            at = at
                .as_object_mut()
                .unwrap()
                .entry(*key)
                .or_insert_with(|| json!({}));
        }
        at.as_object_mut().unwrap().insert(last.to_string(), value);
    }

    fn unset(doc: &mut Value, path: &[&str]) {
        let (last, parents) = path.split_last().unwrap();
        let mut at = doc;
        for key in parents {
            at = at.get_mut(*key).unwrap();
        }
        at.as_object_mut().unwrap().shift_remove(*last).unwrap();
    }

    #[test]
    fn an_added_member_copies_the_layout_of_the_one_beside_it() {
        let add = |doc: &mut Value| set(doc, &["pnpm", "overrides", "a@1"], json!("file:x"));
        for (text, want) in [
            // Two spaces, four spaces, tabs, CRLF, no trailing newline.
            (
                "{\n  \"name\": \"x\"\n}\n",
                "{\n  \"name\": \"x\",\n  \"pnpm\": {\n    \"overrides\": {\n      \"a@1\": \"file:x\"\n    }\n  }\n}\n",
            ),
            (
                "{\n    \"name\": \"x\"\n}\n",
                "{\n    \"name\": \"x\",\n    \"pnpm\": {\n        \"overrides\": {\n            \"a@1\": \"file:x\"\n        }\n    }\n}\n",
            ),
            (
                "{\n\t\"name\": \"x\"\n}",
                "{\n\t\"name\": \"x\",\n\t\"pnpm\": {\n\t\t\"overrides\": {\n\t\t\t\"a@1\": \"file:x\"\n\t\t}\n\t}\n}",
            ),
            (
                "\u{feff}{\r\n  \"name\": \"x\"\r\n}\r\n",
                "\u{feff}{\r\n  \"name\": \"x\",\r\n  \"pnpm\": {\r\n    \"overrides\": {\r\n      \"a@1\": \"file:x\"\r\n    }\r\n  }\r\n}\r\n",
            ),
            // One line: compact, and spaced.
            (
                "{\"name\":\"x\"}\n",
                "{\"name\":\"x\",\"pnpm\":{\"overrides\":{\"a@1\":\"file:x\"}}}\n",
            ),
            (
                "{ \"name\": \"x\", \"v\": 1 }",
                "{ \"name\": \"x\", \"v\": 1, \"pnpm\": { \"overrides\": { \"a@1\": \"file:x\" } } }",
            ),
            // A table that is already there takes the member in its own
            // layout, whatever the rest of the file looks like.
            (
                "{\n  \"pnpm\": { \"overrides\": { \"z\": \"1\" } },\n  \"name\": \"x\"\n}\n",
                "{\n  \"pnpm\": { \"overrides\": { \"z\": \"1\", \"a@1\": \"file:x\" } },\n  \"name\": \"x\"\n}\n",
            ),
            (
                "{\n  \"pnpm\": {\n      \"overrides\": {\n          \"z\": \"1\"\n      }\n  }\n}\n",
                "{\n  \"pnpm\": {\n      \"overrides\": {\n          \"z\": \"1\",\n          \"a@1\": \"file:x\"\n      }\n  }\n}\n",
            ),
            // Empty tables, with and without whitespace inside.
            (
                "{\n  \"pnpm\": {},\n  \"name\": \"x\"\n}\n",
                "{\n  \"pnpm\": {\n    \"overrides\": {\n      \"a@1\": \"file:x\"\n    }\n  },\n  \"name\": \"x\"\n}\n",
            ),
            (
                "{\n  \"pnpm\": { \"overrides\": { } }\n}\n",
                "{\n  \"pnpm\": { \"overrides\": {\"a@1\": \"file:x\" } }\n}\n",
            ),
            ("{}", "{\n  \"pnpm\": {\n    \"overrides\": {\n      \"a@1\": \"file:x\"\n    }\n  }\n}"),
        ] {
            let added = spliced(text, add).unwrap();
            assert_eq!(added, want, "{text:?}");
            // Taking the member out again gives the bytes back: with the
            // tables it was put into left in place...
            let had_pnpm = text.contains("\"pnpm\"");
            let had_overrides = text.contains("\"overrides\"");
            let removed = spliced(&added, |doc| {
                unset(doc, &["pnpm", "overrides", "a@1"]);
                if !had_overrides {
                    unset(doc, &["pnpm", "overrides"]);
                }
                if !had_pnpm {
                    unset(doc, &["pnpm"]);
                }
            })
            .unwrap();
            assert_eq!(removed, text, "{text:?}");
        }
    }

    #[test]
    fn only_the_changed_member_is_respelled() {
        // Everything a parse-and-print round trip would rewrite.
        let text = concat!(
            "{\n",
            "  \"author\": \"Jos\\u00e9\", \"url\": \"https:\\/\\/x\",\n",
            "  \"files\": [\"dist\", \"src\"],\n",
            "  \"n\": [1e3, 4.670e-22, 5.173e28, 18446744073709551616, -0],\n",
            "  \"license\": \"MIT\",\n",
            "  \"license\": \"ISC\",\n",
            "  \"scripts\": { },\n",
            "  \"resolutions\": { \"a\": \"1.0.0\" , \"b\" : \"2.0.0\" }\n",
            "}",
        );
        // A value replaced in place keeps its key and surroundings.
        assert_eq!(
            spliced(text, |doc| set(
                doc,
                &["resolutions", "a"],
                json!("file:./v")
            ))
            .unwrap(),
            text.replace("\"1.0.0\"", "\"file:./v\"")
        );
        // A member dropped from the middle, the end and the front.
        assert_eq!(
            spliced(text, |doc| unset(doc, &["resolutions", "a"])).unwrap(),
            text.replace("\"a\": \"1.0.0\" , ", "")
        );
        assert_eq!(
            spliced(text, |doc| unset(doc, &["resolutions", "b"])).unwrap(),
            text.replace(", \"b\" : \"2.0.0\"", "")
        );
        assert_eq!(
            spliced(text, |doc| unset(doc, &["resolutions"])).unwrap(),
            text.replace(
                ",\n  \"resolutions\": { \"a\": \"1.0.0\" , \"b\" : \"2.0.0\" }",
                ""
            )
        );
        assert_eq!(
            spliced(text, |doc| unset(doc, &["author"])).unwrap(),
            text.replace("\"author\": \"Jos\\u00e9\", ", "")
        );
        // A repeated key reads as its last member; that one is edited.
        assert_eq!(
            spliced(text, |doc| set(doc, &["license"], json!("0BSD"))).unwrap(),
            text.replace("\"ISC\"", "\"0BSD\"")
        );
        // No change, no edit.
        assert_eq!(spliced(text, |_| {}).unwrap(), text);
    }

    #[test]
    fn array_elements_are_added_and_dropped_in_place() {
        let text = "{\n  \"pnpm\": {\n    \"onlyBuiltDependencies\": [\n      \"esbuild\",\n      \"sharp\"\n    ],\n    \"inline\": [\"a\", \"b\"]\n  }\n}\n";
        let list = |doc: &mut Value, field: &str, items: Value| {
            set(doc, &["pnpm", field], items);
        };
        // After an element in the middle, at the end, and at the front.
        let middle = spliced(text, |doc| {
            list(
                doc,
                "onlyBuiltDependencies",
                json!(["esbuild", "new", "sharp"]),
            )
        })
        .unwrap();
        assert_eq!(
            middle,
            text.replace("\"esbuild\",\n", "\"esbuild\",\n      \"new\",\n")
        );
        assert_eq!(
            spliced(&middle, |doc| {
                list(doc, "onlyBuiltDependencies", json!(["esbuild", "sharp"]))
            })
            .unwrap(),
            text
        );
        let end = spliced(text, |doc| list(doc, "inline", json!(["a", "b", "c"]))).unwrap();
        assert_eq!(end, text.replace("[\"a\", \"b\"]", "[\"a\", \"b\", \"c\"]"));
        assert_eq!(
            spliced(&end, |doc| list(doc, "inline", json!(["a", "b"]))).unwrap(),
            text
        );
        assert_eq!(
            spliced(text, |doc| list(doc, "inline", json!(["z", "a", "b"]))).unwrap(),
            text.replace("[\"a\", \"b\"]", "[\"z\", \"a\", \"b\"]")
        );
        // One element swapped for another, and the list emptied.
        assert_eq!(
            spliced(text, |doc| list(doc, "inline", json!(["a", "c"]))).unwrap(),
            text.replace("[\"a\", \"b\"]", "[\"a\", \"c\"]")
        );
        assert_eq!(
            spliced(text, |doc| list(doc, "inline", json!([]))).unwrap(),
            text.replace("[\"a\", \"b\"]", "[]")
        );
    }

    #[test]
    fn a_document_the_editor_cannot_follow_is_left_alone() {
        assert_eq!(
            splice_json("[1]", &json!({})),
            Err("is not a JSON object".to_string())
        );
        assert_eq!(
            splice_json("{\"a\": 1", &json!({})),
            Err("is not a JSON object".to_string())
        );
        assert_eq!(
            splice_json("{}", &json!([])),
            Err("is not a JSON object".to_string())
        );
        assert_eq!(
            splice_manifest("package.json", b"\xff{}", &json!({})),
            Err("package.json is not UTF-8".to_string())
        );
    }

    #[tokio::test]
    async fn the_structure_rule_admits_exactly_the_package_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let leaf = tmp.path().join("@s/b-1.0.0/node_modules");
        let pkg = leaf.join("@s/b");
        tokio::fs::create_dir_all(&pkg).await.unwrap();
        assert!(structure_rule_holds(&pkg, "@s/b").await);
        tokio::fs::create_dir_all(leaf.join("@s/c")).await.unwrap();
        assert!(!structure_rule_holds(&pkg, "@s/b").await);

        let pkg = tmp.path().join("a-1.0.0/node_modules/a");
        tokio::fs::create_dir_all(&pkg).await.unwrap();
        assert!(structure_rule_holds(&pkg, "a").await);
        tokio::fs::write(tmp.path().join("a-1.0.0/node_modules/.x"), b"")
            .await
            .unwrap();
        assert!(!structure_rule_holds(&pkg, "a").await);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn only_links_dirs_and_bin_scripts_live_under_the_package_node_modules() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg = tmp.path();
        assert!(node_modules_holds_only_links(pkg).await, "absent is fine");
        let nm = pkg.join("node_modules");
        tokio::fs::create_dir_all(nm.join(".bin")).await.unwrap();
        tokio::fs::create_dir_all(nm.join("@s")).await.unwrap();
        std::os::unix::fs::symlink("/elsewhere", nm.join("dep")).unwrap();
        std::os::unix::fs::symlink("/elsewhere", nm.join("@s/dep")).unwrap();
        tokio::fs::write(nm.join(".bin/tool"), b"#!/bin/sh\n")
            .await
            .unwrap();
        assert!(node_modules_holds_only_links(pkg).await);
        tokio::fs::write(nm.join("@s/planted.js"), b"x")
            .await
            .unwrap();
        assert!(!node_modules_holds_only_links(pkg).await);
    }

    #[tokio::test]
    async fn uuid_metadata_is_written_with_its_exact_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join(GITIGNORE), b"*\n")
            .await
            .unwrap();
        restore_uuid_metadata(tmp.path()).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(GITIGNORE)).unwrap(),
            "!*\n**/node_modules/*/node_modules/\n**/node_modules/@*/*/node_modules/\n"
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(GITATTRIBUTES)).unwrap(),
            "* -text -filter -ident -working-tree-encoding\n"
        );
    }

    /// #1541: a vendored tree written by an older release holds the
    /// legacy `* -text` file; the next run rewrites it in place.
    #[tokio::test]
    async fn legacy_uuid_gitattributes_is_upgraded() {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join(GITATTRIBUTES), LEGACY_UUID_GITATTRIBUTES)
            .await
            .unwrap();
        restore_uuid_metadata(tmp.path()).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(GITATTRIBUTES)).unwrap(),
            UUID_GITATTRIBUTES
        );
        assert!(is_uuid_gitattributes(LEGACY_UUID_GITATTRIBUTES.as_bytes()));
        assert!(is_uuid_gitattributes(UUID_GITATTRIBUTES.as_bytes()));
        assert!(!is_uuid_gitattributes(b"* -text filter=lfs\n"));
    }

    /// #1541: a repository rule that hands `*.tgz` (or every file) to Git
    /// LFS, or re-encodes or expands it on checkout, does not reach the
    /// vendored artifacts once the uuid `.gitattributes` is in place, so
    /// the commit stores their exact bytes.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_uuid_gitattributes_overrides_repository_lfs_rules() {
        let Some(git) = crate::utils::process::resolve_tool("git") else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let status = std::process::Command::new(&git)
            .args(["init", "-q"])
            .current_dir(root)
            .status()
            .unwrap();
        assert!(status.success());
        std::fs::write(
            root.join(".gitattributes"),
            "*.tgz filter=lfs diff=lfs merge=lfs -text\n\
             *.js filter=lfs working-tree-encoding=UTF-16 ident text eol=crlf\n",
        )
        .unwrap();
        let uuid = root.join(".socket/vendor/npm/u");
        std::fs::create_dir_all(&uuid).unwrap();
        let paths = [
            ".socket/vendor/npm/u/left-pad-1.3.0.tgz",
            ".socket/vendor/npm/u/a-1.0.0/node_modules/a/index.js",
        ];
        let attr = |path: &str| {
            let out = std::process::Command::new(&git)
                .args([
                    "check-attr",
                    "filter",
                    "text",
                    "ident",
                    "working-tree-encoding",
                    "--",
                ])
                .arg(path)
                .current_dir(root)
                .output()
                .unwrap();
            assert!(out.status.success());
            String::from_utf8(out.stdout).unwrap()
        };
        assert!(
            attr(paths[0]).contains("filter: lfs"),
            "the repo rule applies"
        );
        restore_uuid_metadata(&uuid).await.unwrap();
        for path in paths {
            let out = attr(path);
            for name in ["filter", "text", "ident", "working-tree-encoding"] {
                assert!(out.contains(&format!("{path}: {name}: unset")), "{out}");
            }
        }
    }

    fn tgz(entries: &[(&str, tar::EntryType, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (path, kind, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(*kind);
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            if !kind.is_file() && !kind.is_dir() {
                header.set_link_name("target").unwrap();
            }
            header.set_cksum();
            builder.append_data(&mut header, path, *bytes).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn the_service_extract_strips_any_first_component_and_refuses_links() {
        use tar::EntryType;
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("stage");
        let ok = tgz(&[
            ("left-pad/", EntryType::Directory, b""),
            ("left-pad/index.js", EntryType::Regular, b"x"),
        ]);
        super::super::registry_fetch::extract_tgz_strict(&ok, &dest).unwrap();
        assert_eq!(std::fs::read(dest.join("index.js")).unwrap(), b"x");
        for kind in [
            EntryType::Symlink,
            EntryType::Link,
            EntryType::Char,
            EntryType::Fifo,
        ] {
            let bad = tgz(&[
                ("package/index.js", EntryType::Regular, b"x"),
                ("package/evil", kind, b""),
            ]);
            let err =
                super::super::registry_fetch::extract_tgz_strict(&bad, &tmp.path().join("s2"))
                    .unwrap_err();
            assert!(err.contains("not a regular file"), "{kind:?}: {err}");
        }
    }

    #[test]
    fn vlt_build_steps_name_every_script_vlt_build_runs_in_place() {
        let pkg = serde_json::json!({
            "scripts": {
                "postinstall": "node install.js",
                "prepare": "husky",
                "install": " ",
                "test": "tap",
                "build": "tsc"
            }
        });
        assert_eq!(
            vlt_build_steps(&pkg, true),
            [
                "a `postinstall` script",
                "a `prepare` script",
                "node-gyp for its binding.gyp"
            ]
        );
        assert!(vlt_build_steps(&serde_json::json!({"scripts": {"test": "x"}}), false).is_empty());
        // vlt runs each prepare-family script for a `file:` directory even
        // when it's the package's only one (#1633).
        for script in ["preprepare", "postprepare"] {
            let pkg = serde_json::json!({"scripts": {script: "node build.js"}});
            assert_eq!(
                vlt_build_steps(&pkg, false),
                [format!("a `{script}` script")],
                "{script}"
            );
        }
        assert!(vlt_build_steps(&serde_json::json!({}), false).is_empty());
        assert_eq!(
            build_steps_detail("x", "1.0.0", &vlt_build_steps(&pkg, true)),
            "x@1.0.0 has a `postinstall` script, a `prepare` script and node-gyp for its \
             binding.gyp, which `vlt build` runs inside a vendored package's committed \
             directory, rewriting the artifact; use --mode hosted"
        );
        assert_eq!(
            build_steps_detail("esbuild", "0.20.2", &vlt_build_steps(&pkg, false)),
            "esbuild@0.20.2 has a `postinstall` script and a `prepare` script, which `vlt build` \
             runs inside a vendored package's committed directory, rewriting the artifact; use \
             --mode hosted"
        );
    }

    #[test]
    fn check_ignore_records_split_on_nul_so_a_drive_letter_source_parses() {
        let out = "C:/Users/u/.gitignore_global\x003\x00!dist/\x00.socket/p/dist/i.js\x00\
                   C:/Users/u/.gitignore_global\x004\x00*.map\x00.socket/p/i.js.map\x00\
                   .gitignore\x001\x00.socket/\x00.socket/p/a.js\x00";
        assert_eq!(
            ignoring_rules(out),
            [
                "C:/Users/u/.gitignore_global:4:*.map\t.socket/p/i.js.map",
                ".gitignore:1:.socket/\t.socket/p/a.js",
            ]
        );
        assert!(ignoring_rules("").is_empty());
        assert!(ignoring_rules("C:/g\x002\x00!x\x00x\x00").is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_gitignore_probe_ignores_tracked_state_and_names_the_rule() {
        let Some(git) = crate::utils::process::resolve_tool("git") else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let status = std::process::Command::new(&git)
            .args(["init", "-q"])
            .current_dir(root)
            .status()
            .unwrap();
        assert!(status.success());
        let paths = vec![".socket/vendor/npm/u/a-1.0.0/node_modules/a/dist/i.js".to_string()];
        assert_eq!(gitignored(root, &paths).await, None);
        std::fs::write(root.join(".gitignore"), "dist/\n").unwrap();
        let uuid = root.join(".socket/vendor/npm/u");
        std::fs::create_dir_all(&uuid).unwrap();
        assert!(
            gitignored(root, &paths).await.is_some(),
            "a root dist/ rule"
        );
        restore_uuid_metadata(&uuid).await.unwrap();
        assert_eq!(
            gitignored(root, &paths).await,
            None,
            "the uuid .gitignore re-includes it"
        );
        std::fs::write(root.join(".gitignore"), ".socket/\n").unwrap();
        let rules = gitignored(root, &paths).await.unwrap();
        assert!(rules.contains(".gitignore:1:.socket/"), "{rules}");
        assert!(gitignored(&tmp.path().join("missing"), &paths)
            .await
            .is_none());
    }

    /// Git failing to answer is not "not ignored": `gitignore_probe` says
    /// so (`gitignored` keeps its fail-open `None`), while git absent or a
    /// root outside any work tree still has nothing to check.
    #[tokio::test]
    async fn the_gitignore_probe_reports_a_git_failure() {
        let Some(git) = crate::utils::process::resolve_tool("git") else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        std::fs::create_dir_all(&root).unwrap();
        assert_eq!(
            gitignore_probe(&root, &["a".to_string()]).await,
            Ok(None),
            "outside a work tree"
        );
        let status = std::process::Command::new(&git)
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(status.success());
        // A path outside the repository makes `check-ignore` fail (128).
        let outside = vec!["../elsewhere/x.js".to_string()];
        let why = gitignore_probe(&root, &outside).await.unwrap_err();
        assert!(why.contains("`git check-ignore` exited 128"), "{why}");
        assert_eq!(gitignored(&root, &outside).await, None);
        assert!(
            gitignore_unchecked_detail(".socket/vendor/npm/u/a-1.0.0", &why)
                .contains("make sure no ignore rule covers .socket/")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_gitignore_probe_finishes_for_thousands_of_paths() {
        let Some(git) = crate::utils::process::resolve_tool("git") else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let status = std::process::Command::new(&git)
            .args(["init", "-q"])
            .current_dir(root)
            .status()
            .unwrap();
        assert!(status.success());
        let uuid = root.join(".socket/vendor/npm/u");
        std::fs::create_dir_all(&uuid).unwrap();
        restore_uuid_metadata(&uuid).await.unwrap();
        let mut paths: Vec<String> = (0..6000)
            .map(|i| format!(".socket/vendor/npm/u/d-2.30.0/node_modules/d/esm/f{i}/index.js"))
            .collect();
        let probe =
            tokio::time::timeout(std::time::Duration::from_secs(60), gitignored(root, &paths));
        assert_eq!(probe.await.expect("probe deadlocked"), None);
        std::fs::write(root.join(".gitignore"), ".socket/\n").unwrap();
        paths.push(".socket/vendor/npm/u/.gitignore".to_string());
        let probe =
            tokio::time::timeout(std::time::Duration::from_secs(60), gitignored(root, &paths));
        let rules = probe.await.expect("probe deadlocked").unwrap();
        assert!(rules.contains(".gitignore:1:.socket/"), "{rules}");
    }
}
