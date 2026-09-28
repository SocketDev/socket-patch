//! Parser and strict validator for the parts of `socket.yml` socket-patch
//! reads: `version`, `projectIgnorePaths` and the `patches` block.
//!
//! The file is read as a YAML 1.2 event stream (serde-saphyr's parser)
//! into a small node tree. Aliases are never expanded: an alias inside the
//! keys we read is refused, and one anywhere else is left alone, so an
//! alias bomb cannot cost anything. Plain scalars resolve with the YAML 1.2
//! core schema (`no` is a string, `"false"` is not a bool).

use std::collections::HashSet;

use serde_saphyr::granit_parser::{Event, Options, Parser, ScalarStyle, Tag};

use super::paths::{PathMatcher, MAX_PATTERN_BYTES};
use super::{sanitize, PolicyError, PolicyWarning};
use crate::api::ranking::severity_order;
use crate::crawlers::Ecosystem;

/// Largest accepted file, in bytes.
pub const MAX_FILE_BYTES: usize = 64 * 1024;
const MAX_DEPTH: usize = 32;
const MAX_LIST_ENTRIES: usize = 1000;

pub(crate) const PATCHES_KEYS: [&str; 8] = [
    "enabled",
    "includePaths",
    "ignorePaths",
    "ecosystems",
    "packages",
    "ignorePackages",
    "minSeverity",
    "maxNewPatches",
];

#[derive(Debug, Clone, PartialEq)]
enum Scalar {
    Null,
    Bool(bool),
    Int(i128),
    /// A float, or an integer too large for `i128`.
    Number,
    Str(String),
}

#[derive(Debug)]
enum Kind {
    Scalar {
        value: Scalar,
        raw: String,
        plain: bool,
    },
    Seq(Vec<Node>),
    Map(Vec<(Node, Node)>),
    Alias,
}

#[derive(Debug)]
struct Node {
    kind: Kind,
    anchored: bool,
    custom_tag: bool,
}

impl Node {
    fn as_str(&self) -> Option<&str> {
        match &self.kind {
            Kind::Scalar {
                value: Scalar::Str(s),
                ..
            } => Some(s),
            _ => None,
        }
    }

    fn is_merge_key(&self) -> bool {
        matches!(&self.kind, Kind::Scalar { raw, plain: true, .. } if raw == "<<")
    }

    fn describe(&self) -> &'static str {
        match &self.kind {
            Kind::Scalar { value, .. } => match value {
                Scalar::Null => "null",
                Scalar::Bool(_) => "a boolean",
                Scalar::Int(_) | Scalar::Number => "a number",
                Scalar::Str(_) => "a string",
            },
            Kind::Seq(_) => "a list",
            Kind::Map(_) => "a mapping",
            Kind::Alias => "an alias",
        }
    }
}

fn is_int_body(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn is_float(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    let unsigned = lower.trim_start_matches(['-', '+']);
    if matches!(unsigned, ".inf") || lower == ".nan" {
        return true;
    }
    let (mantissa, exponent) = match unsigned.split_once('e') {
        Some((m, e)) => (m, Some(e)),
        None => (unsigned, None),
    };
    let mantissa_ok = match mantissa.split_once('.') {
        Some((whole, frac)) => {
            (whole.is_empty() || is_int_body(whole))
                && (frac.is_empty() || is_int_body(frac))
                && !(whole.is_empty() && frac.is_empty())
        }
        None => is_int_body(mantissa),
    };
    let exponent_ok = exponent.is_none_or(|e| is_int_body(e.trim_start_matches(['-', '+'])));
    mantissa_ok && exponent_ok && (mantissa.contains('.') || exponent.is_some())
}

/// YAML 1.2 core-schema resolution of a plain scalar.
fn resolve_plain(raw: &str) -> Scalar {
    match raw {
        "" | "~" | "null" | "Null" | "NULL" => return Scalar::Null,
        "true" | "True" | "TRUE" => return Scalar::Bool(true),
        "false" | "False" | "FALSE" => return Scalar::Bool(false),
        _ => {}
    }
    let (negative, unsigned) = match raw.as_bytes().first() {
        Some(b'-') => (true, &raw[1..]),
        Some(b'+') => (false, &raw[1..]),
        _ => (false, raw),
    };
    if is_int_body(unsigned) {
        return match unsigned.parse::<i128>() {
            Ok(n) => Scalar::Int(if negative { -n } else { n }),
            Err(_) => Scalar::Number,
        };
    }
    if let Some(hex) = raw.strip_prefix("0x") {
        if !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return i128::from_str_radix(hex, 16).map_or(Scalar::Number, Scalar::Int);
        }
    }
    if let Some(oct) = raw.strip_prefix("0o") {
        if !oct.is_empty() && oct.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
            return i128::from_str_radix(oct, 8).map_or(Scalar::Number, Scalar::Int);
        }
    }
    if is_float(raw) {
        return Scalar::Number;
    }
    Scalar::Str(raw.to_string())
}

/// Resolve a scalar with its tag. `Err` is an explicit core tag the value
/// does not fit (`!!int abc`).
fn resolve_scalar(
    raw: &str,
    style: ScalarStyle,
    tag: Option<&Tag>,
) -> Result<(Scalar, bool), String> {
    let core = tag.and_then(|t| t.core_suffix().map(str::to_string));
    let custom = tag.is_some() && core.is_none();
    let plain = style == ScalarStyle::Plain;
    let value = match core.as_deref() {
        Some("str") => Scalar::Str(raw.to_string()),
        Some(kind @ ("int" | "bool" | "null" | "float")) => {
            let resolved = resolve_plain(raw);
            let fits = matches!(
                (kind, &resolved),
                ("int", Scalar::Int(_))
                    | ("bool", Scalar::Bool(_))
                    | ("null", Scalar::Null)
                    | ("float", Scalar::Number | Scalar::Int(_))
            );
            if !fits {
                return Err(format!("`{}` is not a valid !!{kind}", sanitize(raw)));
            }
            resolved
        }
        _ if plain && tag.is_none() => resolve_plain(raw),
        _ => Scalar::Str(raw.to_string()),
    };
    Ok((value, custom))
}

enum Frame {
    Seq(Node, Vec<Node>),
    Map(Node, Vec<(Node, Node)>, Option<Node>, HashSet<String>),
}

fn key_identity(key: &Node) -> Option<String> {
    match &key.kind {
        Kind::Scalar { value, .. } => Some(format!("{value:?}")),
        _ => None,
    }
}

/// Parse `text` into one document's root node; `None` for an empty or
/// comment-only stream.
fn build_tree(text: &str) -> Result<Option<Node>, String> {
    let mut options = Options::default();
    options.emit_comments = false;
    let parser = Parser::new_from_str_with_options(text, options);
    let mut stack: Vec<Frame> = Vec::new();
    let mut root: Option<Node> = None;
    let mut documents = 0usize;

    fn attach(stack: &mut [Frame], root: &mut Option<Node>, node: Node) -> Result<(), String> {
        match stack.last_mut() {
            None => {
                *root = Some(node);
                Ok(())
            }
            Some(Frame::Seq(_, items)) => {
                items.push(node);
                Ok(())
            }
            Some(Frame::Map(_, pairs, pending, seen)) => match pending.take() {
                None => {
                    *pending = Some(node);
                    Ok(())
                }
                Some(key) => {
                    if let Some(id) = key_identity(&key) {
                        if !seen.insert(id) {
                            let name = match &key.kind {
                                Kind::Scalar { raw, .. } => sanitize(raw),
                                _ => String::new(),
                            };
                            return Err(format!("duplicate key `{name}`"));
                        }
                    }
                    pairs.push((key, node));
                    Ok(())
                }
            },
        }
    }

    for event in parser {
        let (event, span) = event.map_err(|e| e.to_string())?;
        let line = span.start.line();
        let header = |anchor: usize, tag: Option<&Tag>| Node {
            kind: Kind::Alias,
            anchored: anchor != 0,
            custom_tag: tag.is_some_and(|t| t.core_suffix().is_none()),
        };
        match event {
            Event::StreamStart | Event::StreamEnd | Event::DocumentEnd | Event::Comment(..) => {}
            Event::DocumentStart(..) => {
                documents += 1;
                if documents > 1 {
                    return Err(format!("more than one YAML document (line {line})"));
                }
            }
            Event::Alias(_) => {
                let node = Node {
                    kind: Kind::Alias,
                    anchored: false,
                    custom_tag: false,
                };
                attach(&mut stack, &mut root, node)?;
            }
            Event::Scalar(raw, style, anchor, tag) => {
                let (value, custom_tag) = resolve_scalar(&raw, style, tag.as_deref())
                    .map_err(|m| format!("{m} (line {line})"))?;
                let node = Node {
                    kind: Kind::Scalar {
                        value,
                        raw: raw.into_owned(),
                        plain: style == ScalarStyle::Plain,
                    },
                    anchored: anchor != 0,
                    custom_tag,
                };
                attach(&mut stack, &mut root, node)?;
            }
            Event::SequenceStart(_, anchor, tag) => {
                if stack.len() >= MAX_DEPTH {
                    return Err(format!(
                        "nesting is deeper than {MAX_DEPTH} levels (line {line})"
                    ));
                }
                stack.push(Frame::Seq(header(anchor, tag.as_deref()), Vec::new()));
            }
            Event::MappingStart(_, anchor, tag) => {
                if stack.len() >= MAX_DEPTH {
                    return Err(format!(
                        "nesting is deeper than {MAX_DEPTH} levels (line {line})"
                    ));
                }
                stack.push(Frame::Map(
                    header(anchor, tag.as_deref()),
                    Vec::new(),
                    None,
                    HashSet::new(),
                ));
            }
            Event::SequenceEnd => {
                let Some(Frame::Seq(mut node, items)) = stack.pop() else {
                    return Err("unbalanced sequence".to_string());
                };
                node.kind = Kind::Seq(items);
                attach(&mut stack, &mut root, node)?;
            }
            Event::MappingEnd => {
                let Some(Frame::Map(mut node, pairs, _, _)) = stack.pop() else {
                    return Err("unbalanced mapping".to_string());
                };
                node.kind = Kind::Map(pairs);
                attach(&mut stack, &mut root, node)?;
            }
            _ => return Err(format!("unsupported YAML construct (line {line})")),
        }
    }
    Ok(root)
}

/// The validated `patches` block. `None` list fields mean "absent".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct PatchesBlock {
    pub enabled: Option<bool>,
    pub include_paths: Option<Vec<String>>,
    pub ignore_paths: Vec<String>,
    pub ecosystems: Option<Vec<String>>,
    pub packages: Option<Vec<String>>,
    pub ignore_packages: Vec<String>,
    pub min_severity: Option<u8>,
    pub max_new_patches: Option<u32>,
}

/// What one root file contributes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ParsedFile {
    /// Empty, comment-only or null document: the file counts as absent.
    pub empty: bool,
    pub patches: Option<PatchesBlock>,
    pub project_ignore_paths: Vec<String>,
}

impl ParsedFile {
    /// The parts two files must agree on when both exist.
    pub(crate) fn same_policy(&self, other: &ParsedFile) -> bool {
        self.patches == other.patches && self.project_ignore_paths == other.project_ignore_paths
    }
}

/// Levenshtein distance, for did-you-mean hints.
fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut prev = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cur = row[j + 1];
            row[j + 1] = if ca == *cb {
                prev
            } else {
                1 + prev.min(cur).min(row[j])
            };
            prev = cur;
        }
    }
    row[b.len()]
}

fn did_you_mean<'a>(input: &str, known: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    let lower = input.to_lowercase();
    known
        .into_iter()
        .map(|k| (edit_distance(&lower, &k.to_lowercase()), k))
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, k)| k)
}

struct Ctx<'a> {
    file: &'a str,
}

impl Ctx<'_> {
    fn err(&self, key: impl Into<String>, message: impl Into<String>) -> PolicyError {
        PolicyError::Invalid {
            file: self.file.to_string(),
            key: key.into(),
            message: message.into(),
        }
    }
}

/// Refuse anchors, aliases, merge keys and custom tags anywhere in `node`.
fn check_plain_subtree(node: &Node, path: &str) -> Result<(), (String, String)> {
    if node.anchored {
        return Err((
            path.to_string(),
            "YAML anchors are not allowed here".to_string(),
        ));
    }
    if node.custom_tag {
        return Err((
            path.to_string(),
            "custom YAML tags are not allowed here".to_string(),
        ));
    }
    match &node.kind {
        Kind::Alias => Err((
            path.to_string(),
            "YAML aliases are not allowed here".to_string(),
        )),
        Kind::Scalar { .. } => Ok(()),
        Kind::Seq(items) => {
            for (i, item) in items.iter().enumerate() {
                check_plain_subtree(item, &format!("{path}[{i}]"))?;
            }
            Ok(())
        }
        Kind::Map(pairs) => {
            for (key, value) in pairs {
                if key.is_merge_key() {
                    return Err((
                        path.to_string(),
                        "YAML merge keys (`<<`) are not allowed here".to_string(),
                    ));
                }
                let name = key.as_str().map(sanitize).unwrap_or_default();
                let child = if path.is_empty() {
                    name
                } else {
                    format!("{path}.{name}")
                };
                check_plain_subtree(key, &child)?;
                check_plain_subtree(value, &child)?;
            }
            Ok(())
        }
    }
}

/// A list of strings, with the size limits every list key shares.
fn string_list(node: &Node, key: &str) -> Result<Vec<String>, (String, String)> {
    let Kind::Seq(items) = &node.kind else {
        return Err((
            key.to_string(),
            format!("must be a list of strings, found {}", node.describe()),
        ));
    };
    if items.len() > MAX_LIST_ENTRIES {
        return Err((
            key.to_string(),
            format!("has more than {MAX_LIST_ENTRIES} entries"),
        ));
    }
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let path = format!("{key}[{i}]");
        let Some(s) = item.as_str() else {
            return Err((
                path,
                format!("must be a string, found {} (quote it)", item.describe()),
            ));
        };
        if s.len() > MAX_PATTERN_BYTES {
            return Err((path, format!("is longer than {MAX_PATTERN_BYTES} bytes")));
        }
        out.push(s.to_string());
    }
    Ok(out)
}

/// Compile a pattern list so a bad glob fails here, with its key path.
fn check_patterns(patterns: &[String], key: &'static str) -> Result<(), (String, String)> {
    PathMatcher::new(&[(key, patterns)])
        .map(|_| ())
        .map_err(|(_, pattern, message)| {
            let index = patterns.iter().position(|p| *p == pattern);
            let path = index.map_or_else(|| key.to_string(), |i| format!("{key}[{i}]"));
            (path, format!("{message}: `{}`", sanitize(&pattern)))
        })
}

/// Why a `--package`-grammar spec is invalid, if it is.
pub(crate) fn package_spec_error(spec: &str) -> Option<&'static str> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Some("package spec is empty");
    }
    if spec.len() >= 4 && spec[..4].eq_ignore_ascii_case("pkg:") {
        let rest = &spec[4..];
        let valid = rest.split_once('/').is_some_and(|(ty, name)| {
            !ty.is_empty() && !name.trim_matches('/').is_empty() && !name.starts_with('@')
        });
        if !valid {
            return Some("purl spec needs a type and a name (`pkg:npm/lodash`)");
        }
    }
    None
}

fn project_ignore_paths(node: &Node) -> Result<Vec<String>, (String, String)> {
    const KEY: &str = "projectIgnorePaths";
    check_plain_subtree(node, KEY)?;
    let list = match &node.kind {
        Kind::Scalar {
            value: Scalar::Null,
            ..
        } => Vec::new(),
        Kind::Scalar {
            value: Scalar::Str(s),
            ..
        } => vec![s.clone()],
        _ => string_list(node, KEY)?,
    };
    if list.len() == 1 && list[0].len() > MAX_PATTERN_BYTES {
        return Err((
            KEY.to_string(),
            format!("is longer than {MAX_PATTERN_BYTES} bytes"),
        ));
    }
    check_patterns(&list, KEY)?;
    Ok(list)
}

fn patches_block(node: &Node) -> Result<PatchesBlock, (String, String)> {
    let mut block = PatchesBlock::default();
    let pairs = match &node.kind {
        Kind::Scalar {
            value: Scalar::Null,
            ..
        } if !node.anchored && !node.custom_tag => return Ok(block),
        Kind::Map(pairs) => pairs,
        _ => {
            check_plain_subtree(node, "patches")?;
            return Err((
                "patches".to_string(),
                format!("must be a mapping, found {}", node.describe()),
            ));
        }
    };
    check_plain_subtree(node, "patches")?;
    for (key, value) in pairs {
        let Some(name) = key.as_str() else {
            return Err((
                "patches".to_string(),
                format!("keys must be strings, found {}", key.describe()),
            ));
        };
        let path = format!("patches.{}", sanitize(name));
        if !PATCHES_KEYS.contains(&name) {
            let hint = did_you_mean(name, PATCHES_KEYS)
                .map(|k| format!(" (did you mean `{k}`?)"))
                .unwrap_or_default();
            return Err((
                path,
                format!(
                    "unknown key{hint}; a newer socket-patch may support it: upgrade socket-patch or remove the key"
                ),
            ));
        }
        if matches!(
            &value.kind,
            Kind::Scalar {
                value: Scalar::Null,
                ..
            }
        ) {
            return Err((
                path,
                "has no value; remove the key to use the default".to_string(),
            ));
        }
        match name {
            "enabled" => match &value.kind {
                Kind::Scalar {
                    value: Scalar::Bool(b),
                    ..
                } => block.enabled = Some(*b),
                _ => {
                    return Err((
                        path,
                        format!("must be true or false, found {}", value.describe()),
                    ))
                }
            },
            "includePaths" | "ignorePaths" => {
                let list = string_list(value, &path)?;
                let key: &'static str = if name == "includePaths" {
                    "patches.includePaths"
                } else {
                    "patches.ignorePaths"
                };
                check_patterns(&list, key)?;
                if name == "includePaths" {
                    if list.is_empty() {
                        return Err((path, "is empty and would match nothing; use `enabled: false` to pause patching".to_string()));
                    }
                    block.include_paths = Some(list);
                } else {
                    block.ignore_paths = list;
                }
            }
            "ecosystems" => {
                let list = string_list(value, &path)?;
                if list.is_empty() {
                    return Err((
                        path,
                        "is empty and would match nothing; use `enabled: false` to pause patching"
                            .to_string(),
                    ));
                }
                let known: Vec<&str> = Ecosystem::all().iter().map(|e| e.cli_name()).collect();
                let mut out = Vec::with_capacity(list.len());
                for (i, entry) in list.iter().enumerate() {
                    let lower = entry.trim().to_lowercase();
                    if !known.contains(&lower.as_str()) {
                        let hint = did_you_mean(&lower, known.iter().copied())
                            .map(|k| format!(" (did you mean `{k}`?)"))
                            .unwrap_or_default();
                        return Err((
                            format!("{path}[{i}]"),
                            format!(
                                "unknown ecosystem `{}`{hint}; expected one of {}",
                                sanitize(entry),
                                known.join(", ")
                            ),
                        ));
                    }
                    out.push(lower);
                }
                block.ecosystems = Some(out);
            }
            "packages" | "ignorePackages" => {
                let list = string_list(value, &path)?;
                if name == "packages" && list.is_empty() {
                    return Err((
                        path,
                        "is empty and would match nothing; use `enabled: false` to pause patching"
                            .to_string(),
                    ));
                }
                for (i, spec) in list.iter().enumerate() {
                    if let Some(message) = package_spec_error(spec) {
                        return Err((
                            format!("{path}[{i}]"),
                            format!("{message}: `{}`", sanitize(spec)),
                        ));
                    }
                }
                if name == "packages" {
                    block.packages = Some(list);
                } else {
                    block.ignore_packages = list;
                }
            }
            "minSeverity" => {
                let Some(s) = value.as_str() else {
                    return Err((
                        path,
                        format!("must be a string, found {}", value.describe()),
                    ));
                };
                match parse_severity_name(s) {
                    Some(order) => block.min_severity = Some(order),
                    None => {
                        return Err((
                            path,
                            format!("unknown severity `{}`; expected critical, high, medium, moderate or low", sanitize(s)),
                        ))
                    }
                }
            }
            "maxNewPatches" => match &value.kind {
                Kind::Scalar {
                    value: Scalar::Int(n),
                    ..
                } if (0..=i128::from(u32::MAX)).contains(n) => {
                    block.max_new_patches = Some(u32::try_from(*n).unwrap_or(u32::MAX));
                }
                _ => {
                    return Err((
                        path,
                        format!(
                            "must be an integer from 0 to {}, found {}",
                            u32::MAX,
                            value.describe()
                        ),
                    ))
                }
            },
            _ => unreachable!("PATCHES_KEYS is exhaustive"),
        }
    }
    Ok(block)
}

/// `critical|high|medium|moderate|low` (any case) to a severity order.
pub(crate) fn parse_severity_name(s: &str) -> Option<u8> {
    match s.trim().to_ascii_lowercase().as_str() {
        name @ ("critical" | "high" | "medium" | "moderate" | "low") => {
            Some(severity_order(Some(name)))
        }
        _ => None,
    }
}

fn decode(ctx: &Ctx<'_>, bytes: &[u8]) -> Result<String, PolicyError> {
    if bytes.starts_with(&[0xFE, 0xFF]) || bytes.starts_with(&[0xFF, 0xFE]) {
        return Err(ctx.err("", "file is UTF-16; save it as UTF-8"));
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    if bytes.contains(&0) {
        return Err(ctx.err("", "file contains NUL bytes; save it as UTF-8 text"));
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| ctx.err("", "file is not valid UTF-8"))
}

/// Parse and validate one root policy file (4.4).
pub(crate) fn parse_file(
    file: &str,
    bytes: &[u8],
    warnings: &mut Vec<PolicyWarning>,
) -> Result<ParsedFile, PolicyError> {
    let ctx = Ctx { file };
    let text = decode(&ctx, bytes)?;
    let root = build_tree(&text).map_err(|m| ctx.err("", format!("invalid YAML: {m}")))?;
    let Some(root) = root else {
        return Ok(ParsedFile {
            empty: true,
            ..ParsedFile::default()
        });
    };
    let pairs = match &root.kind {
        Kind::Map(pairs) => pairs,
        Kind::Scalar {
            value: Scalar::Null,
            ..
        } => {
            return Ok(ParsedFile {
                empty: true,
                ..ParsedFile::default()
            })
        }
        _ => {
            return Err(ctx.err(
                "",
                format!("the top level must be a mapping, found {}", root.describe()),
            ));
        }
    };

    let mut version: Option<&Node> = None;
    let mut patches: Option<&Node> = None;
    let mut ignore_paths: Option<&Node> = None;
    for (key, value) in pairs {
        let Some(name) = key.as_str() else { continue };
        let lower = name.to_ascii_lowercase();
        if (lower == "patch" || lower == "patches") && name != "patches" {
            return Err(ctx.err(
                sanitize(name),
                "looks like a misspelled `patches` block; the key must be exactly `patches`",
            ));
        }
        match name {
            "version" => version = Some(value),
            "patches" => patches = Some(value),
            "projectIgnorePaths" => ignore_paths = Some(value),
            _ => {}
        }
    }

    let Some(patches) = patches else {
        let project_ignore_paths = match ignore_paths.map(project_ignore_paths) {
            None => Vec::new(),
            Some(Ok(list)) => list,
            Some(Err((key, message))) => {
                warnings.push(PolicyWarning {
                    code: super::SOCKET_YML_IGNORED_VALUE,
                    detail: format!("{file}: {key} {message}; the key is ignored"),
                });
                Vec::new()
            }
        };
        return Ok(ParsedFile {
            empty: false,
            patches: None,
            project_ignore_paths,
        });
    };

    let version_ok = version.is_some_and(|v| {
        matches!(
            &v.kind,
            Kind::Scalar {
                value: Scalar::Int(2),
                ..
            }
        ) || matches!(&v.kind, Kind::Scalar { value: Scalar::Str(s), .. } if s == "2")
    });
    if !version_ok {
        return Err(ctx.err("version", "a `patches` block requires `version: 2`"));
    }
    let project_ignore_paths = match ignore_paths {
        None => Vec::new(),
        Some(node) => project_ignore_paths(node).map_err(|(key, message)| ctx.err(key, message))?,
    };
    let block = patches_block(patches).map_err(|(key, message)| ctx.err(key, message))?;
    Ok(ParsedFile {
        empty: false,
        patches: Some(block),
        project_ignore_paths,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<ParsedFile, PolicyError> {
        let mut warnings = Vec::new();
        parse_file("socket.yml", text.as_bytes(), &mut warnings)
    }

    fn parse_warn(text: &str) -> (ParsedFile, Vec<PolicyWarning>) {
        let mut warnings = Vec::new();
        let parsed = parse_file("socket.yml", text.as_bytes(), &mut warnings).expect("parses");
        (parsed, warnings)
    }

    fn err_key(text: &str) -> (String, String) {
        match parse(text) {
            Err(PolicyError::Invalid { key, message, .. }) => (key, message),
            other => panic!("expected an invalid-file error for {text:?}, got {other:?}"),
        }
    }

    fn block(text: &str) -> PatchesBlock {
        parse(text).expect("valid").patches.expect("patches block")
    }

    #[test]
    fn every_key_parses() {
        let b = block(
            "version: 2\npatches:\n  enabled: false\n  includePaths: [\"/services/\"]\n  ignorePaths: [\"/legacy/\"]\n  ecosystems: [NPM, pypi]\n  packages: [\"pkg:npm/lodash\"]\n  ignorePackages: [\"pkg:npm/left-pad\", \"core\"]\n  minSeverity: High\n  maxNewPatches: 5\n",
        );
        assert_eq!(b.enabled, Some(false));
        assert_eq!(b.include_paths, Some(vec!["/services/".to_string()]));
        assert_eq!(b.ignore_paths, vec!["/legacy/".to_string()]);
        assert_eq!(
            b.ecosystems,
            Some(vec!["npm".to_string(), "pypi".to_string()])
        );
        assert_eq!(b.packages, Some(vec!["pkg:npm/lodash".to_string()]));
        assert_eq!(b.ignore_packages.len(), 2);
        assert_eq!(b.min_severity, Some(1));
        assert_eq!(b.max_new_patches, Some(5));
    }

    #[test]
    fn defaults_when_absent() {
        for text in [
            "version: 2\npatches:\n",
            "version: 2\npatches: {}\n",
            "version: 2\npatches: null\n",
        ] {
            assert_eq!(block(text), PatchesBlock::default(), "{text:?}");
        }
        let parsed = parse("version: 2\n").unwrap();
        assert!(parsed.patches.is_none());
        assert!(!parsed.empty);
    }

    #[test]
    fn empty_and_comment_only_files_are_absent() {
        for text in ["", "\n\n", "# just a comment\n", "---\n", "~\n"] {
            assert!(parse(text).unwrap().empty, "{text:?}");
        }
    }

    #[test]
    fn bom_and_crlf_are_fine() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"version: 2\r\npatches:\r\n  maxNewPatches: 3\r\n");
        let parsed = parse_file("socket.yml", &bytes, &mut Vec::new()).unwrap();
        assert_eq!(parsed.patches.unwrap().max_new_patches, Some(3));
    }

    #[test]
    fn encoding_errors() {
        for bytes in [
            &b"\xFF\xFEv\0e\0r\0"[..],
            &b"\xFE\xFF\0v\0e"[..],
            &b"version: 2\0\n"[..],
            &b"version: \xC3\x28\n"[..],
        ] {
            assert!(
                parse_file("socket.yml", bytes, &mut Vec::new()).is_err(),
                "{bytes:?}"
            );
        }
    }

    #[test]
    fn yaml_errors() {
        for text in [
            "version: 2\npatches: [\n",
            "a: 1\na: 2\n",
            "version: 2\npatches:\n  enabled: true\n  enabled: false\n",
            "- a\n- b\n",
            "just a string\n",
            "a: 1\n---\nb: 2\n",
            "projectIgnorePaths:\n  - **\n",
        ] {
            assert!(parse(text).is_err(), "{text:?} must fail");
        }
    }

    #[test]
    fn nesting_limit() {
        let deep = format!("a: {}{}\n", "[".repeat(40), "]".repeat(40));
        let (key, message) = err_key(&deep);
        assert_eq!(key, "");
        assert!(message.contains("deeper than 32"), "{message}");
        let ok = format!("a: {}{}\n", "[".repeat(30), "]".repeat(30));
        assert!(parse(&ok).is_ok());
    }

    #[test]
    fn alias_bomb_elsewhere_is_never_expanded() {
        let mut text = String::from(
            "a: &a [\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\"]\n",
        );
        let names = ["b", "c", "d", "e", "f", "g", "h", "i", "j"];
        let mut prev = "a";
        for name in names {
            text.push_str(&format!("{name}: &{name} [*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev}]\n"));
            prev = name;
        }
        text.push_str("version: 2\npatches:\n  maxNewPatches: 1\n");
        let started = std::time::Instant::now();
        assert_eq!(block(&text).max_new_patches, Some(1));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn anchors_aliases_and_merge_keys_are_refused_in_our_keys() {
        for text in [
            "version: 2\nx: &x [\"/a/\"]\npatches:\n  ignorePaths: *x\n",
            "version: 2\npatches:\n  ignorePaths: &y [\"/a/\"]\n",
            "version: 2\nbase: &b {maxNewPatches: 1}\npatches:\n  <<: *b\n",
            "version: 2\npatches:\n  <<: {maxNewPatches: 1}\n",
            "version: 2\nx: &x \"/a/\"\npatches: {}\nprojectIgnorePaths: [*x]\n",
            "version: 2\npatches: &p {}\n",
            "version: 2\npatches:\n  minSeverity: !custom high\n",
        ] {
            let (_, message) = err_key(text);
            assert!(message.contains("not allowed"), "{text:?}: {message}");
        }
        // Outside the keys we read, anchors and aliases are someone else's business.
        let ok = "version: 2\nissueRules: &r {a: 1}\nother: *r\npatches:\n  maxNewPatches: 2\n";
        assert_eq!(block(ok).max_new_patches, Some(2));
    }

    #[test]
    fn case_variant_of_patches_is_an_error() {
        for text in [
            "version: 2\nPatches: {}\n",
            "version: 2\npatch:\n  enabled: false\n",
            "PATCHES: {}\n",
        ] {
            let (_, message) = err_key(text);
            assert!(message.contains("misspelled"), "{text:?}: {message}");
        }
    }

    #[test]
    fn version_gate() {
        for text in [
            "patches: {}\n",
            "version: 1\npatches: {}\n",
            "version: 3\npatches: {}\n",
            "version: 2.0\npatches: {}\n",
        ] {
            assert_eq!(err_key(text).0, "version", "{text:?}");
        }
        assert!(parse("version: \"2\"\npatches: {}\n").is_ok());
        // No patches block: any version, projectIgnorePaths honored.
        let parsed = parse("version: 1\nprojectIgnorePaths: [\"/a/\"]\n").unwrap();
        assert_eq!(parsed.project_ignore_paths, vec!["/a/".to_string()]);
    }

    #[test]
    fn unknown_keys_with_hint() {
        let (key, message) = err_key("version: 2\npatches:\n  minSeverty: high\n");
        assert_eq!(key, "patches.minSeverty");
        assert!(message.contains("did you mean `minSeverity`"), "{message}");
        assert!(message.contains("newer socket-patch"), "{message}");
        let (_, message) = err_key("version: 2\npatches:\n  apiToken: x\n");
        assert!(!message.contains("did you mean"), "{message}");
        let (key, message) = err_key("version: 2\npatches:\n  maxnewpatches: 1\n");
        assert_eq!(key, "patches.maxnewpatches");
        assert!(
            message.contains("did you mean `maxNewPatches`"),
            "{message}"
        );
    }

    #[test]
    fn trust_boundary_keys_are_unknown() {
        for key in [
            "apiUrl",
            "apiToken",
            "org",
            "mode",
            "downloadMode",
            "patchServerUrl",
            "noVerify",
            "strict",
        ] {
            let text = format!("version: 2\npatches:\n  {key}: x\n");
            assert_eq!(err_key(&text).0, format!("patches.{key}"));
        }
    }

    #[test]
    fn wrong_types() {
        let cases = [
            ("enabled: \"false\"", "patches.enabled"),
            ("enabled: no", "patches.enabled"),
            ("enabled: 1", "patches.enabled"),
            ("enabled:", "patches.enabled"),
            ("includePaths: \"/a/\"", "patches.includePaths"),
            ("includePaths: [1]", "patches.includePaths[0]"),
            ("includePaths: []", "patches.includePaths"),
            ("ecosystems: []", "patches.ecosystems"),
            ("ecosystems: [npn]", "patches.ecosystems[0]"),
            ("packages: []", "patches.packages"),
            ("packages: [\"pkg:\"]", "patches.packages[0]"),
            (
                "ignorePackages: [\"pkg:npm/\"]",
                "patches.ignorePackages[0]",
            ),
            ("ignorePackages: [\"  \"]", "patches.ignorePackages[0]"),
            ("minSeverity: severe", "patches.minSeverity"),
            ("minSeverity: none", "patches.minSeverity"),
            ("minSeverity: 1", "patches.minSeverity"),
            ("maxNewPatches: -1", "patches.maxNewPatches"),
            ("maxNewPatches: 4294967296", "patches.maxNewPatches"),
            ("maxNewPatches: 1.5", "patches.maxNewPatches"),
            ("maxNewPatches: \"5\"", "patches.maxNewPatches"),
            ("ignorePaths: [\"../x\"]", "patches.ignorePaths[0]"),
            ("ignorePaths: [\"C:/x\"]", "patches.ignorePaths[0]"),
            ("ignorePaths: [\"a/[b\"]", "patches.ignorePaths[0]"),
            ("ignorePaths: {a: 1}", "patches.ignorePaths"),
        ];
        for (line, key) in cases {
            let text = format!("version: 2\npatches:\n  {line}\n");
            assert_eq!(err_key(&text).0, key, "{line}");
        }
        assert!(parse("version: 2\npatches: [a]\n").is_err());
        assert!(parse("version: 2\npatches: true\n").is_err());
    }

    #[test]
    fn size_limits_on_lists() {
        let many: Vec<String> = (0..1001).map(|i| format!("\"/a{i}/\"")).collect();
        let text = format!(
            "version: 2\npatches:\n  ignorePaths: [{}]\n",
            many.join(",")
        );
        assert_eq!(err_key(&text).0, "patches.ignorePaths");
        let long = "a".repeat(1025);
        let text = format!("version: 2\npatches:\n  ignorePackages: [\"{long}\"]\n");
        assert_eq!(err_key(&text).0, "patches.ignorePackages[0]");
    }

    #[test]
    fn integer_forms_and_boundaries() {
        assert_eq!(
            block("version: 2\npatches:\n  maxNewPatches: 0\n").max_new_patches,
            Some(0)
        );
        assert_eq!(
            block("version: 2\npatches:\n  maxNewPatches: 4294967295\n").max_new_patches,
            Some(u32::MAX)
        );
        assert_eq!(
            block("version: 2\npatches:\n  maxNewPatches: 0x10\n").max_new_patches,
            Some(16)
        );
        assert_eq!(
            block("version: 2\npatches:\n  maxNewPatches: !!int \"7\"\n").max_new_patches,
            Some(7)
        );
        assert!(parse("version: 2\npatches:\n  maxNewPatches: !!int seven\n").is_err());
    }

    #[test]
    fn moderate_is_medium() {
        assert_eq!(
            block("version: 2\npatches:\n  minSeverity: moderate\n").min_severity,
            Some(2)
        );
        assert_eq!(
            block("version: 2\npatches:\n  minSeverity: medium\n").min_severity,
            Some(2)
        );
    }

    #[test]
    fn project_ignore_paths_rules() {
        // Strict with a patches block.
        let parsed = parse("version: 2\nprojectIgnorePaths: \"/a/\"\npatches: {}\n").unwrap();
        assert_eq!(parsed.project_ignore_paths, vec!["/a/".to_string()]);
        assert_eq!(
            err_key("version: 2\nprojectIgnorePaths: 5\npatches: {}\n").0,
            "projectIgnorePaths"
        );
        assert_eq!(
            err_key("version: 2\nprojectIgnorePaths: [\"../x\"]\npatches: {}\n").0,
            "projectIgnorePaths[0]"
        );
        // Lenient without one: warning, key ignored.
        let (parsed, warnings) = parse_warn("version: 2\nprojectIgnorePaths: {a: 1}\n");
        assert!(parsed.project_ignore_paths.is_empty());
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, "socket_yml_ignored_value");
        let (parsed, warnings) = parse_warn("projectIgnorePaths: [\"/a/\", \"b/\"]\n");
        assert_eq!(parsed.project_ignore_paths.len(), 2);
        assert!(warnings.is_empty());
    }

    #[test]
    fn yaml12_scalars() {
        assert_eq!(resolve_plain("no"), Scalar::Str("no".to_string()));
        assert_eq!(resolve_plain("yes"), Scalar::Str("yes".to_string()));
        assert_eq!(resolve_plain("True"), Scalar::Bool(true));
        assert_eq!(resolve_plain("~"), Scalar::Null);
        assert_eq!(resolve_plain("-12"), Scalar::Int(-12));
        assert_eq!(resolve_plain("0o17"), Scalar::Int(15));
        assert_eq!(resolve_plain("1e3"), Scalar::Number);
        assert_eq!(resolve_plain(".5"), Scalar::Number);
        assert_eq!(resolve_plain("1.2.3"), Scalar::Str("1.2.3".to_string()));
        assert_eq!(resolve_plain("0x"), Scalar::Str("0x".to_string()));
    }

    #[test]
    fn same_policy_compares_parsed_values() {
        let a = parse("version: 2\npatches: {maxNewPatches: 1}\n").unwrap();
        let b = parse(
            "# other comments\nversion: \"2\"\npatches:\n  maxNewPatches: 0x1\nissueRules: {}\n",
        )
        .unwrap();
        assert!(a.same_policy(&b));
        let c = parse("version: 2\npatches: {maxNewPatches: 2}\n").unwrap();
        assert!(!a.same_policy(&c));
        let d = parse("version: 2\nprojectIgnorePaths: [\"/b/\", \"/a/\"]\n").unwrap();
        let e = parse("version: 2\nprojectIgnorePaths: [\"/a/\", \"/b/\"]\n").unwrap();
        assert!(!d.same_policy(&e), "order-sensitive");
    }

    #[test]
    fn package_specs() {
        for good in [
            "lodash",
            "@babel/core",
            "pkg:npm/lodash",
            "pkg:npm/lodash@4.17.21",
            "pkg:pypi/requests",
            "PKG:npm/x",
        ] {
            assert!(package_spec_error(good).is_none(), "{good}");
        }
        for bad in [
            "",
            " ",
            "pkg:",
            "pkg:npm",
            "pkg:npm/",
            "pkg:/lodash",
            "pkg:npm/@1.0.0",
        ] {
            assert!(package_spec_error(bad).is_some(), "{bad:?}");
        }
    }

    #[test]
    fn did_you_mean_distance() {
        assert_eq!(
            did_you_mean("ignorePath", PATCHES_KEYS),
            Some("ignorePaths")
        );
        assert_eq!(did_you_mean("zzzzzz", PATCHES_KEYS), None);
    }
}
