//! `.yarnrc.yml` settings, read the way yarn berry reads them (#1100).
//!
//! Yarn parses the file as YAML, so a setting can sit under a quoted key,
//! on the line after its key, or in a flow mapping, and the last
//! occurrence of a key wins. Every value then has its environment
//! references expanded (yarn's `replaceEnvVariables`): `${NAME}`,
//! `${NAME-fallback}` (the fallback when `NAME` is unset) and
//! `${NAME:-fallback}` (also when it is empty). A reference to an unset
//! variable with no fallback is an error yarn refuses to run on.
//!
//! Every `.yarnrc.yml` scalar socket-patch decides on (`nodeLinker`,
//! `compressionLevel`, `pnpmStoreFolder`) is read through [`setting`], so
//! no reader takes the literal `${…}` text for the value yarn uses.
//!
//! Yarn 4 expands those references with the variables of its
//! `injectEnvironmentFiles` (`.env.yarn` by default) applied, a file's
//! value winning over an exported one (#1611): [`env_file_paths`] names
//! the files and [`injected_env`] reads them.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use serde_saphyr::granit_parser::{Event, Options, Parser};

use crate::formats::text::strip_bom;

/// A top-level `.yarnrc.yml` setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YarnrcSetting {
    /// The scalar as written in the file, quotes removed and nothing
    /// expanded: what a refusal names, so it never prints the value of an
    /// environment variable the file pulls in.
    pub raw: String,
    /// The value yarn uses, its environment references expanded; `None`
    /// when a reference cannot be (an unset variable with no fallback).
    pub value: Option<String>,
}

/// The top-level setting `key` of the rc text `rc`, its references
/// expanded through `var` (a variable's value, `None` when unset). `None`
/// when the file does not set `key` to a scalar.
pub fn setting(rc: &str, key: &str, var: &dyn Fn(&str) -> Option<String>) -> Option<YarnrcSetting> {
    let raw = raw_setting(rc, key)?;
    let value = expand_env(&raw, &mut |name| Ok(var(name))).ok();
    Some(YarnrcSetting { raw, value })
}

/// The top-level scalar `key` of `rc` as written (quotes removed, nothing
/// expanded), or `None` when it is absent or not a scalar. The file is
/// parsed as YAML after one leading BOM (yarn's parser skips one); a file
/// that does not parse as one YAML document falls back to a column-0 line
/// scan, so a setting stays readable in a file yarn would refuse anyway.
pub fn raw_setting(rc: &str, key: &str) -> Option<String> {
    let rc = strip_bom(rc);
    // A second BOM is content to yarn (#905), which the YAML parser would
    // skip as a marker; the line scan keeps it in the key.
    if strip_bom(rc).len() < rc.len() {
        return line_scan(rc, key);
    }
    match top_level_values(rc) {
        Ok(mut settings) => match settings.remove(key) {
            Some(RcValue::Scalar(value)) => Some(value),
            _ => None,
        },
        Err(()) => line_scan(rc, key),
    }
}

/// The top-level list setting `key` of `rc` as written (nothing
/// expanded): a sequence's scalar items, or a scalar split at its commas,
/// as yarn reads an array setting given as a string. The last occurrence
/// wins; `Some(vec![])` empties the list. `None` when the file does not
/// set `key` to a list or scalar, or yarn would refuse it (not a single
/// YAML document with a mapping root, or a second BOM).
pub fn raw_list_setting(rc: &str, key: &str) -> Option<Vec<String>> {
    let rc = strip_bom(rc);
    if strip_bom(rc).len() < rc.len() {
        return None;
    }
    match top_level_values(rc).ok()?.remove(key)? {
        RcValue::Scalar(value) => Some(split_list(&value)),
        RcValue::List(items) => Some(items),
        RcValue::Other => None,
    }
}

/// A string given for an array setting, split at its commas, each item
/// trimmed and empty ones dropped.
fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

/// A top-level setting's value, as [`top_level_values`] reads it.
enum RcValue {
    Scalar(String),
    /// A sequence: its scalar items.
    List(Vec<String>),
    /// A nested mapping or an alias.
    Other,
}

/// The root mapping's keys, each with its value (a sequence's scalar
/// items; nothing for a nested mapping or alias); the last occurrence of a key wins,
/// as in yarn. A root that is not a mapping (a list, a lone scalar) sets
/// nothing: yarn refuses such a file. `Err` when the text is not a single
/// YAML document.
fn top_level_values(rc: &str) -> Result<HashMap<String, RcValue>, ()> {
    let mut options = Options::default();
    options.emit_comments = false;
    let mut out = HashMap::new();
    let mut depth = 0usize;
    let mut documents = 0usize;
    let mut pending_key: Option<String> = None;
    // Whether the next root-level node is a key (true) or a value.
    let mut at_key = true;
    let mut root_is_mapping = false;
    // The setting whose sequence value is being read, with its items.
    let mut list: Option<(String, Vec<String>)> = None;
    for event in Parser::new_from_str_with_options(rc, options) {
        let (event, _) = event.map_err(|_| ())?;
        match event {
            Event::StreamStart | Event::StreamEnd | Event::DocumentEnd | Event::Comment(..) => {}
            Event::DocumentStart(..) => {
                documents += 1;
                if documents > 1 {
                    return Err(());
                }
            }
            Event::MappingStart(..) | Event::SequenceStart(..) => {
                if depth == 0 {
                    root_is_mapping = matches!(event, Event::MappingStart(..));
                } else if depth == 1 && !at_key {
                    if let Some(key) = pending_key.take() {
                        if root_is_mapping && matches!(event, Event::SequenceStart(..)) {
                            list = Some((key, Vec::new()));
                        } else {
                            out.insert(key, RcValue::Other);
                        }
                    }
                    at_key = true;
                } else if depth == 1 {
                    // A complex key: not a setting name.
                    pending_key = None;
                    at_key = false;
                }
                depth += 1;
            }
            Event::MappingEnd | Event::SequenceEnd => {
                depth = depth.saturating_sub(1);
                if depth == 1 {
                    if let Some((key, items)) = list.take() {
                        out.insert(key, RcValue::List(items));
                    }
                }
            }
            Event::Scalar(text, ..) if depth == 1 && root_is_mapping => {
                if at_key {
                    pending_key = Some(text.into_owned());
                    at_key = false;
                } else {
                    if let Some(key) = pending_key.take() {
                        out.insert(key, RcValue::Scalar(text.into_owned()));
                    }
                    at_key = true;
                }
            }
            Event::Scalar(text, ..) if depth == 2 => {
                if let Some((_, items)) = list.as_mut() {
                    items.push(text.into_owned());
                }
            }
            Event::Alias(_) if depth == 1 && root_is_mapping => {
                if !at_key {
                    if let Some(key) = pending_key.take() {
                        out.insert(key, RcValue::Other);
                    }
                }
                at_key = !at_key;
            }
            _ => {}
        }
    }
    Ok(out)
}

/// `injectEnvironmentFiles`' default: the folder yarn runs in's
/// `.env.yarn`, optional.
pub const DEFAULT_ENV_FILES: &[&str] = &[".env.yarn?"];

/// The environment files yarn 4 loads (`injectEnvironmentFiles`), in load
/// order. The list is `env_list` (`YARN_INJECT_ENVIRONMENT_FILES`, comma
/// separated) when set, else that of the highest-precedence rc file in
/// `rcs` (each with its folder, which its relative entries resolve
/// against) that sets it, else [`DEFAULT_ENV_FILES`]; the environment's
/// and the default entries resolve against `start`, the folder yarn runs
/// in. An entry's `${NAME}` references expand through `var`; one that
/// cannot is skipped. The optional marker (`?`) is dropped: yarn stops on
/// a missing required file, so no run of it reads a value from one.
pub fn env_file_paths(
    env_list: Option<&str>,
    rcs: &[(&Path, &str)],
    start: &Path,
    var: &dyn Fn(&str) -> Option<String>,
) -> Vec<PathBuf> {
    let (base, entries) = match env_list {
        Some(list) => (start, split_list(list)),
        None => rcs
            .iter()
            .find_map(|(dir, rc)| Some((*dir, raw_list_setting(rc, "injectEnvironmentFiles")?)))
            .unwrap_or_else(|| {
                (
                    start,
                    DEFAULT_ENV_FILES.iter().map(|f| f.to_string()).collect(),
                )
            }),
    };
    entries
        .iter()
        .filter_map(|entry| {
            let entry = expand_env(entry, &mut |name| Ok(var(name))).ok()?;
            let path = entry.strip_suffix('?').unwrap_or(&entry);
            (!path.is_empty()).then(|| base.join(path))
        })
        .collect()
}

/// The variables yarn adds to its environment from the dotenv files
/// `paths` ([`env_file_paths`]), as `read` gives their text (`None`: the
/// file is missing or unreadable, which injects nothing). Each value has
/// its `${NAME}` references expanded, as yarn does, against the variables
/// injected so far, then `var` (the environment); one that cannot be
/// stays as written. A later file overrides an earlier one.
pub fn injected_env(
    paths: &[PathBuf],
    read: &dyn Fn(&Path) -> Option<String>,
    var: &dyn Fn(&str) -> Option<String>,
) -> BTreeMap<String, String> {
    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    for path in paths {
        let Some(text) = read(path) else {
            continue;
        };
        for (key, value) in parse_dotenv(&text) {
            let value = expand_env(&value, &mut |name| {
                Ok(vars.get(name).cloned().or_else(|| var(name)))
            })
            .unwrap_or(value);
            vars.insert(key, value);
        }
    }
    vars
}

/// The `KEY=value` pairs of the dotenv text `text`, in file order, as
/// yarn's dotenv parser reads them: an optional `export ` prefix, `=` or
/// `: ` between key and value, a value in single, double or back quotes
/// (which may span lines; a double-quoted one turns `\n` and `\r` into
/// line breaks), or else unquoted up to a `#` comment and trimmed.
pub fn parse_dotenv(text: &str) -> Vec<(String, String)> {
    static LINE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r#"(?m)^\s*(?:export\s+)?([A-Za-z0-9_.-]+)(?:\s*=\s*?|:\s+?)(\s*'(?:\\'|[^'])*'|\s*"(?:\\"|[^"])*"|\s*`(?:\\`|[^`])*`|[^#\r\n]+)?\s*(?:#.*)?$"#,
        )
        .expect("the dotenv line pattern compiles")
    });
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    LINE.captures_iter(&text)
        .map(|caps| {
            let mut value = caps.get(2).map_or("", |m| m.as_str()).trim().to_string();
            let quote = value.chars().next();
            if let Some(q) = quote.filter(|q| matches!(q, '\'' | '"' | '`')) {
                if value.len() >= 2 && value.ends_with(q) {
                    value = value[1..value.len() - 1].to_string();
                }
                if q == '"' {
                    value = value.replace("\\n", "\n").replace("\\r", "\r");
                }
            }
            (caps[1].to_string(), value)
        })
        .collect()
}

/// The column-0 `key: value` line scan [`raw_setting`] falls back to: a
/// quoted value ends at its closing quote, and a plain value ends before
/// a whitespace-separated `#` comment (#370).
fn line_scan(rc: &str, key: &str) -> Option<String> {
    rc.lines().find_map(|line| {
        let rest = line.strip_prefix(key)?.strip_prefix(':')?.trim();
        if let Some(quote) = rest.chars().next().filter(|c| matches!(c, '\'' | '"')) {
            if let Some(end) = rest[1..].find(quote) {
                return Some(rest[1..1 + end].to_string());
            }
        }
        let value = rest
            .char_indices()
            .find(|&(i, c)| c == '#' && rest[..i].ends_with([' ', '\t']))
            .map_or(rest, |(i, _)| &rest[..i]);
        Some(value.trim_end().trim_matches(['\'', '"']).to_string())
    })
}

/// Yarn's `replaceEnvVariables` over `value`: each `${NAME}`,
/// `${NAME-fallback}` and `${NAME:-fallback}` (`NAME` of ASCII letters,
/// digits and `_`) is replaced by what `lookup` gives for `NAME` (`None`:
/// unset), by the fallback, or is an `Err` naming the unset variable.
/// `lookup` may itself refuse a variable with an `Err`. Text that is not
/// such a reference stays as written.
pub fn expand_env(
    value: &str,
    lookup: &mut dyn FnMut(&str) -> Result<Option<String>, String>,
) -> Result<String, String> {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(at) = rest.find("${") {
        out.push_str(&rest[..at]);
        let body = &rest[at + 2..];
        let name_len = body
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(body.len());
        let name = &body[..name_len];
        let mut tail = &body[name_len..];
        let colon = tail.starts_with(':');
        if colon {
            tail = &tail[1..];
        }
        let fallback = match tail.strip_prefix('-') {
            Some(after) => match after.find('}') {
                Some(close) => {
                    tail = &after[close..];
                    Some(&after[..close])
                }
                None => None,
            },
            None => None,
        };
        let Some(after) = tail.strip_prefix('}').filter(|_| !name.is_empty()) else {
            // Not a reference yarn recognizes: kept literally.
            out.push_str("${");
            rest = body;
            continue;
        };
        let expanded = match (lookup(name)?, fallback) {
            (Some(v), _) if !v.is_empty() => v,
            (Some(v), _) if !colon => v,
            (_, Some(fallback)) => fallback.to_string(),
            (_, None) => return Err(format!("the environment variable {name} is not set")),
        };
        out.push_str(&expanded);
        rest = after;
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            vars.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        }
    }

    fn value(rc: &str, key: &str, vars: &[(&str, &str)]) -> Option<Option<String>> {
        setting(rc, key, &env(vars)).map(|s| s.value)
    }

    /// #1611: dotenv text as yarn's parser reads it.
    #[test]
    fn dotenv_reads_like_yarn() {
        let text = "# comment\r\nA=1\nexport B = two words # note\n\
                    C='single # kept'\nD=\"line\\nbreak\"\nE=`back`\nF=\nG: colon\n\
                    H=\"multi\nline\"\nnot a pair\nI.J-K=x\n";
        let got: Vec<(String, String)> = parse_dotenv(text);
        let want: Vec<(&str, &str)> = vec![
            ("A", "1"),
            ("B", "two words"),
            ("C", "single # kept"),
            ("D", "line\nbreak"),
            ("E", "back"),
            ("F", ""),
            ("G", "colon"),
            ("H", "multi\nline"),
            ("I.J-K", "x"),
        ];
        let got: Vec<(&str, &str)> = got.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        assert_eq!(got, want);
    }

    /// #1611: `injectEnvironmentFiles` as a sequence, a flow list, a comma
    /// string or emptied; another key's list is not it.
    #[test]
    fn list_settings_read_like_yarn() {
        let key = "injectEnvironmentFiles";
        let list = |items: &[&str]| Some(items.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(
            raw_list_setting("injectEnvironmentFiles: [a, \"b?\"]\n", key),
            list(&["a", "b?"])
        );
        assert_eq!(
            raw_list_setting("x: [z]\ninjectEnvironmentFiles:\n  - a\n  - b\ny: 1\n", key),
            list(&["a", "b"])
        );
        assert_eq!(
            raw_list_setting("injectEnvironmentFiles: a, b\n", key),
            list(&["a", "b"])
        );
        assert_eq!(
            raw_list_setting("injectEnvironmentFiles: []\n", key),
            list(&[])
        );
        assert_eq!(
            raw_list_setting("x: [a]\nn:\n  injectEnvironmentFiles: [b]\n", key),
            None
        );
        assert_eq!(
            raw_list_setting(
                "injectEnvironmentFiles: [a]\ninjectEnvironmentFiles: [b]\n",
                key
            ),
            list(&["b"])
        );
    }

    /// #1611: the default list, an rc list against its folder, the
    /// environment's list against the start folder, `?` and `${…}`.
    #[test]
    fn env_file_paths_follow_precedence() {
        let start = Path::new("/p/app");
        let rc_dir = Path::new("/p");
        let none = |_: &str| None;
        assert_eq!(
            env_file_paths(None, &[], start, &none),
            vec![start.join(".env.yarn")]
        );
        let rcs = [(rc_dir, "injectEnvironmentFiles: [\"${D:-env}/x\", y?]\n")];
        assert_eq!(
            env_file_paths(None, &rcs, start, &none),
            vec![rc_dir.join("env/x"), rc_dir.join("y")]
        );
        assert_eq!(
            env_file_paths(Some("a, b?"), &rcs, start, &none),
            vec![start.join("a"), start.join("b")]
        );
        // An entry yarn cannot expand is skipped.
        let rcs = [(rc_dir, "injectEnvironmentFiles: [\"${UNSET}\", z]\n")];
        assert_eq!(
            env_file_paths(None, &rcs, start, &none),
            vec![rc_dir.join("z")]
        );
    }

    /// #1611: yarn expands a dotenv value's `${…}` against the variables
    /// injected so far, then the environment; a later file wins.
    #[test]
    fn injected_values_expand_like_yarn() {
        let files = [
            ("/a", "A=node-modules\nL=${A}\nM=${CI:-pnp}\nN=${UNSET}\n"),
            ("/b", "B=${L}-x\n"),
        ];
        let read = |p: &Path| {
            files
                .iter()
                .find(|(f, _)| Path::new(f) == p)
                .map(|(_, t)| t.to_string())
        };
        let paths = [
            PathBuf::from("/a"),
            PathBuf::from("/missing"),
            PathBuf::from("/b"),
        ];
        let vars = injected_env(&paths, &read, &|n| (n == "CI").then(|| "pnpm".to_string()));
        let get = |k: &str| vars.get(k).map(String::as_str);
        assert_eq!(get("L"), Some("node-modules"));
        assert_eq!(get("M"), Some("pnpm"));
        assert_eq!(get("N"), Some("${UNSET}"));
        assert_eq!(get("B"), Some("node-modules-x"));
    }

    /// #1611: a list setting in a file yarn refuses is not read.
    #[test]
    fn list_settings_need_a_file_yarn_reads() {
        let key = "injectEnvironmentFiles";
        assert_eq!(
            raw_list_setting("- injectEnvironmentFiles\n- [a]\n", key),
            None
        );
        assert_eq!(
            raw_list_setting(
                "injectEnvironmentFiles: [a]\n---\ninjectEnvironmentFiles: []\n",
                key
            ),
            None
        );
        assert_eq!(
            raw_list_setting("\u{feff}\u{feff}injectEnvironmentFiles: [a]\n", key),
            None
        );
        assert_eq!(
            raw_list_setting("injectEnvironmentFiles:\n  a: b\n", key),
            None
        );
    }

    /// The #1100 shapes: yarn expands `${…}` in the value it uses.
    #[test]
    fn references_expand_like_yarn() {
        let pnp = Some(Some("pnp".to_string()));
        assert_eq!(value("nodeLinker: \"${L:-pnp}\"\n", "nodeLinker", &[]), pnp);
        assert_eq!(
            value("nodeLinker: \"${L}\"\n", "nodeLinker", &[("L", "pnp")]),
            pnp
        );
        assert_eq!(
            value(
                "nodeLinker: \"${L:-node-modules}\"\n",
                "nodeLinker",
                &[("L", "pnp")]
            ),
            pnp
        );
        assert_eq!(
            value("compressionLevel: \"${CL:-0}\"\n", "compressionLevel", &[]),
            Some(Some("0".to_string()))
        );
        // `-` without `:` keeps an empty set value; `:-` replaces it.
        assert_eq!(
            value("a: x${E-d}y\n", "a", &[("E", "")]),
            Some(Some("xy".to_string()))
        );
        assert_eq!(
            value("a: x${E:-d}y\n", "a", &[("E", "")]),
            Some(Some("xdy".to_string()))
        );
        assert_eq!(
            value("a: ${E}\n", "a", &[("E", "")]),
            Some(Some(String::new()))
        );
        // Unset with no fallback: yarn refuses to run.
        assert_eq!(value("a: ${NOPE}\n", "a", &[]), Some(None));
        assert_eq!(value("a: ${NOPE:}\n", "a", &[]), Some(None));
        // Not a reference: literal.
        assert_eq!(
            value("a: \"${} ${-x} $X ${A B}\"\n", "a", &[]),
            Some(Some("${} ${-x} $X ${A B}".to_string()))
        );
        // The raw text never carries an expanded value.
        let s = setting("a: \"${T}\"\n", "a", &env(&[("T", "secret")])).unwrap();
        assert_eq!(
            (s.raw.as_str(), s.value.as_deref()),
            ("${T}", Some("secret"))
        );
    }

    /// The #1100 fail-closed rows: yarn reads these as `node-modules`.
    #[test]
    fn yaml_shapes_read_like_yarn() {
        for rc in [
            "\"nodeLinker\": node-modules\n",
            "'nodeLinker': node-modules\n",
            "nodeLinker:\n  node-modules\n",
            "{nodeLinker: node-modules}\n",
            "{\"nodeLinker\": \"node-modules\", compressionLevel: 0}\n",
            "nodeLinker: pnp\nnodeLinker: node-modules\n",
            "\u{feff}nodeLinker: node-modules # comment\r\n",
            "---\nnodeLinker: node-modules\n...\n",
        ] {
            assert_eq!(
                raw_setting(rc, "nodeLinker").as_deref(),
                Some("node-modules"),
                "{rc:?}"
            );
        }
    }

    #[test]
    fn non_scalars_and_other_levels_are_not_settings() {
        let rc = "npmScopes:\n  nodeLinker: pnp\nlist:\n  - nodeLinker\npackageExtensions: {nodeLinker: x}\n";
        assert_eq!(raw_setting(rc, "nodeLinker"), None);
        assert_eq!(raw_setting(rc, "npmScopes"), None);
        assert_eq!(raw_setting("", "nodeLinker"), None);
        assert_eq!(raw_setting("# only a comment\n", "nodeLinker"), None);
        assert_eq!(raw_setting("- a\n- b\n", "nodeLinker"), None);
        // A root list is not settings, even one that pairs up as a key and
        // a value (yarn refuses the file).
        assert_eq!(
            raw_setting("- nodeLinker\n- node-modules\n", "nodeLinker"),
            None
        );
        assert_eq!(
            raw_setting("[nodeLinker, node-modules]\n", "nodeLinker"),
            None
        );
        let rc = "a: &x pnp\nnodeLinker: *x\nb: 1\n";
        assert_eq!(raw_setting(rc, "nodeLinker"), None);
        assert_eq!(raw_setting(rc, "b").as_deref(), Some("1"));
    }

    /// A file that is not one YAML document still has its column-0
    /// settings read (fail closed on the knobs that refuse).
    #[test]
    fn an_unparseable_file_falls_back_to_the_line_scan() {
        assert_eq!(
            raw_setting("compressionLevel: '0'# no gap\n", "compressionLevel").as_deref(),
            Some("0")
        );
        assert_eq!(
            raw_setting("a: [\ncompressionLevel: 9\n", "compressionLevel").as_deref(),
            Some("9")
        );
    }
}
