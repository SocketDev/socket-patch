//! Yarn classic's `.yarnrc`, read the way yarn 1.22 reads the whole file
//! (`lockfile/parse.js`): first with the lockfile grammar, and when that
//! fails anywhere in the file, as YAML (`safeLoad`, FAILSAFE schema). A
//! file neither grammar reads makes yarn exit with an error, so it sets
//! nothing here.
//!
//! Every `.yarnrc` reader goes through [`settings`] or [`scalar`], so the npm
//! crawler's `--modules-folder` read and the hosted redirect's
//! `global-folder` and `yarn-offline-mirror` reads cannot disagree on a
//! file (#1901).

use std::collections::HashMap;

use serde_saphyr::granit_parser::{Event, Options, Parser};

use crate::formats::text::strip_bom;

/// A top-level `.yarnrc` value yarn hands to its config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RcScalar {
    /// A string: a double-quoted JSON string or a bare word, or any YAML
    /// scalar (the FAILSAFE schema types nothing else).
    Str(String),
    /// A lockfile-grammar `true` / `false`.
    Bool(bool),
    /// A lockfile-grammar run of digits, as written.
    Num(String),
}

/// The top-level `key_name` value of a `.yarnrc` as yarn 1 reads the file
/// (see the module docs). `None` when the key is unset, holds a nested
/// block, or yarn can't read the file.
pub fn scalar(text: &str, key_name: &str) -> Option<RcScalar> {
    settings(text)?.remove(key_name)
}

/// Every top-level scalar setting of a `.yarnrc` (see [`scalar`]), for a
/// caller that reads several keys from one file. `None` when yarn can't
/// read the file.
pub fn settings(text: &str) -> Option<HashMap<String, RcScalar>> {
    top_level(strip_bom(text))
}

/// Take `key_name`'s string value out of [`settings`]. A boolean or
/// number is not a path or name yarn can use, so it is `None` too.
pub fn take_str(settings: &mut HashMap<String, RcScalar>, key_name: &str) -> Option<String> {
    match settings.remove(key_name)? {
        RcScalar::Str(value) => Some(value),
        RcScalar::Bool(_) | RcScalar::Num(_) => None,
    }
}

/// Every top-level scalar setting, or `None` when neither grammar reads
/// the file.
fn top_level(text: &str) -> Option<HashMap<String, RcScalar>> {
    match lockfile_grammar(text) {
        Some(found) => Some(found),
        None => yaml_fallback(text),
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Newline,
    Comment,
    Indent(usize),
    Str(String),
    Num(String),
    Bool(bool),
    Colon,
    Comma,
    Invalid,
    Eof,
}

/// yarn 1's lockfile tokenizer (`tokenise` in `lockfile/parse.js`).
fn tokenize(mut input: &str) -> Vec<Token> {
    let mut out = Vec::new();
    let mut last_newline = false;
    while !input.is_empty() {
        let bytes = input.as_bytes();
        let (token, chop) = match bytes[0] {
            b'\n' | b'\r' => {
                let chop = if bytes.get(1) == Some(&b'\n') { 2 } else { 1 };
                (Some(Token::Newline), chop)
            }
            // A comment runs to the next `\n`: a lone `\r` doesn't end it.
            b'#' => (
                Some(Token::Comment),
                input.find('\n').unwrap_or(input.len()),
            ),
            b' ' if last_newline => {
                let size = bytes.iter().take_while(|b| **b == b' ').count();
                if size % 2 == 1 {
                    // yarn throws "Invalid number of spaces".
                    out.push(Token::Invalid);
                    break;
                }
                (Some(Token::Indent(size / 2)), size)
            }
            b' ' => (None, 1),
            b'"' => {
                let mut end = input.len();
                for i in 1..bytes.len() {
                    let escaped = bytes[i - 1] == b'\\' && (i < 2 || bytes[i - 2] != b'\\');
                    if bytes[i] == b'"' && !escaped {
                        end = i + 1;
                        break;
                    }
                }
                let token = serde_json::from_str::<String>(&input[..end])
                    .map(Token::Str)
                    .unwrap_or(Token::Invalid);
                (Some(token), end)
            }
            b'0'..=b'9' => {
                let end = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
                (Some(Token::Num(input[..end].to_string())), end)
            }
            _ if input.starts_with("true") => (Some(Token::Bool(true)), 4),
            _ if input.starts_with("false") => (Some(Token::Bool(false)), 5),
            b':' => (Some(Token::Colon), 1),
            b',' => (Some(Token::Comma), 1),
            c if c.is_ascii_alphabetic() || matches!(c, b'/' | b'.' | b'-') => {
                let end = input
                    .find([':', ' ', '\n', '\r', ','])
                    .unwrap_or(input.len());
                (Some(Token::Str(input[..end].to_string())), end)
            }
            _ => (Some(Token::Invalid), 0),
        };
        if chop == 0 {
            out.push(Token::Invalid);
            break;
        }
        out.extend(token);
        // yarn starts an indent only after `\n` or `\r\n`, not a lone `\r`.
        last_newline = input.starts_with('\n') || input.starts_with("\r\n");
        input = &input[chop..];
    }
    out.push(Token::Eof);
    out
}

/// A parsed lockfile-grammar value.
enum Node {
    Scalar(RcScalar),
    Block,
}

/// yarn 1's lockfile parser (`Parser.parse` in `lockfile/parse.js`),
/// keeping the top-level scalars. `None` where yarn throws.
fn lockfile_grammar(text: &str) -> Option<HashMap<String, RcScalar>> {
    let tokens = tokenize(text);
    let mut pos = 0;
    let mut out = HashMap::new();
    parse_block(&tokens, &mut pos, 0, Some(&mut out))?;
    Some(out)
}

/// How deep [`parse_block`] nests before it calls the file unreadable.
/// The `.yarnrc` comes from the (untrusted) project, and the parser
/// recurses once per nested block, so a hostile nesting depth must not
/// overflow the stack. No yarn setting nests more than a level or two.
const MAX_BLOCK_DEPTH: usize = 64;

fn parse_block(
    tokens: &[Token],
    pos: &mut usize,
    indent: usize,
    mut out: Option<&mut HashMap<String, RcScalar>>,
) -> Option<()> {
    if indent > MAX_BLOCK_DEPTH {
        return None;
    }
    let at = |pos: usize| tokens.get(pos).unwrap_or(&Token::Eof);
    loop {
        match at(*pos) {
            Token::Newline => {
                *pos += 1;
                if indent == 0 {
                    continue;
                }
                match at(*pos) {
                    Token::Indent(n) if *n == indent => *pos += 1,
                    _ => break,
                }
            }
            Token::Indent(n) => {
                if *n == indent {
                    *pos += 1;
                } else {
                    break;
                }
            }
            Token::Eof => break,
            Token::Comment => *pos += 1,
            Token::Str(key) => {
                if key.is_empty() {
                    return None;
                }
                let mut keys = vec![key.clone()];
                *pos += 1;
                while *at(*pos) == Token::Comma {
                    *pos += 1;
                    match at(*pos) {
                        Token::Str(key) if !key.is_empty() => keys.push(key.clone()),
                        _ => return None,
                    }
                    *pos += 1;
                }
                let was_colon = *at(*pos) == Token::Colon;
                if was_colon {
                    *pos += 1;
                }
                let node = match at(*pos) {
                    Token::Str(v) => Node::Scalar(RcScalar::Str(v.clone())),
                    Token::Num(v) => Node::Scalar(RcScalar::Num(v.clone())),
                    Token::Bool(v) => Node::Scalar(RcScalar::Bool(*v)),
                    _ if was_colon => {
                        parse_block(tokens, pos, indent + 1, None)?;
                        Node::Block
                    }
                    _ => return None,
                };
                if let Node::Scalar(_) = node {
                    *pos += 1;
                }
                if let Some(out) = out.as_deref_mut() {
                    for key in keys {
                        match &node {
                            Node::Scalar(v) => out.insert(key, v.clone()),
                            Node::Block => out.remove(&key),
                        };
                    }
                }
                if matches!(node, Node::Block)
                    && indent > 0
                    && !matches!(at(*pos), Token::Indent(_))
                {
                    break;
                }
            }
            _ => return None,
        }
    }
    Some(())
}

/// yarn's YAML fallback (js-yaml `safeLoad`, FAILSAFE schema): the
/// file's root mapping, every scalar a string and an empty value null
/// (unset). A root that is not a mapping sets nothing. Where js-yaml
/// throws (a duplicate key, a tag the FAILSAFE schema doesn't know, a
/// syntax error), yarn rethrows the lockfile error: `None`.
fn yaml_fallback(text: &str) -> Option<HashMap<String, RcScalar>> {
    let mut options = Options::default();
    options.emit_comments = false;
    let mut out = HashMap::new();
    let mut keys = std::collections::HashSet::new();
    // Anchored scalars, for an alias to read.
    let mut anchors: HashMap<usize, Option<String>> = HashMap::new();
    let mut depth = 0usize;
    let mut documents = 0usize;
    let mut root_is_mapping = false;
    let mut pending_key: Option<String> = None;
    let mut at_key = true;
    // A root-level key or value: a scalar (`None` for null or a
    // collection).
    let mut root_node = |node: Option<String>,
                         pending_key: &mut Option<String>,
                         at_key: &mut bool,
                         out: &mut HashMap<String, RcScalar>|
     -> Option<()> {
        if *at_key {
            // A non-scalar key is not a setting name; js-yaml would read
            // it as "[object Object]", which no caller asks for.
            let key = node.unwrap_or_default();
            if !keys.insert(key.clone()) {
                return None;
            }
            *pending_key = Some(key);
        } else if let Some(key) = pending_key.take() {
            match node {
                Some(value) => out.insert(key, RcScalar::Str(value)),
                None => out.remove(&key),
            };
        }
        *at_key = !*at_key;
        Some(())
    };
    for event in Parser::new_from_str_with_options(text, options) {
        let (event, span) = event.ok()?;
        match event {
            Event::DocumentStart(..) => {
                documents += 1;
                if documents > 1 {
                    return None;
                }
            }
            Event::MappingStart(_, _, ref tag) | Event::SequenceStart(_, _, ref tag) => {
                let is_map = matches!(event, Event::MappingStart(..));
                let known = if is_map { "map" } else { "seq" };
                if tag
                    .as_ref()
                    .is_some_and(|t| !t.is_yaml_core_schema_tag(known))
                {
                    return None;
                }
                if depth == 0 {
                    root_is_mapping = is_map;
                } else if depth == 1 && root_is_mapping {
                    root_node(None, &mut pending_key, &mut at_key, &mut out)?;
                }
                depth += 1;
            }
            Event::MappingEnd | Event::SequenceEnd => depth = depth.saturating_sub(1),
            Event::Scalar(text, _, anchor, tag) => {
                if tag.is_some_and(|t| !t.is_yaml_core_schema_tag("str")) {
                    return None;
                }
                // An empty node is null; a written `~` is the string `~`.
                let node = (!span.is_empty()).then(|| text.into_owned());
                if anchor != 0 {
                    anchors.insert(anchor, node.clone());
                }
                if depth == 1 && root_is_mapping {
                    root_node(node, &mut pending_key, &mut at_key, &mut out)?;
                }
            }
            Event::Alias(anchor) if depth == 1 && root_is_mapping => {
                let node = anchors.get(&anchor).cloned().flatten();
                root_node(node, &mut pending_key, &mut at_key, &mut out)?;
            }
            _ => {}
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(rc: &str, key: &str) -> Option<String> {
        take_str(&mut settings(rc)?, key)
    }

    fn v(rc: &str) -> Option<String> {
        value(rc, "--modules-folder")
    }

    /// Each `.yarnrc` below was checked against yarn 1.22.22 (where
    /// `yarn install` put the package).
    #[test]
    fn lockfile_grammar_reads_like_yarn() {
        assert_eq!(v("--modules-folder deps\n").as_deref(), Some("deps"));
        assert_eq!(v("--modules-folder \"deps\"\n").as_deref(), Some("deps"));
        assert_eq!(v("--modules-folder deps # c\n").as_deref(), Some("deps"));
        assert_eq!(v("--modules-folder:deps\n").as_deref(), Some("deps"));
        assert_eq!(v("--modules-folder: lib\n").as_deref(), Some("lib"));
        assert_eq!(
            v("\"--modules-folder\" \"./my deps\"\n").as_deref(),
            Some("./my deps")
        );
        assert_eq!(
            v("--modules-folder \"C:\\\\deps\"\n").as_deref(),
            Some("C:\\deps")
        );
        assert_eq!(
            v("--modules-folder: deps\nfoo bar\n").as_deref(),
            Some("deps")
        );
        assert_eq!(
            v("\u{feff}# c\r\n--modules-folder deps\r\n").as_deref(),
            Some("deps")
        );
        assert_eq!(
            v("--modules-folder a\n--modules-folder b\n").as_deref(),
            Some("b")
        );
        // `a, b value` sets both keys.
        let rc = "--modules-folder, --install.modules-folder deps\n";
        assert_eq!(v(rc).as_deref(), Some("deps"));
        assert_eq!(
            value(rc, "--install.modules-folder").as_deref(),
            Some("deps")
        );
    }

    /// When the lockfile grammar fails anywhere, yarn reads the file as
    /// YAML: a single-quoted value or one with spaces counts only in a
    /// `key: value` pair.
    #[test]
    fn yaml_fallback_reads_like_yarn() {
        for (rc, want) in [
            ("--modules-folder: 'deps'\n", "deps"),
            ("--modules-folder:\t'deps'\n", "deps"),
            ("--modules-folder : 'deps'\n", "deps"),
            ("\"--modules-folder\": 'deps'\n", "deps"),
            ("--modules-folder: 'deps' # c\n", "deps"),
            ("--modules-folder: 'it''s'\n", "it's"),
            ("--modules-folder: my deps\n", "my deps"),
            ("--modules-folder: ~/x\n", "~/x"),
        ] {
            assert_eq!(v(rc).as_deref(), Some(want), "{rc:?}");
        }
    }

    /// A file yarn reads as no mapping, or can't read at all (yarn exits
    /// with an error), sets nothing; so does a boolean or number value.
    #[test]
    fn unreadable_file_or_value_is_none() {
        for rc in [
            "",
            "# --modules-folder deps\n",
            "--modules-folder-x deps\n",
            "--modules-folder\n",
            "--modules-folder 'deps'\n",
            "--modules-folder 'my deps'\n",
            "--modules-folder:'deps'\n",
            "\"--modules-folder\" 'deps'\n",
            "\"--modules-folder\":'deps'\n",
            "--modules-folder ~/x\n",
            "--modules-folder C:\\deps\n",
            "--modules-folder C:deps\n",
            "--modules-folder deps, x\n",
            "--modules-folder trueDeps\n",
            "--modules-folder false\n",
            "--modules-folder 0\n",
            "--modules-folder\tdeps\n",
            "--modules-folder \"unterminated\n",
            "--modules-folder deps\nyarn-path ~/y.js\n",
            "--modules-folder deps\n   odd\n",
        ] {
            assert_eq!(v(rc), None, "{rc:?}");
        }
        // An empty value set last overrides an earlier one.
        assert_eq!(
            v("--modules-folder deps\n--modules-folder \"\"\n").as_deref(),
            Some("")
        );
        assert_eq!(
            scalar("--modules-folder false\n", "--modules-folder"),
            Some(RcScalar::Bool(false))
        );
    }

    /// js-yaml's FAILSAFE reading: an empty value is null (unset), a
    /// written `~` or `false` is a string, an alias reads its anchor, and
    /// a duplicate key or an unknown tag fails the whole file.
    #[test]
    fn yaml_fallback_follows_js_yaml_failsafe() {
        // `'x'` forces the YAML fallback in each file.
        assert_eq!(v("a: 'x'\n--modules-folder:\n"), None);
        assert_eq!(v("a: 'x'\n--modules-folder: ~\n").as_deref(), Some("~"));
        assert_eq!(
            scalar("a: 'x'\n--modules-folder: false\n", "--modules-folder"),
            Some(RcScalar::Str("false".into()))
        );
        assert_eq!(
            v("a: &x 'deps'\n--modules-folder: *x\n").as_deref(),
            Some("deps")
        );
        assert_eq!(v("--modules-folder: 'a'\n--modules-folder: 'b'\n"), None);
        assert_eq!(v("--modules-folder: !!int 'deps'\n"), None);
        assert_eq!(
            v("--modules-folder: !!str 'deps'\n").as_deref(),
            Some("deps")
        );
    }

    /// Only `\n` or `\r\n` start an indent, and a comment runs to `\n`.
    #[test]
    fn lone_cr_follows_yarns_tokenizer() {
        assert_eq!(
            v("a b\r  c d\r--modules-folder deps\n").as_deref(),
            Some("deps")
        );
        assert_eq!(v("# c\r--modules-folder deps\r"), None);
        assert_eq!(v("--modules-folder, \"\" deps\n"), None);
    }

    /// Nesting past [`MAX_BLOCK_DEPTH`] makes the file unreadable instead
    /// of recursing without bound (a repository `.yarnrc` is untrusted).
    #[test]
    fn deep_nesting_is_unreadable_not_a_stack_overflow() {
        let nested = |levels: usize| {
            let mut rc = String::from("--modules-folder deps\n");
            for level in 0..levels {
                rc.push_str(&"  ".repeat(level));
                rc.push_str("x:\n");
            }
            rc
        };
        assert_eq!(v(&nested(3)).as_deref(), Some("deps"));
        assert_eq!(lockfile_grammar(&nested(MAX_BLOCK_DEPTH + 10)), None);
        // Run the deep case on a small stack: it must return, not overflow.
        let rc = nested(2_000);
        let found = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || lockfile_grammar(&rc))
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(found, None);
    }

    /// A key holding a nested block is not a scalar setting.
    #[test]
    fn nested_block_is_not_a_scalar() {
        let rc = "--modules-folder deps\n--modules-folder:\n  x y\nother z\n";
        assert_eq!(v(rc), None);
        assert_eq!(value(rc, "other").as_deref(), Some("z"));
    }
}
