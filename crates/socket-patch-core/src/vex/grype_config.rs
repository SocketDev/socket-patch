//! Keep a Grype config's `vex-documents` list naming a VEX document.
//!
//! Grype reads every document that list names on each scan, so a VEX
//! document listed there suppresses its findings without `--vex`. Grype
//! fails the whole scan when a listed document is missing, and refuses a
//! config that names the key twice, so the editor only changes a file whose
//! shape it can read with certainty and leaves every other line byte for
//! byte. Anything else is refused with the reason, for the caller to print
//! the line to add by hand.
//!
//! Pure text in, text out; the caller owns the reads and writes.

use crate::formats::pnpm::workspace::{block_insert_point, top_level_key, yaml_scalar};

/// The key Grype reads VEX documents from.
pub const VEX_DOCUMENTS_KEY: &str = "vex-documents";

/// What an edit does to the config.
#[derive(Debug, PartialEq, Eq)]
pub enum GrypeConfigEdit {
    /// The list already says what was asked; the file stays as it is.
    Unchanged,
    /// The new text of the file.
    Write(String),
}

/// Add `entry` to the `vex-documents` list of the config `text` (`None`:
/// the file does not exist). `Err` says why the file is left alone.
pub fn add_vex_document(text: Option<&str>, entry: &str) -> Result<GrypeConfigEdit, String> {
    let item = format!("  - {}", yaml_item(entry));
    let Some(text) = text else {
        return Ok(GrypeConfigEdit::Write(format!(
            "{VEX_DOCUMENTS_KEY}:\n{item}\n"
        )));
    };
    let mut doc = Lines::parse(text);
    match find_key(&doc.lines)? {
        None => {
            let at = block_insert_point(&doc.lines)?;
            doc.lines
                .splice(at..at, [format!("{VEX_DOCUMENTS_KEY}:"), item]);
        }
        Some(key) => {
            let list = read_list(&doc.lines, key)?;
            if list.items.iter().any(|(_, value)| value == entry) {
                return Ok(GrypeConfigEdit::Unchanged);
            }
            if list.empty_flow {
                let line = &doc.lines[key];
                doc.lines[key] = line.replacen("[]", "", 1).trim_end().to_string();
            }
            let (at, item) = match list.items.last() {
                // A new item takes the indentation of the last one.
                Some((last, _)) => {
                    let indent: String =
                        doc.lines[*last].chars().take_while(|c| *c == ' ').collect();
                    (*last + 1, format!("{indent}- {}", yaml_item(entry)))
                }
                None => (key + 1, item),
            };
            doc.lines.insert(at, item);
        }
    }
    Ok(GrypeConfigEdit::Write(doc.join()))
}

/// Remove `entry` from the `vex-documents` list of the config `text`.
/// A config without the key, or without the entry, is unchanged.
pub fn remove_vex_document(text: &str, entry: &str) -> Result<GrypeConfigEdit, String> {
    let mut doc = Lines::parse(text);
    let Some(key) = find_key(&doc.lines)? else {
        return Ok(GrypeConfigEdit::Unchanged);
    };
    let list = read_list(&doc.lines, key)?;
    let named: Vec<usize> = list
        .items
        .iter()
        .filter(|(_, value)| value == entry)
        .map(|(line, _)| *line)
        .collect();
    if named.is_empty() {
        return Ok(GrypeConfigEdit::Unchanged);
    }
    for line in named.into_iter().rev() {
        doc.lines.remove(line);
    }
    Ok(GrypeConfigEdit::Write(doc.join()))
}

/// The line of the top-level `vex-documents` key. Grype's config loader
/// matches keys without regard to case and refuses a key named twice, so
/// any other spelling, or a second one, leaves the file alone.
fn find_key(lines: &[String]) -> Result<Option<usize>, String> {
    let mut found = None;
    for (i, line) in lines.iter().enumerate() {
        let Some((key, _)) = top_level_key(line) else {
            continue;
        };
        if !key.eq_ignore_ascii_case(VEX_DOCUMENTS_KEY) {
            continue;
        }
        if key != VEX_DOCUMENTS_KEY {
            return Err(format!("spells the key `{key}`"));
        }
        if found.is_some() {
            return Err(format!("names `{VEX_DOCUMENTS_KEY}` more than once"));
        }
        found = Some(i);
    }
    Ok(found)
}

/// The items of the list under the key on line `key`.
struct List {
    /// (line, decoded value) of each item, in order.
    items: Vec<(usize, String)>,
    /// The key's value is an inline `[]`.
    empty_flow: bool,
}

fn read_list(lines: &[String], key: usize) -> Result<List, String> {
    let (_, inline) = top_level_key(&lines[key]).expect("a key line");
    let inline = inline.trim();
    if inline == "[]" {
        return Ok(List {
            items: Vec::new(),
            empty_flow: true,
        });
    }
    if !inline.is_empty() {
        return Err(format!("has `{VEX_DOCUMENTS_KEY}: {inline}` on one line"));
    }
    let mut items = Vec::new();
    let mut indent = None;
    for (i, raw) in lines.iter().enumerate().skip(key + 1) {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let depth = line.len() - trimmed.len();
        if line.starts_with('\t') {
            return Err(format!("indents `{VEX_DOCUMENTS_KEY}` with a tab"));
        }
        let is_item = trimmed == "-" || trimmed.starts_with("- ");
        if !is_item {
            if depth == 0 {
                break; // the next top-level key
            }
            return Err(format!(
                "holds something other than a list of paths under `{VEX_DOCUMENTS_KEY}`"
            ));
        }
        match indent {
            None => indent = Some(depth),
            Some(d) if d == depth => {}
            Some(_) => {
                return Err(format!(
                    "indents the items of `{VEX_DOCUMENTS_KEY}` unevenly"
                ))
            }
        }
        let value = strip_comment(trimmed[1..].trim());
        if value.is_empty() || value.starts_with(['[', '{', '|', '>', '&', '*', '!']) {
            return Err(format!(
                "holds an item of `{VEX_DOCUMENTS_KEY}` that is not a plain path"
            ));
        }
        items.push((i, yaml_scalar(value)));
    }
    Ok(List {
        items,
        empty_flow: false,
    })
}

/// `value` without a trailing ` # comment` outside quotes.
fn strip_comment(value: &str) -> &str {
    let mut quote = None;
    let bytes = value.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b == b'\'' || b == b'"' => quote = Some(b),
            None if b == b'#' && (i == 0 || bytes[i - 1] == b' ') => {
                return value[..i].trim_end();
            }
            None => {}
        }
    }
    value
}

/// `entry` as a list item: plain when YAML reads it back unchanged,
/// single-quoted otherwise.
fn yaml_item(entry: &str) -> String {
    let plain = !entry.is_empty()
        && entry
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '-' | '_'))
        && !entry.starts_with('-');
    if plain {
        entry.to_string()
    } else {
        format!("'{}'", entry.replace('\'', "''"))
    }
}

/// A file's lines without their terminators, with the terminator to join
/// them back with and whether the text ended in one.
struct Lines {
    lines: Vec<String>,
    eol: &'static str,
    trailing: bool,
}

impl Lines {
    fn parse(text: &str) -> Self {
        let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
        let trailing = text.is_empty() || text.ends_with('\n');
        let body = text.strip_suffix('\n').unwrap_or(text);
        let body = if eol == "\r\n" {
            body.strip_suffix('\r').unwrap_or(body)
        } else {
            body
        };
        let lines = if text.is_empty() {
            Vec::new()
        } else {
            body.split(eol).map(str::to_string).collect()
        };
        Lines {
            lines,
            eol,
            trailing,
        }
    }

    fn join(&self) -> String {
        let mut out = self.lines.join(self.eol);
        if self.trailing || !out.is_empty() {
            out.push_str(self.eol);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn added(text: Option<&str>) -> String {
        match add_vex_document(text, "socket.vex.json").unwrap() {
            GrypeConfigEdit::Write(text) => text,
            GrypeConfigEdit::Unchanged => panic!("expected a write"),
        }
    }

    #[test]
    fn a_missing_config_is_created() {
        assert_eq!(added(None), "vex-documents:\n  - socket.vex.json\n");
    }

    #[test]
    fn the_key_is_appended_to_a_config_without_it() {
        let text = "# grype settings\nfail-on-severity: high\n";
        assert_eq!(
            added(Some(text)),
            "# grype settings\nfail-on-severity: high\nvex-documents:\n  - socket.vex.json\n"
        );
    }

    #[test]
    fn the_entry_joins_an_existing_list_with_its_indentation() {
        let text = "vex-documents:\n    - other.json  # ours\noutput: table\n";
        assert_eq!(
            added(Some(text)),
            "vex-documents:\n    - other.json  # ours\n    - socket.vex.json\noutput: table\n"
        );
    }

    #[test]
    fn a_listed_entry_leaves_the_file_alone() {
        for text in [
            "vex-documents:\n  - socket.vex.json\n",
            "vex-documents:\n- 'socket.vex.json' # pinned\n",
            "vex-documents:\n  - \"socket.vex.json\"\n",
        ] {
            assert_eq!(
                add_vex_document(Some(text), "socket.vex.json"),
                Ok(GrypeConfigEdit::Unchanged),
                "{text}"
            );
        }
    }

    #[test]
    fn an_empty_flow_list_becomes_a_block_list() {
        assert_eq!(
            added(Some("vex-documents: []\n")),
            "vex-documents:\n  - socket.vex.json\n"
        );
    }

    #[test]
    fn crlf_and_a_missing_final_newline_are_kept() {
        assert_eq!(
            added(Some("output: table\r\n")),
            "output: table\r\nvex-documents:\r\n  - socket.vex.json\r\n"
        );
        assert_eq!(
            added(Some("output: table")),
            "output: table\nvex-documents:\n  - socket.vex.json\n"
        );
    }

    #[test]
    fn shapes_it_cannot_read_are_refused() {
        for text in [
            "vex-documents: [a.json]\n",
            "vex-documents: a.json\n",
            "Vex-Documents:\n  - a.json\n",
            "vex-documents:\n  - a.json\nvex-documents:\n  - b.json\n",
            "vex-documents:\n  - a.json\n    - b.json\n",
            "vex-documents:\n  key: value\n",
            "{vex-documents: [a.json]}\n",
            "output: table\n---\nfail-on-severity: high\n",
        ] {
            assert!(
                add_vex_document(Some(text), "socket.vex.json").is_err(),
                "{text}"
            );
        }
    }

    #[test]
    fn an_entry_that_needs_quotes_is_quoted() {
        assert_eq!(
            add_vex_document(None, "vex docs/socket.vex.json"),
            Ok(GrypeConfigEdit::Write(
                "vex-documents:\n  - 'vex docs/socket.vex.json'\n".to_string()
            ))
        );
    }

    #[test]
    fn remove_drops_only_the_entry() {
        let text = "vex-documents:\n  - other.json\n  - socket.vex.json\noutput: table\n";
        assert_eq!(
            remove_vex_document(text, "socket.vex.json"),
            Ok(GrypeConfigEdit::Write(
                "vex-documents:\n  - other.json\noutput: table\n".to_string()
            ))
        );
        assert_eq!(
            remove_vex_document("output: table\n", "socket.vex.json"),
            Ok(GrypeConfigEdit::Unchanged)
        );
        assert_eq!(
            remove_vex_document("vex-documents:\n  - other.json\n", "socket.vex.json"),
            Ok(GrypeConfigEdit::Unchanged)
        );
    }

    #[test]
    fn add_then_remove_restores_the_file() {
        let text = "# settings\nfail-on-severity: high\n";
        let GrypeConfigEdit::Write(with) = add_vex_document(Some(text), "socket.vex.json").unwrap()
        else {
            panic!()
        };
        let GrypeConfigEdit::Write(without) =
            remove_vex_document(&with, "socket.vex.json").unwrap()
        else {
            panic!()
        };
        assert_eq!(without, format!("{text}vex-documents:\n"));
    }
}
