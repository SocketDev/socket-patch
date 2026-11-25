//! Keep a Grype config's `vex-documents` list naming a VEX document.
//!
//! Grype reads every document that list names on each scan, so a VEX
//! document listed there suppresses its findings without `--vex`. Grype
//! fails the whole scan when a listed document is missing, and refuses a
//! config that names the key twice, so the editor only changes a file whose
//! shape it can read with certainty and leaves every other byte as it was,
//! each line's own ending and a missing final newline included. Anything
//! else is refused with the reason, for the caller to print the line to add
//! by hand.
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
/// the file does not exist). An item naming the same path in another
/// spelling (`./socket.vex.json`) counts as listed. `Err` says why the file
/// is left alone.
pub fn add_vex_document(text: Option<&str>, entry: &str) -> Result<GrypeConfigEdit, String> {
    let item = format!("  - {}", yaml_item(entry));
    let Some(text) = text else {
        return Ok(GrypeConfigEdit::Write(format!(
            "{VEX_DOCUMENTS_KEY}:\n{item}\n"
        )));
    };
    let mut doc = Lines::parse(text);
    // One block-mapping document, whatever the edit: the check refuses
    // flow and indented roots and a second document.
    let end = block_insert_point(&doc.lines)?;
    match find_key(&doc.lines)? {
        None => {
            doc.insert(end, format!("{VEX_DOCUMENTS_KEY}:"));
            doc.insert(end + 1, item);
        }
        Some(key) => {
            let list = read_list(&doc.lines, key)?;
            if list.items.iter().any(|(_, value)| same_path(value, entry)) {
                return Ok(GrypeConfigEdit::Unchanged);
            }
            if list.empty_flow {
                let line = &doc.lines[key];
                doc.lines[key] = line.replacen("[]", "", 1).trim_end().to_string();
            }
            match list.items.last() {
                // A new item takes the indentation of the last one.
                Some((last, _)) => {
                    let indent: String =
                        doc.lines[*last].chars().take_while(|c| *c == ' ').collect();
                    doc.insert(*last + 1, format!("{indent}- {}", yaml_item(entry)));
                }
                None => doc.insert(key + 1, item),
            }
        }
    }
    Ok(GrypeConfigEdit::Write(doc.join()))
}

/// Remove every item naming `entry` (in any spelling) from the
/// `vex-documents` list of the config `text`. A config without the key, or
/// without the entry, is unchanged. `Err` says why the file could not be
/// read with certainty.
pub fn remove_vex_document(text: &str, entry: &str) -> Result<GrypeConfigEdit, String> {
    let mut doc = Lines::parse(text);
    block_insert_point(&doc.lines)?;
    let Some(key) = find_key(&doc.lines)? else {
        return Ok(GrypeConfigEdit::Unchanged);
    };
    let list = read_list(&doc.lines, key)?;
    let named: Vec<usize> = list
        .items
        .iter()
        .filter(|(_, value)| same_path(value, entry))
        .map(|(line, _)| *line)
        .collect();
    if named.is_empty() {
        return Ok(GrypeConfigEdit::Unchanged);
    }
    for line in named.into_iter().rev() {
        doc.remove(line);
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
    for (i, line) in lines.iter().enumerate().skip(key + 1) {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if line.starts_with('\t') {
            return Err(format!("indents `{VEX_DOCUMENTS_KEY}` with a tab"));
        }
        let depth = line.len() - trimmed.len();
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

/// `value` without a trailing comment. A quote counts only where it opens
/// the value, as in YAML: `team's.json # ci` is the plain `team's.json`.
fn strip_comment(value: &str) -> &str {
    let bytes = value.as_bytes();
    let mut start = 0;
    if let Some(&quote) = bytes.first().filter(|b| matches!(b, b'\'' | b'"')) {
        let mut i = 1;
        while i < bytes.len() {
            if bytes[i] == quote {
                // `''` is an escaped quote inside single quotes.
                if quote == b'\'' && bytes.get(i + 1) == Some(&b'\'') {
                    i += 2;
                    continue;
                }
                if quote == b'"' && bytes[i - 1] == b'\\' {
                    i += 1;
                    continue;
                }
                break;
            }
            i += 1;
        }
        start = (i + 1).min(bytes.len());
    }
    for i in start..bytes.len() {
        if bytes[i] == b'#' && i > 0 && matches!(bytes[i - 1], b' ' | b'\t') {
            return value[..i].trim_end();
        }
    }
    value
}

/// Whether two listed paths name the same file: `./a`, `a` and `b/../a`
/// alike, with `\` read as `/`. A leading `..` of a relative path stays,
/// so `../a` is not `a`.
fn same_path(a: &str, b: &str) -> bool {
    fn normal(path: &str) -> String {
        let path = path.replace('\\', "/");
        let absolute = path.starts_with('/');
        let mut parts: Vec<&str> = Vec::new();
        for segment in path.split('/') {
            match segment {
                "" | "." => {}
                ".." => {
                    if parts.last().is_some_and(|last| *last != "..") {
                        parts.pop();
                    } else if !absolute {
                        // Nothing to climb out of: the path leaves its base.
                        parts.push("..");
                    }
                }
                other => parts.push(other),
            }
        }
        let joined = parts.join("/");
        if path.starts_with('/') {
            format!("/{joined}")
        } else {
            joined
        }
    }
    normal(a) == normal(b)
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

/// A file's lines without their terminators, each with its own, so a
/// mixed-ending file splits at every line and joins back byte for byte.
/// A last line with no terminator keeps having none.
struct Lines {
    lines: Vec<String>,
    ends: Vec<&'static str>,
    /// The terminator new lines get: the file's most common one.
    eol: &'static str,
}

impl Lines {
    fn parse(text: &str) -> Self {
        let mut lines = Vec::new();
        let mut ends = Vec::new();
        for chunk in text.split_inclusive('\n') {
            if let Some(line) = chunk.strip_suffix("\r\n") {
                lines.push(line.to_string());
                ends.push("\r\n");
            } else if let Some(line) = chunk.strip_suffix('\n') {
                lines.push(line.to_string());
                ends.push("\n");
            } else {
                lines.push(chunk.to_string());
                ends.push("");
            }
        }
        let crlf = ends.iter().filter(|end| **end == "\r\n").count();
        let lf = ends.iter().filter(|end| **end == "\n").count();
        let eol = if crlf > lf { "\r\n" } else { "\n" };
        Lines { lines, ends, eol }
    }

    /// Insert `line` before line `at`. After an unterminated last line, the
    /// new line becomes the unterminated one.
    fn insert(&mut self, at: usize, line: String) {
        let end = if at > 0 && at == self.lines.len() && self.ends[at - 1].is_empty() {
            self.ends[at - 1] = self.eol;
            ""
        } else {
            self.eol
        };
        self.lines.insert(at, line);
        self.ends.insert(at, end);
    }

    /// Remove line `at`. A removed unterminated last line leaves the line
    /// before it unterminated.
    fn remove(&mut self, at: usize) {
        if self.ends[at].is_empty() && at > 0 {
            self.ends[at - 1] = "";
        }
        self.lines.remove(at);
        self.ends.remove(at);
    }

    fn join(&self) -> String {
        self.lines
            .iter()
            .zip(&self.ends)
            .map(|(line, end)| format!("{line}{end}"))
            .collect()
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
            "vex-documents:\n  - ./socket.vex.json\n",
            "vex-documents:\n  - out/../socket.vex.json\n",
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
    fn line_endings_and_a_missing_final_newline_are_kept() {
        assert_eq!(
            added(Some("output: table\r\n")),
            "output: table\r\nvex-documents:\r\n  - socket.vex.json\r\n"
        );
        assert_eq!(
            added(Some("output: table")),
            "output: table\nvex-documents:\n  - socket.vex.json"
        );
    }

    #[test]
    fn a_mixed_ending_file_is_read_line_by_line() {
        // The key sits on an LF line of a CRLF file: it is found, not
        // appended a second time.
        let text = "output: table\r\nvex-documents:\n  - other.json\n";
        assert_eq!(
            added(Some(text)),
            "output: table\r\nvex-documents:\n  - other.json\n  - socket.vex.json\n"
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
            "vex-documents:\n  - a.json\n---\nfail-on-severity: high\n",
        ] {
            assert!(
                add_vex_document(Some(text), "socket.vex.json").is_err(),
                "{text}"
            );
            assert!(
                remove_vex_document(text, "socket.vex.json").is_err(),
                "{text}"
            );
        }
    }

    #[test]
    fn a_quote_inside_a_plain_path_is_part_of_it() {
        let text = "vex-documents:\n  - o'brien/socket.vex.json  # ci\n";
        assert_eq!(
            add_vex_document(Some(text), "o'brien/socket.vex.json"),
            Ok(GrypeConfigEdit::Unchanged)
        );
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
    fn a_parent_path_is_not_the_local_document() {
        // `..` with nothing to climb out of leaves the base: the parent's
        // document is another file.
        let text = "vex-documents:\n  - ../socket.vex.json\n";
        assert_eq!(
            add_vex_document(Some(text), "socket.vex.json"),
            Ok(GrypeConfigEdit::Write(
                "vex-documents:\n  - ../socket.vex.json\n  - socket.vex.json\n".to_string()
            ))
        );
        assert_eq!(
            remove_vex_document(text, "socket.vex.json"),
            Ok(GrypeConfigEdit::Unchanged)
        );
        assert!(same_path("a/../../b", "../b"));
        assert!(!same_path("../../b", "../b"));
        assert!(same_path("/../b", "/b"));
    }

    #[test]
    fn remove_drops_every_spelling_of_the_entry() {
        let text = "vex-documents:\n  - other.json\n  - socket.vex.json\n  - ./socket.vex.json\noutput: table\n";
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
    fn removing_an_unterminated_last_item_keeps_the_file_unterminated() {
        assert_eq!(
            remove_vex_document(
                "vex-documents:\n  - a\n  - socket.vex.json",
                "socket.vex.json"
            ),
            Ok(GrypeConfigEdit::Write("vex-documents:\n  - a".to_string()))
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
