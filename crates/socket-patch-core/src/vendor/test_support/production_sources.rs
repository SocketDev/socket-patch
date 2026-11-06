//! A crate's production source text, for the architecture guards that
//! scan it (the BOM-helper guard in `formats::text`, the no-lock-download
//! guard in `vendor::lock_inventory` and its CLI twin).
//!
//! "Production" is every `.rs` file under `src/` except the test-only
//! files (`*tests.rs`, `test_support`), with every test-only item removed:
//! an item behind `#[cfg(test)]` or `#[cfg(all(test, …))]` (a test module,
//! inline or `mod x;`, a test helper, a test `use`), and the whole file
//! when it opens with `#![cfg(test)]`. Items are removed in place, never by
//! truncating at the first `#[cfg(test)]`, so production code after a test
//! item is still scanned. Line endings are normalized to LF, and removed
//! bytes become spaces (newlines kept), so line numbers stay the file's.
//!
//! The scan is lexical, not a parser: it skips comments, string, raw
//! string, byte string and char literals while matching brackets, which is
//! enough for rustfmt-formatted code. `cfg_attr` and a `test` cfg spelled
//! any other way (`any(test, …)` is not test-only) are not recognized.

use std::path::{Path, PathBuf};

/// One production source file.
pub struct ProductionSource {
    /// Path relative to the scanned `src/`, `/`-separated.
    pub rel: String,
    /// The text with test-only items blanked out (see the module docs).
    pub text: String,
}

impl ProductionSource {
    /// [`Self::text`] with comments and literal contents blanked too: what
    /// a scan for identifiers (calls, imports) should read.
    pub fn code(&self) -> String {
        code_only(&self.text)
    }
}

/// Every production `.rs` file under `src`, sorted by path, each read once.
pub fn production_sources(src: &Path) -> Vec<ProductionSource> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(src, &mut files);
    let mut out: Vec<ProductionSource> = files
        .into_iter()
        .filter_map(|path| {
            let rel = path
                .strip_prefix(src)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if rel.ends_with("tests.rs") || rel.contains("test_support") {
                return None;
            }
            // Windows CI checks out with CRLF.
            let text = std::fs::read_to_string(&path)
                .unwrap()
                .replace("\r\n", "\n");
            Some(ProductionSource {
                rel,
                text: strip_test_items(&text),
            })
        })
        .collect();
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Code,
    Comment,
    Literal,
}

/// Classify each byte of `src` as code, comment or literal.
fn classify(src: &str) -> Vec<Kind> {
    let b = src.as_bytes();
    let n = b.len();
    let mut kind = vec![Kind::Code; n];
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0;
    let mark = |kind: &mut Vec<Kind>, from: usize, to: usize, k: Kind| {
        for slot in &mut kind[from..to.min(n)] {
            *slot = k;
        }
    };
    // End (exclusive) of a quoted literal whose opening quote is at `open`.
    let quoted_end = |open: usize, quote: u8| {
        let mut j = open + 1;
        while j < n {
            match b[j] {
                b'\\' => j += 2,
                c if c == quote => return j + 1,
                _ => j += 1,
            }
        }
        n
    };
    while i < n {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if c == b'/' && next == Some(b'/') {
            let end = src[i..].find('\n').map_or(n, |at| i + at);
            mark(&mut kind, i, end, Kind::Comment);
            i = end;
        } else if c == b'/' && next == Some(b'*') {
            let (mut j, mut depth) = (i + 2, 1);
            while j < n && depth > 0 {
                if b[j] == b'/' && b.get(j + 1) == Some(&b'*') {
                    depth += 1;
                    j += 2;
                } else if b[j] == b'*' && b.get(j + 1) == Some(&b'/') {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            mark(&mut kind, i, j, Kind::Comment);
            i = j;
        } else if (c == b'r' || c == b'b') && (i == 0 || !ident(b[i - 1])) {
            // r"…", r#"…"#, b"…", br#"…"#, b'…'.
            let mut j = i;
            if b[j] == b'b' {
                j += 1;
            }
            let raw = b.get(j) == Some(&b'r');
            if raw {
                j += 1;
            }
            let mut hashes = 0;
            while raw && b.get(j) == Some(&b'#') {
                hashes += 1;
                j += 1;
            }
            if b.get(j) == Some(&b'"') {
                let end = if raw {
                    let closing = format!("\"{}", "#".repeat(hashes));
                    src[j + 1..]
                        .find(&closing)
                        .map_or(n, |at| j + 1 + at + closing.len())
                } else {
                    quoted_end(j, b'"')
                };
                mark(&mut kind, i, end, Kind::Literal);
                i = end;
            } else if !raw && c == b'b' && next == Some(b'\'') {
                let end = quoted_end(i + 1, b'\'');
                mark(&mut kind, i, end, Kind::Literal);
                i = end;
            } else {
                i += 1;
            }
        } else if c == b'"' {
            let end = quoted_end(i, b'"');
            mark(&mut kind, i, end, Kind::Literal);
            i = end;
        } else if c == b'\'' {
            // A char literal, or a lifetime / label (`'a`, `'outer:`).
            if next == Some(b'\\') {
                let end = quoted_end(i, b'\'');
                mark(&mut kind, i, end, Kind::Literal);
                i = end;
            } else {
                let width = src[i + 1..].chars().next().map_or(1, char::len_utf8);
                if b.get(i + 1 + width) == Some(&b'\'') {
                    mark(&mut kind, i, i + 2 + width, Kind::Literal);
                    i += 2 + width;
                } else {
                    i += 1;
                }
            }
        } else {
            i += 1;
        }
    }
    kind
}

/// Index of the bracket closing the one at `open`, over code bytes only.
fn matching_close(b: &[u8], kind: &[Kind], open: usize) -> usize {
    let mut depth = 0usize;
    for (j, &c) in b.iter().enumerate().skip(open) {
        if kind[j] != Kind::Code {
            continue;
        }
        match c {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return j;
                }
            }
            _ => {}
        }
    }
    b.len().saturating_sub(1)
}

/// End (exclusive) of the item starting at `start`: its first `;` outside
/// brackets, or its first top-level `{…}` block (plus a `;` right after).
fn item_end(b: &[u8], kind: &[Kind], start: usize) -> usize {
    let mut depth = 0usize;
    let mut j = start;
    while j < b.len() {
        if kind[j] == Kind::Code {
            match b[j] {
                b'(' | b'[' => depth += 1,
                b')' | b']' => depth = depth.saturating_sub(1),
                b';' if depth == 0 => return j + 1,
                b'{' if depth == 0 => {
                    let close = matching_close(b, kind, j);
                    let mut k = close + 1;
                    while k < b.len() && b[k].is_ascii_whitespace() {
                        k += 1;
                    }
                    return if b.get(k) == Some(&b';') {
                        k + 1
                    } else {
                        close + 1
                    };
                }
                _ => {}
            }
        }
        j += 1;
    }
    b.len()
}

/// Whether an attribute's inside (`cfg(test)` of `#[cfg(test)]`) gates its
/// item to test builds.
fn is_test_cfg(inside: &str) -> bool {
    let compact: String = inside.chars().filter(|c| !c.is_whitespace()).collect();
    compact == "cfg(test)" || compact.starts_with("cfg(all(test,")
}

/// `src` with every test-only item blanked (see the module docs).
pub fn strip_test_items(src: &str) -> String {
    let b = src.as_bytes();
    let kind = classify(src);
    let mut out = b.to_vec();
    let blank = |out: &mut [u8], from: usize, to: usize| {
        for byte in &mut out[from..to] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    };
    let mut i = 0;
    while i + 1 < b.len() {
        if kind[i] != Kind::Code || b[i] != b'#' {
            i += 1;
            continue;
        }
        let inner = b[i + 1] == b'!';
        let open = if inner { i + 2 } else { i + 1 };
        if b.get(open) != Some(&b'[') {
            i += 1;
            continue;
        }
        let close = matching_close(b, &kind, open);
        if !is_test_cfg(&src[open + 1..close]) {
            i = close + 1;
            continue;
        }
        if inner {
            // `#![cfg(test)]`: the whole file (module) is test-only.
            return src
                .bytes()
                .map(|c| if c == b'\n' { '\n' } else { ' ' })
                .collect();
        }
        // The item: past whitespace, comments and further attributes.
        let mut j = close + 1;
        loop {
            while j < b.len() && (b[j].is_ascii_whitespace() || kind[j] == Kind::Comment) {
                j += 1;
            }
            if b.get(j) == Some(&b'#') && b.get(j + 1) == Some(&b'[') {
                j = matching_close(b, &kind, j + 1) + 1;
                continue;
            }
            break;
        }
        let end = item_end(b, &kind, j);
        blank(&mut out, i, end);
        i = end;
    }
    // Only ASCII bytes were written, each over a whole removed range whose
    // ends are ASCII, so the text stays UTF-8.
    String::from_utf8(out).expect("blanking keeps UTF-8")
}

/// `src` with comments and literal contents blanked (newlines kept).
pub fn code_only(src: &str) -> String {
    let kind = classify(src);
    let out: Vec<u8> = src
        .bytes()
        .zip(&kind)
        .map(|(c, k)| match k {
            Kind::Code => c,
            _ if c == b'\n' => b'\n',
            _ => b' ',
        })
        .collect();
    // Non-code bytes became ASCII; code bytes are whole chars.
    String::from_utf8(out).unwrap_or_default()
}

/// Every reference to the identifier `name` in `code` (from
/// [`ProductionSource::code`]) other than its own definition (`fn name`):
/// a call by any path, a method call, an import (`use …::name` and
/// `… as alias`), a function value passed along. Each is `(line, the
/// trimmed line)`, 1-based.
pub fn references(code: &str, name: &str) -> Vec<(usize, String)> {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut out = Vec::new();
    for (index, line) in code.lines().enumerate() {
        let mut from = 0;
        while let Some(at) = line[from..].find(name) {
            let start = from + at;
            let end = start + name.len();
            from = end;
            let before = line[..start].chars().next_back();
            let after = line[end..].chars().next();
            if before.is_some_and(ident) || after.is_some_and(ident) {
                continue;
            }
            let prefix = line[..start].trim_end();
            if prefix.ends_with("fn") && !prefix[..prefix.len() - 2].ends_with(ident) {
                continue;
            }
            out.push((index + 1, line.trim().to_string()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_items_are_removed_in_place_not_truncated() {
        let src = "fn a() {}\n#[cfg(test)]\nfn helper() { let s = \"}\"; }\nfn b() { x(); }\n\
                   #[cfg(test)]\nmod tests;\n#[cfg(all(test, unix))]\nuse std::fs::{self, File};\n\
                   #[cfg(test)]\n#[path = \"t.rs\"]\nmod more { fn y() { '}'; } }\nfn c() {}\n";
        let out = strip_test_items(src);
        assert_eq!(out.lines().count(), src.lines().count(), "{out}");
        for kept in ["fn a()", "fn b() { x(); }", "fn c()"] {
            assert!(out.contains(kept), "{kept}: {out}");
        }
        for dropped in ["helper", "mod tests", "File", "more", "fn y"] {
            assert!(!out.contains(dropped), "{dropped}: {out}");
        }
        assert!(strip_test_items("#![cfg(test)]\nfn z() {}\n")
            .trim()
            .is_empty());
        // `any(test, …)` also builds outside tests.
        assert!(
            strip_test_items("#[cfg(any(test, feature = \"x\"))]\nfn k() {}\n").contains("fn k")
        );
    }

    #[test]
    fn literals_and_comments_do_not_confuse_the_scan() {
        let src = "#[cfg(test)]\nfn t() { let r = r#\"{ \"#; let c = '{'; /* { */ // {\n }\nfn p<'a>(x: &'a str) {}\n";
        let out = strip_test_items(src);
        assert!(out.contains("fn p<'a>"), "{out}");
        assert!(!out.contains("fn t"), "{out}");
        let code = code_only("call(\"download(\"); // download(\ndownload(1);\n");
        assert_eq!(
            references(&code, "download"),
            vec![(2, "download(1);".to_string())]
        );
    }

    #[test]
    fn references_find_every_spelling_but_the_definition() {
        let code = "pub(crate) async fn download(u: &str) {}\n\
                    use a::registry_fetch::download as fetch;\n\
                    self.download(&url);\n\
                    x.map(download);\n\
                    redownload(); download_unredacted();\n";
        let lines: Vec<usize> = references(code, "download").iter().map(|r| r.0).collect();
        assert_eq!(lines, vec![2, 3, 4]);
    }
}
