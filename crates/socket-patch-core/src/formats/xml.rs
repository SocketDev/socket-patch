//! A bounded, dependency-free XML element scanner, shared by every reader
//! of a small XML file the wirings touch: the root `pom.xml`
//! ([`super::maven`]) and Gradle's `verification-metadata.xml`. Comments and
//! CDATA sections are blanked first, keeping byte offsets, so commented-out
//! or character-data markup never reads as an element. Pure: text in,
//! offsets out.

/// One element's byte offsets in the scanned text.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Element {
    /// The `<` of the open tag.
    pub(crate) start: usize,
    /// Just past the open tag's `>`.
    pub(crate) inner_start: usize,
    /// The `<` of the close tag (== `inner_start` for `<x/>`).
    pub(crate) inner_end: usize,
    /// Just past the close tag's `>`.
    pub(crate) end: usize,
}

impl Element {
    pub(crate) fn inner<'t>(&self, text: &'t str) -> &'t str {
        &text[self.inner_start..self.inner_end]
    }

    /// The open tag, `<name …>` (or `<name …/>`).
    pub(crate) fn open_tag<'t>(&self, text: &'t str) -> &'t str {
        &text[self.start..self.inner_start]
    }
}

/// `text` with every `<!-- … -->` comment and `<![CDATA[ … ]]>` section
/// blanked byte-for-byte (offsets are kept), scanned in document order so a
/// comment opener inside CDATA is text and vice versa. A `<repository>` or
/// `<dependency>` written inside CDATA (say, in a `<description>`) is
/// character data to Maven — no repository is configured and the original
/// GAV resolves from Central — so it must never read as wiring. An
/// unterminated comment blanks through EOF, like the vendor backend; an
/// unterminated CDATA section is an error.
pub(crate) fn blank_non_markup(text: &str) -> Result<String, String> {
    const CDATA_OPEN: &str = "<![CDATA[";
    let mut bytes = text.as_bytes().to_vec();
    let mut from = 0;
    loop {
        let comment = text[from..].find("<!--").map(|r| from + r);
        let cdata = text[from..].find(CDATA_OPEN).map(|r| from + r);
        let (start, end) = match (comment, cdata) {
            (None, None) => break,
            (Some(c), d) if d.is_none_or(|d| c < d) => {
                let end = text[c + 4..]
                    .find("-->")
                    .map_or(text.len(), |r| c + 4 + r + 3);
                (c, end)
            }
            (_, d) => {
                let d = d.expect("a CDATA opener comes first");
                let body = d + CDATA_OPEN.len();
                let end = text[body..]
                    .find("]]>")
                    .map(|r| body + r + 3)
                    .ok_or_else(|| "unterminated <![CDATA[ section".to_string())?;
                (d, end)
            }
        };
        bytes[start..end].fill(b' ');
        from = end;
    }
    Ok(String::from_utf8(bytes).expect("blanking whole ASCII-delimited spans keeps UTF-8 valid"))
}

/// `(start, past '>', self-closing)` of every real `<name …>` open tag — the
/// next byte must be a tag boundary, so `<repositories>` is not
/// `<repository>` and `<dependencyManagement>` is not `<dependency>`.
pub(crate) fn open_tags(text: &str, name: &str) -> Result<Vec<(usize, usize, bool)>, String> {
    let needle = format!("<{name}");
    let mut tags = Vec::new();
    let mut from = 0;
    while let Some(rel) = text[from..].find(&needle) {
        let start = from + rel;
        let after = start + needle.len();
        from = after;
        match text[after..].chars().next() {
            Some(c) if c == '>' || c == '/' || c.is_whitespace() => {}
            _ => continue,
        }
        let Some(gt) = text[after..].find('>').map(|r| after + r) else {
            return Err(format!("unterminated <{name}> tag"));
        };
        tags.push((start, gt + 1, text[..gt].ends_with('/')));
        from = gt + 1;
    }
    Ok(tags)
}

/// Every `<name>` element, each closed by the next `</name>` (none of the
/// elements scanned here nest in themselves).
pub(crate) fn elements(text: &str, name: &str) -> Result<Vec<Element>, String> {
    let close = format!("</{name}>");
    let mut out = Vec::new();
    let mut resume = 0;
    for (start, inner_start, self_closing) in open_tags(text, name)? {
        if start < resume {
            continue; // inside the previous element (malformed nesting)
        }
        if self_closing {
            out.push(Element {
                start,
                inner_start,
                inner_end: inner_start,
                end: inner_start,
            });
            continue;
        }
        let Some(inner_end) = text[inner_start..].find(&close).map(|r| inner_start + r) else {
            return Err(format!("unterminated <{name}> element"));
        };
        let end = inner_end + close.len();
        out.push(Element {
            start,
            inner_start,
            inner_end,
            end,
        });
        resume = end;
    }
    Ok(out)
}

/// Trimmed text of the FIRST `<tag>` child in `body`.
pub(crate) fn child_text(body: &str, tag: &str) -> Result<Option<String>, String> {
    Ok(elements(body, tag)?
        .first()
        .map(|e| e.inner(body).trim().to_string()))
}

/// Every `<name>` element inside `parent`'s content, with offsets into
/// `text` (the text `parent` was scanned from).
pub(crate) fn children(text: &str, parent: &Element, name: &str) -> Result<Vec<Element>, String> {
    let base = parent.inner_start;
    Ok(elements(parent.inner(text), name)?
        .into_iter()
        .map(|e| Element {
            start: base + e.start,
            inner_start: base + e.inner_start,
            inner_end: base + e.inner_end,
            end: base + e.end,
        })
        .collect())
}

/// The quoted value of attribute `name` in the open tag `tag`: the first
/// whitespace-preceded `name =` followed by a `"` or `'` quoted value.
pub(crate) fn attr<'t>(tag: &'t str, name: &str) -> Option<&'t str> {
    let mut rest = tag;
    loop {
        let at = rest.find(name)?;
        let before = rest[..at].chars().last();
        let after = rest[at + name.len()..].trim_start();
        rest = &rest[at + name.len()..];
        if !before.is_some_and(char::is_whitespace) {
            continue;
        }
        let Some(after) = after.strip_prefix('=') else {
            continue;
        };
        let after = after.trim_start();
        let quote = after.chars().next()?;
        if quote != '"' && quote != '\'' {
            return None;
        }
        let body = &after[1..];
        return body.find(quote).map(|e| &body[..e]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_and_cdata_are_blanked_in_document_order() {
        let text = "<a><!-- <b/> --><![CDATA[<b/><!--]]><b x='1'/></a>";
        let masked = blank_non_markup(text).unwrap();
        assert_eq!(masked.len(), text.len(), "offsets are kept");
        let found = elements(&masked, "b").unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].open_tag(text), "<b x='1'/>");
        assert!(blank_non_markup("<a><![CDATA[ open").is_err());
        assert_eq!(
            blank_non_markup("<a><!-- open").unwrap(),
            format!("<a>{}", " ".repeat(9)),
            "an unterminated comment blanks through EOF"
        );
    }

    #[test]
    fn elements_respect_tag_boundaries_and_report_damage() {
        let text = "<deps><dependencyManagement/><dependency>x</dependency><dependency/></deps>";
        let found = elements(text, "dependency").unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].inner(text), "x");
        assert_eq!(found[1].inner_start, found[1].end, "self-closing");
        assert!(elements("<a><b>", "b").is_err(), "unterminated element");
        assert!(elements("<a><b x", "b").is_err(), "unterminated tag");
    }

    #[test]
    fn children_are_scanned_inside_the_parent_with_document_offsets() {
        let text = "<c n='0'/><p><c n='1'/><c n='2'>t</c></p><c n='3'/>";
        let parent = elements(text, "p").unwrap().remove(0);
        let kids = children(text, &parent, "c").unwrap();
        let names: Vec<_> = kids.iter().map(|k| attr(k.open_tag(text), "n")).collect();
        assert_eq!(names, [Some("1"), Some("2")]);
        assert_eq!(kids[1].inner(text), "t");
        let empty = elements("<p/>", "p").unwrap().remove(0);
        assert!(children("<p/>", &empty, "c").unwrap().is_empty());
    }

    #[test]
    fn attr_reads_whole_quoted_names_only() {
        for (tag, want) in [
            (r#"<a name="x"/>"#, Some("x")),
            ("<a name = 'x'>", Some("x")),
            (r#"<a filename="no" name="x">"#, Some("x")),
            (r#"<a name-x="no" name="x">"#, Some("x")),
            ("<a name=x>", None),
            (r#"<a value="name=no">"#, None),
            ("<a>", None),
        ] {
            assert_eq!(attr(tag, "name"), want, "{tag}");
        }
    }
}
