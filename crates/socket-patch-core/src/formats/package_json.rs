//! The `workspaces` field of an npm-family `package.json`, read one way
//! for every caller (#1900).
//!
//! The field takes two shapes: the array form (npm, yarn, Bun) and the
//! object form whose `packages` array holds the patterns (yarn classic's
//! `nohoist` shape, Bun's catalogs shape). What the package managers do
//! with anything else was probed on npm 10.9, yarn 1.22.22 and Bun 1.4.4:
//!
//! | `workspaces`              | npm    | yarn 1        | Bun    |
//! |---------------------------|--------|---------------|--------|
//! | `["a", 1]`                | fails  | fails         | fails  |
//! | `null`                    | fails  | no workspaces | fails  |
//! | `"a"`                     | fails  | no workspaces | fails  |
//! | `{"packages": "a"}`       | fails  | no workspaces | fails  |
//! | `{"nohoist": []}`         | fails  | no workspaces | no workspaces |
//!
//! A list with a non-string item fails every install, so it is
//! [`Workspaces::Malformed`], as are the other shapes npm and Bun refuse
//! (yarn 1 installs those as if no field were set). The object form
//! without `packages` installs under the two package managers that write
//! it, so it declares no patterns.
//!
//! Readers that only widen (a governing-root refusal, an extra crawl
//! root, a warning, a patch search) take a malformed field's string items
//! through [`Workspaces::into_listed`]. A reader that must name an exact
//! member set (the Bun member walk) treats a malformed field as
//! unreadable.

use serde_json::Value;

/// A `package.json` parsed the way Bun reads it: a leading BOM is skipped,
/// and when the text is not strict JSON, the comments and trailing commas
/// Bun accepts are removed first ([`strip_jsonc`]). npm, yarn, pnpm and vlt
/// refuse such a file outright, so this is for readers that know Bun is the
/// installer (or that only widen): reading it is what keeps a Bun
/// workspace root from looking like no workspace at all. `None` when Bun
/// could not parse the text either.
pub(crate) fn parse(text: &str) -> Option<Value> {
    let text = super::text::strip_bom(text);
    serde_json::from_str(text)
        .or_else(|_| serde_json::from_str(&strip_jsonc(text)))
        .ok()
}

/// `text` with the JSONC Bun accepts in a `package.json` removed: `//` and
/// `/* */` comments and a comma before a closing `}` or `]`, all outside
/// strings. Everything else, strings included, is kept byte for byte.
pub(crate) fn strip_jsonc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if c == '\\' {
                if let Some(escaped) = chars.next() {
                    out.push(escaped);
                }
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => {
                while chars.peek().is_some_and(|&n| n != '\n') {
                    chars.next();
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut prev = '\0';
                for n in chars.by_ref() {
                    if prev == '*' && n == '/' {
                        break;
                    }
                    prev = n;
                }
            }
            '}' | ']' => {
                let kept = out.trim_end_matches(char::is_whitespace).len();
                if out[..kept].ends_with(',') {
                    out.remove(kept - 1);
                }
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// What a `package.json` `workspaces` field declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Workspaces {
    /// No field, or the object form without `packages`.
    None,
    /// The patterns of a well-formed field, in order (possibly empty).
    /// A leading `!` is kept: each caller applies negations the way its
    /// package manager does.
    Patterns(Vec<String>),
    /// A field the package managers refuse to install from (see the
    /// module table), with the string items it does hold.
    Malformed(Vec<String>),
}

impl Workspaces {
    /// The field of a parsed `package.json`.
    pub(crate) fn of(manifest: &Value) -> Self {
        let list = match manifest.get("workspaces") {
            None => return Workspaces::None,
            Some(Value::Array(list)) => list,
            Some(Value::Object(map)) => match map.get("packages") {
                None => return Workspaces::None,
                Some(Value::Array(list)) => list,
                Some(_) => return Workspaces::Malformed(Vec::new()),
            },
            Some(_) => return Workspaces::Malformed(Vec::new()),
        };
        let strings: Vec<String> = list
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        if strings.len() == list.len() {
            Workspaces::Patterns(strings)
        } else {
            Workspaces::Malformed(strings)
        }
    }

    /// The field of a `package.json` text (a leading BOM is ignored);
    /// `None` when the text is not JSON. Strict, as npm, yarn, pnpm and
    /// vlt read it: a manifest with comments is one they cannot install
    /// from, so it names no workspace of theirs.
    pub(crate) fn parse(package_json: &str) -> Option<Self> {
        serde_json::from_str(super::text::strip_bom(package_json))
            .ok()
            .map(|doc| Self::of(&doc))
    }

    /// [`Self::parse`] as Bun reads the manifest ([`parse`]): comments and
    /// trailing commas allowed. For a root Bun installs, and for readers
    /// that only widen.
    pub(crate) fn parse_as_bun(package_json: &str) -> Option<Self> {
        parse(package_json).map(|doc| Self::of(&doc))
    }

    /// The patterns a widening reader takes: every string item of a
    /// declared field, well-formed or not; `None` when no field is
    /// declared. A refusal, an extra crawl root or a warning that reads a
    /// malformed root's patterns errs on the side the package managers'
    /// failure cannot make unsafe.
    pub(crate) fn into_listed(self) -> Option<Vec<String>> {
        match self {
            Workspaces::None => None,
            Workspaces::Patterns(list) | Workspaces::Malformed(list) => Some(list),
        }
    }

    /// [`Self::parse`] then [`Self::into_listed`]: the patterns a widening
    /// reader takes from a `package.json` text.
    pub(crate) fn listed_patterns(package_json: &str) -> Option<Vec<String>> {
        Self::parse(package_json)?.into_listed()
    }

    /// [`Self::listed_patterns`] as Bun reads the manifest
    /// ([`Self::parse_as_bun`]).
    pub(crate) fn listed_patterns_as_bun(package_json: &str) -> Option<Vec<String>> {
        Self::parse_as_bun(package_json)?.into_listed()
    }

    /// Whether the field names at least one pattern ([`Self::into_listed`]
    /// non-empty).
    pub(crate) fn lists_any(&self) -> bool {
        matches!(
            self,
            Workspaces::Patterns(list) | Workspaces::Malformed(list) if !list.is_empty()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// Bun installs from a `package.json` with comments and trailing
    /// commas (measured on Bun 1.1.45 to 1.4.4), so its workspace root must
    /// read as one: a strict reader saw no workspace, which let a member's
    /// stray lock be attested and left members in pruned directories
    /// uncrawled.
    #[test]
    fn reads_the_comments_and_trailing_commas_bun_accepts() {
        let jsonc = "{\n  // workspace root\n  \"name\": \"mono\", /* private */\n  \
                     \"workspaces\": [\"packages/*\", \"vendor/lib\",],\n}\n";
        assert!(serde_json::from_str::<Value>(jsonc).is_err());
        assert_eq!(
            Workspaces::listed_patterns_as_bun(jsonc),
            Some(strings(&["packages/*", "vendor/lib"]))
        );
        assert_eq!(parse(jsonc).unwrap()["name"], "mono");
        // npm, yarn, pnpm and vlt cannot install from it: no workspace of
        // theirs.
        assert_eq!(Workspaces::listed_patterns(jsonc), None);
        assert_eq!(Workspaces::parse(jsonc), None);
        // The object form, behind a BOM.
        let object = "\u{feff}{\"workspaces\": {\"packages\": [\"a\",], }, }";
        assert_eq!(
            Workspaces::listed_patterns_as_bun(object),
            Some(strings(&["a"]))
        );
        // Comment markers and commas inside strings are content.
        let strings_kept = r#"{"name": "a//b /* c */", "workspaces": ["x,]", "y,}"],}"#;
        assert_eq!(parse(strings_kept).unwrap()["name"], "a//b /* c */");
        assert_eq!(
            Workspaces::listed_patterns_as_bun(strings_kept),
            Some(strings(&["x,]", "y,}"]))
        );
        // Strict JSON reads the same either way.
        let plain = r#"{"workspaces": ["a/*"]}"#;
        assert_eq!(
            Workspaces::listed_patterns_as_bun(plain),
            Workspaces::listed_patterns(plain)
        );
        // Still not JSON: unreadable, as before.
        for broken in ["{\"workspaces\": [}", "{\"workspaces\": [\"a\"]", ""] {
            assert_eq!(Workspaces::parse_as_bun(broken), None, "{broken:?}");
        }
    }

    #[test]
    fn classifies_every_shape() {
        let cases: &[(&str, Workspaces)] = &[
            (r#"{"name":"x"}"#, Workspaces::None),
            (r#"{"workspaces":{"nohoist":["**"]}}"#, Workspaces::None),
            (r#"{"workspaces":[]}"#, Workspaces::Patterns(Vec::new())),
            (
                r#"{"workspaces":["a/*","!a/skip","b"]}"#,
                Workspaces::Patterns(strings(&["a/*", "!a/skip", "b"])),
            ),
            (
                r#"{"workspaces":{"packages":["a/*"],"nohoist":["**"]}}"#,
                Workspaces::Patterns(strings(&["a/*"])),
            ),
            (
                r#"{"workspaces":["a",1]}"#,
                Workspaces::Malformed(strings(&["a"])),
            ),
            (
                r#"{"workspaces":{"packages":[null,"b"]}}"#,
                Workspaces::Malformed(strings(&["b"])),
            ),
            (r#"{"workspaces":null}"#, Workspaces::Malformed(Vec::new())),
            (r#"{"workspaces":"a"}"#, Workspaces::Malformed(Vec::new())),
            (
                r#"{"workspaces":{"packages":"a"}}"#,
                Workspaces::Malformed(Vec::new()),
            ),
        ];
        for (text, want) in cases {
            assert_eq!(Workspaces::parse(text).as_ref(), Some(want), "{text}");
        }
    }

    #[test]
    fn parse_ignores_a_bom_and_rejects_non_json() {
        assert_eq!(
            Workspaces::parse("\u{feff}{\"workspaces\":[\"a\"]}"),
            Some(Workspaces::Patterns(strings(&["a"])))
        );
        assert_eq!(Workspaces::parse("not json"), None);
    }

    #[test]
    fn widening_readers_keep_a_malformed_fields_strings() {
        assert_eq!(Workspaces::None.into_listed(), None);
        assert_eq!(
            Workspaces::Malformed(strings(&["a"])).into_listed(),
            Some(strings(&["a"]))
        );
        assert!(Workspaces::Malformed(strings(&["a"])).lists_any());
        assert!(!Workspaces::Malformed(Vec::new()).lists_any());
        assert!(!Workspaces::Patterns(Vec::new()).lists_any());
        assert!(!Workspaces::None.lists_any());
    }
}
