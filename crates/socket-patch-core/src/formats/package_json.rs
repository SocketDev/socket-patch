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
//! [`Workspaces::Malformed`], as are the other shapes npm and Bun refuse.
//! The object form without `packages` installs under the two package
//! managers that write it, so it declares no patterns.

use serde_json::Value;

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
    /// `None` when the text is not JSON.
    pub(crate) fn parse(package_json: &str) -> Option<Self> {
        serde_json::from_str(super::text::strip_bom(package_json))
            .ok()
            .map(|doc| Self::of(&doc))
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
