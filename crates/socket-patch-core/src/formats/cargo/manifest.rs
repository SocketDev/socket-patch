//! `Cargo.toml`'s `[package]` identity: the ONE reader of a manifest's
//! `name` and `version`.
//!
//! Every caller parses with `toml_edit`, so they agree with cargo on what a
//! manifest says: a UTF-8 BOM, the legacy `[project]` table, dotted keys
//! (`package.name = "…"`) and an inline `package = { … }` all read the
//! same, and a manifest cargo rejects (invalid TOML) reads as nothing.
//!
//! Callers: the cargo crawler (crate identity), VEX product detection (the
//! project purl) and `vendor::cargo_tag` (the version literal it rewrites).

use toml_edit::{Document, Item, Table, TableLike};

/// The `[package]` table of a parsed manifest, else its legacy `[project]`
/// spelling (crates published before manifest normalization ship it
/// verbatim, and cargo still accepts it).
pub(crate) fn package_table(root: &Table) -> Option<&dyn TableLike> {
    ["package", "project"]
        .iter()
        .find_map(|key| root.get(key).and_then(Item::as_table_like))
}

/// The literal `name` and `version` of a `Cargo.toml`'s package table.
///
/// `None` when the text is not valid TOML, has no package table, or either
/// field is missing, empty or not a literal string — notably
/// `version.workspace = true`, whose version this file alone cannot tell.
pub fn package_name_version(text: &str) -> Option<(String, String)> {
    let doc = Document::parse(text).ok()?;
    let package = package_table(doc.as_table())?;
    let field = |key| {
        package
            .get(key)
            .and_then(Item::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    Some((field("name")?, field("version")?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nv(name: &str, version: &str) -> Option<(String, String)> {
        Some((name.to_string(), version.to_string()))
    }

    #[test]
    fn reads_every_spelling_cargo_accepts() {
        let cases = [
            (
                "[package]\nname = \"a\"\nversion = \"1.0.0\"\n",
                nv("a", "1.0.0"),
            ),
            (
                "\u{feff}[package]\nname = \"a\"\nversion = \"1.0.0\"\n",
                nv("a", "1.0.0"),
            ),
            (
                "[project]\nname = \"a\"\nversion = \"1.0.0\"\n",
                nv("a", "1.0.0"),
            ),
            (
                "package.name = \"a\"\npackage.version = \"1.0.0\"\n",
                nv("a", "1.0.0"),
            ),
            (
                "package = { name = \"a\", version = \"1.0.0\" }\n",
                nv("a", "1.0.0"),
            ),
            (
                "[package]\nname = 'a'\nversion = '1.0.0'\n",
                nv("a", "1.0.0"),
            ),
            (
                "[ package ] # c\nname = \"a\" # c\nversion = \"1.0.0\"\n",
                nv("a", "1.0.0"),
            ),
            (
                "[package]\r\nname = \"a\"\r\nversion = \"1.0.0\"\r\n",
                nv("a", "1.0.0"),
            ),
        ];
        for (text, want) in cases {
            assert_eq!(package_name_version(text), want, "{text:?}");
        }
    }

    #[test]
    fn package_wins_over_project() {
        let text = "[package]\nname = \"a\"\nversion = \"1.0.0\"\n\
                    [project]\nname = \"b\"\nversion = \"2.0.0\"\n";
        assert_eq!(package_name_version(text), nv("a", "1.0.0"));
    }

    #[test]
    fn reads_nothing_it_cannot_tell() {
        for text in [
            "[package]\nname = \"a\"\nversion.workspace = true\n",
            "[package]\nname = \"a\"\nversion = { workspace = true }\n",
            "[package]\nname = \"a\"\n",
            "[package]\nversion = \"1.0.0\"\n",
            "[package]\nname = \"\"\nversion = \"1.0.0\"\n",
            "[dependencies]\nname = \"a\"\nversion = \"1.0.0\"\n",
            "[package]\nname = \"a\"\n[dependencies]\nversion = \"1.0.0\"\n",
            // Not TOML: cargo rejects it, so it names no package.
            "[package] junk\nname = \"a\"\nversion = \"1.0.0\"\n",
            "[package]\nname = \"a\"\n[oops\nversion = \"1.0.0\"\n",
        ] {
            assert_eq!(package_name_version(text), None, "{text:?}");
        }
    }
}
