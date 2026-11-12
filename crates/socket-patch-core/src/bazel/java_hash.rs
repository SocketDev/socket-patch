//! Starlark `hash()` and `repr()`: the values rulesets store beside their
//! locks.
//!
//! rules_jvm_external signs `maven_install.json` with `hash(repr(...))`, and
//! rules_js keeps `hash(<file content>)` for every input of an
//! `update_pnpm_lock` hub. The build computes the value again and compares,
//! so a lane that edits such a file must write the number Bazel will
//! compute, or the build fails.
//!
//! Starlark `hash` is Java's `String.hashCode`. What it hashes is decided by
//! how Bazel holds text: it reads every file as ISO-8859-1, so a Starlark
//! string has one char per byte of the file and a UTF-8 `é` is two chars.
//! [`hash_bytes`] is that model. The other reading, `hashCode` over the
//! UTF-16 units of the decoded text, differs for every non-ASCII string and
//! real builds refuted it on Bazel 6.6.0, 7.7.2, 8.8.2 and 9.3.2 (`expected
//! 385063259 and got 832349099`), so it is not implemented: a value written
//! from it would break the build it was meant to keep.

use std::borrow::Cow;

/// `java.lang.String.hashCode()` of the string that has one char per byte
/// of `bytes`: `h = 31 * h + byte`, wrapping at 32 bits, read as signed.
///
/// For a file this is the value of Starlark `hash(rctx.read(file))`, binary
/// files included. For text a ruleset built from such strings (a `repr`),
/// pass its UTF-8 bytes.
pub fn hash_bytes(bytes: &[u8]) -> i32 {
    bytes.iter().fold(0i32, |h, byte| {
        h.wrapping_mul(31).wrapping_add(i32::from(*byte))
    })
}

/// A Starlark value, as far as `repr` needs to know it. It has no float:
/// no hashed lock value is one, and a caller that meets a float refuses
/// instead of guessing how Starlark would print it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Starlark<'a> {
    None,
    Bool(bool),
    /// The decimal digits of an int. Starlark ints are unbounded, so a
    /// lock's own digits are kept instead of a machine integer.
    Int(Cow<'a, str>),
    Str(Cow<'a, str>),
    List(Vec<Starlark<'a>>),
    /// The entries in iteration order: a Starlark dict prints in insertion
    /// order, and the callers hash dicts whose order they have fixed.
    Dict(Vec<(&'a str, Starlark<'a>)>),
}

impl Starlark<'_> {
    /// A 32-bit int, which is what `hash` returns.
    pub fn int(value: i32) -> Self {
        Self::Int(Cow::Owned(value.to_string()))
    }
}

/// Starlark `repr(value)`, as `net.starlark.java.eval.Printer` writes it on
/// every Bazel line from 5.4.1 to 9.3.2: `None`, `True`, decimal ints,
/// double-quoted strings, `[a, b]` and `{"k": v}`.
pub fn repr(value: &Starlark<'_>) -> String {
    let mut out = String::new();
    write_repr(value, &mut out);
    out
}

/// Starlark `hash(repr(value))`.
pub fn hash_repr(value: &Starlark<'_>) -> i32 {
    hash_bytes(repr(value).as_bytes())
}

fn write_repr(value: &Starlark<'_>, out: &mut String) {
    match value {
        Starlark::None => out.push_str("None"),
        Starlark::Bool(true) => out.push_str("True"),
        Starlark::Bool(false) => out.push_str("False"),
        Starlark::Int(digits) => out.push_str(digits),
        Starlark::Str(text) => write_quoted(text, out),
        Starlark::List(items) => {
            out.push('[');
            for (at, item) in items.iter().enumerate() {
                out.push_str(if at == 0 { "" } else { ", " });
                write_repr(item, out);
            }
            out.push(']');
        }
        Starlark::Dict(entries) => {
            out.push('{');
            for (at, (key, item)) in entries.iter().enumerate() {
                out.push_str(if at == 0 { "" } else { ", " });
                write_quoted(key, out);
                out.push_str(": ");
                write_repr(item, out);
            }
            out.push('}');
        }
    }
}

/// A string as `Printer.appendQuoted` writes it. Only `"`, `\` and the
/// control characters below 0x20 are escaped; DEL and every byte of a
/// non-ASCII character pass through, which keeps the byte model exact.
fn write_quoted(text: &str, out: &mut String) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => out.push_str(&format!("\\x{:02x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use base64::Engine as _;

    use super::*;

    fn text(value: &str) -> Starlark<'_> {
        Starlark::Str(Cow::Borrowed(value))
    }

    /// Values any JVM prints: the two-letter collision, and the one
    /// well-known string whose hash is `Integer.MIN_VALUE`, which only an
    /// implementation that wraps at 32 bits reaches.
    #[test]
    fn hash_bytes_is_string_hash_code() {
        for (input, hash) in [
            ("", 0),
            ("a", 97),
            ("hello", 99_162_322),
            ("Aa", 2112),
            ("BB", 2112),
            ("polygenelubricants", i32::MIN),
        ] {
            assert_eq!(hash_bytes(input.as_bytes()), hash, "{input:?}");
        }
    }

    /// `é` is the bytes C3 A9, so 31 * 0xC3 + 0xA9. Over UTF-16 units it
    /// would be 0xE9 = 233, the reading real Bazel refuted.
    #[test]
    fn a_non_ascii_character_is_hashed_as_its_utf8_bytes() {
        assert_eq!(hash_bytes("é".as_bytes()), 6214);
        assert_eq!(hash_bytes(&[0xC3, 0xA9]), 6214);
        // A byte above 0x7F counts as 128..=255, never as a negative.
        assert_eq!(hash_bytes(&[0xFF]), 255);
    }

    #[test]
    fn repr_writes_what_the_starlark_printer_writes() {
        let cases = [
            (Starlark::None, "None"),
            (Starlark::Bool(true), "True"),
            (Starlark::Bool(false), "False"),
            (Starlark::int(-1_949_687_017), "-1949687017"),
            (
                Starlark::Int(Cow::Borrowed("123456789012345678901234567890")),
                "123456789012345678901234567890",
            ),
            (text(""), "\"\""),
            (text("a\"b\\c"), "\"a\\\"b\\\\c\""),
            (text("\n\r\t"), "\"\\n\\r\\t\""),
            // Other control characters are `\xNN` in lowercase hex; DEL and
            // non-ASCII text are written as they are.
            (
                text("\u{0}\u{8}\u{c}\u{1f}\u{7f}é"),
                "\"\\x00\\x08\\x0c\\x1f\u{7f}é\"",
            ),
            (Starlark::List(vec![]), "[]"),
            (Starlark::Dict(vec![]), "{}"),
            (
                Starlark::List(vec![text("a"), Starlark::None, Starlark::int(7)]),
                "[\"a\", None, 7]",
            ),
            (
                Starlark::Dict(vec![
                    ("version", text("1.7.36")),
                    ("deps", Starlark::List(vec![text("g:a")])),
                    ("hashes", Starlark::Dict(vec![("g:a", Starlark::int(0))])),
                ]),
                "{\"version\": \"1.7.36\", \"deps\": [\"g:a\"], \"hashes\": {\"g:a\": 0}}",
            ),
        ];
        for (value, expected) in cases {
            assert_eq!(repr(&value), expected);
        }
    }

    /// rules_jvm_external 7.2 on Bazel 8.8.2 wrote `"repositories":
    /// -1949687017` into a pinned lock for a hub with this one repository
    /// attribute: `hash(repr(sorted(repositories)))`.
    #[test]
    fn hash_repr_reproduces_a_value_bazel_wrote() {
        let repositories = Starlark::List(vec![text(
            "{ \"repo_url\": \"https://repo1.maven.org/maven2\" }",
        )]);
        assert_eq!(
            repr(&repositories),
            "[\"{ \\\"repo_url\\\": \\\"https://repo1.maven.org/maven2\\\" }\"]"
        );
        assert_eq!(hash_repr(&repositories), -1_949_687_017);
    }

    fn hash_file_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/bazel/rje_locks/hash_file/rules_js-v3.6.0")
    }

    /// The hash file rules_js commits for its own repository at v3.6.0,
    /// and the 21 files it names, one of them a binary tarball: every
    /// `path=hash` line is `hash_bytes` of the file.
    #[test]
    fn reproduces_the_21_entries_of_the_upstream_rules_js_hash_file() {
        let dir = hash_file_dir();
        let name = "npm_translate_lock_LTE4Nzc1MDcwNjU=";
        let hash_file = std::fs::read_to_string(dir.join(name)).expect("read the hash file");
        let entries: Vec<(&str, &str)> = hash_file
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(|line| line.split_once('=').expect("a path=hash line"))
            .collect();
        assert_eq!(entries.len(), 21);
        let mut binary = 0;
        for (path, stored) in entries {
            // A fixture is named after its workspace path, `/` as `__`.
            let fixture = dir
                .join("inputs")
                .join(format!("{}.in", path.replace('/', "__")));
            let bytes = std::fs::read(&fixture).expect("read a hashed input");
            binary += usize::from(std::str::from_utf8(&bytes).is_err());
            assert_eq!(hash_bytes(&bytes).to_string(), stored, "{path}");
        }
        assert_eq!(binary, 1, "the tarball is the one input that is not text");

        // The file's own name is a hash too: base64 of the decimal hash of
        // the hub name joined to the lock label.
        let suffix = hash_bytes(b"npm//:pnpm-lock.yaml").to_string();
        assert_eq!(suffix, "-1877507065");
        let encoded = base64::engine::general_purpose::STANDARD.encode(suffix);
        assert_eq!(format!("npm_translate_lock_{encoded}"), name);
    }
}
