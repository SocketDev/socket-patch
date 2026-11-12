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

/// Starlark `hash(repr(value))`. The text is hashed as it is printed and
/// never held, so a large value costs no memory.
pub fn hash_repr(value: &Starlark<'_>) -> i32 {
    let mut out = Hashed::EMPTY;
    write_repr(value, &mut out);
    out.hash
}

/// A piece of text as far as `String.hashCode` knows it: enough to hash
/// the text that pieces make when joined, without holding any of them.
///
/// `hashCode` is a polynomial in 31, so for texts `a` and `b`,
/// `hash(a + b) = hash(a) * 31^len(b) + hash(b)`, wrapping at 32 bits. A
/// ruleset that hashes many dicts with a shared entry prints that entry
/// each time; a caller here hashes it once with [`Hashed::entry`] and
/// joins it to each dict with [`Hashed::then`] in constant time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hashed {
    /// [`hash_bytes`] of the piece.
    hash: i32,
    /// 31 to the power of the piece's length in bytes, wrapping like the
    /// hash: what a text before the piece is multiplied by.
    scale: i32,
}

impl Hashed {
    /// The empty text.
    pub const EMPTY: Self = Self { hash: 0, scale: 1 };

    /// One entry of a dict's `repr` with what comes before it:
    /// `{"key": value` for the dict's first entry, `, "key": value` for a
    /// later one. The entries of a dict joined in order and closed with
    /// [`Hashed::close`] are the `repr` of the dict.
    pub fn entry(first: bool, key: &str, value: &Starlark<'_>) -> Self {
        let mut out = Self::EMPTY;
        write_entry(first, key, value, &mut out);
        out
    }

    /// The piece followed by `next`.
    #[must_use]
    pub fn then(self, next: Self) -> Self {
        Self {
            hash: self.hash.wrapping_mul(next.scale).wrapping_add(next.hash),
            scale: self.scale.wrapping_mul(next.scale),
        }
    }

    /// Starlark `hash(repr(dict))` of the dict whose entries, at least
    /// one, are this piece.
    pub fn close(mut self) -> i32 {
        self.put("}");
        self.hash
    }
}

/// Where `repr` is written: a `String` keeps the text, a [`Hashed`] only
/// its hash.
trait Sink {
    fn put(&mut self, text: &str);
}

impl Sink for String {
    fn put(&mut self, text: &str) {
        self.push_str(text);
    }
}

impl Sink for Hashed {
    fn put(&mut self, text: &str) {
        for byte in text.bytes() {
            self.hash = self.hash.wrapping_mul(31).wrapping_add(i32::from(byte));
            self.scale = self.scale.wrapping_mul(31);
        }
    }
}

fn write_repr(value: &Starlark<'_>, out: &mut impl Sink) {
    match value {
        Starlark::None => out.put("None"),
        Starlark::Bool(true) => out.put("True"),
        Starlark::Bool(false) => out.put("False"),
        Starlark::Int(digits) => out.put(digits),
        Starlark::Str(text) => write_quoted(text, out),
        Starlark::List(items) => {
            out.put("[");
            for (at, item) in items.iter().enumerate() {
                out.put(if at == 0 { "" } else { ", " });
                write_repr(item, out);
            }
            out.put("]");
        }
        Starlark::Dict(entries) => {
            for (at, (key, item)) in entries.iter().enumerate() {
                write_entry(at == 0, key, item, out);
            }
            out.put(if entries.is_empty() { "{}" } else { "}" });
        }
    }
}

/// One entry of a dict, with the `{` or `, ` that comes before it.
fn write_entry(first: bool, key: &str, value: &Starlark<'_>, out: &mut impl Sink) {
    out.put(if first { "{" } else { ", " });
    write_quoted(key, out);
    out.put(": ");
    write_repr(value, out);
}

/// A string as `Printer.appendQuoted` writes it. Only `"`, `\` and the
/// control characters below 0x20 are escaped; DEL and every byte of a
/// non-ASCII character pass through, which keeps the byte model exact.
fn write_quoted(text: &str, out: &mut impl Sink) {
    out.put("\"");
    // Every escaped character is one ASCII byte, so the text between two
    // of them is whole characters.
    let mut rest = text;
    while let Some(at) = rest.find(|c: char| matches!(c, '"' | '\\') || c < ' ') {
        let (plain, escaped) = rest.split_at(at);
        out.put(plain);
        match escaped.as_bytes()[0] {
            b'"' => out.put("\\\""),
            b'\\' => out.put("\\\\"),
            b'\n' => out.put("\\n"),
            b'\r' => out.put("\\r"),
            b'\t' => out.put("\\t"),
            control => out.put(&format!("\\x{control:02x}")),
        }
        rest = &escaped[1..];
    }
    out.put(rest);
    out.put("\"");
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
            // The hash is taken as the text is printed, with no text kept.
            assert_eq!(hash_repr(&value), hash_bytes(expected.as_bytes()));
        }
    }

    /// The entries of a dict, each hashed alone and then joined, hash as
    /// the dict printed whole. The pieces are long enough for `31^len` to
    /// wrap many times over, and one holds bytes above 0x7F.
    #[test]
    fn dict_entries_hashed_apart_join_to_the_hash_of_the_dict() {
        let entries = [
            (
                "standard",
                Starlark::Dict(vec![
                    ("version", text("1.7.36-socket.0b5e1c1e")),
                    (
                        "exclusions",
                        Starlark::List(vec![text("a\"b"), Starlark::None]),
                    ),
                ]),
            ),
            (
                "sha",
                text("489b51c35e393dbd4861a2e8155883f0defdf9243ea0e9e3d82f25caf0878cf5"),
            ),
            ("repository", text("https://répo.example.invalid/mäven2/")),
            ("dependencies", Starlark::List(vec![])),
            (
                "dependency_hashes",
                Starlark::Dict(vec![("g:a", Starlark::int(i32::MIN))]),
            ),
        ];
        for count in 1..=entries.len() {
            let dict = Starlark::Dict(entries[..count].to_vec());
            let pieces = entries[..count].iter().enumerate();
            let pieces = pieces.map(|(at, (key, value))| Hashed::entry(at == 0, key, value));
            let joined = pieces.fold(Hashed::EMPTY, Hashed::then);
            assert_eq!(joined.close(), hash_repr(&dict), "{count} entries");
            assert_eq!(joined.close(), hash_bytes(repr(&dict).as_bytes()));
        }
        // Joining is associative, so a shared run of entries can be joined
        // once and reused.
        let [a, b, c] = [0, 1, 2].map(|at| Hashed::entry(at == 0, entries[at].0, &entries[at].1));
        assert_eq!(a.then(b).then(c), a.then(b.then(c)));
        assert_eq!(a.then(Hashed::EMPTY), a);
        assert_eq!(Hashed::EMPTY.then(a), a);
        assert_ne!(a.then(b), b.then(a));
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
    /// and the 21 files it names: every `path=hash` line is `hash_bytes`
    /// of the file. Two of the files tell the byte model from the UTF-16
    /// one without any campaign probe. One is a binary tarball, which has
    /// no UTF-16 reading. The other is a `package.json` with an `ß` in it,
    /// and the value rules_js stored for it is not its hash over UTF-16
    /// units.
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
        let (mut binary, mut non_ascii) = (0, Vec::new());
        for (path, stored) in entries {
            // A fixture is named after its workspace path, `/` as `__`.
            let fixture = dir
                .join("inputs")
                .join(format!("{}.in", path.replace('/', "__")));
            let bytes = std::fs::read(&fixture).expect("read a hashed input");
            assert_eq!(hash_bytes(&bytes).to_string(), stored, "{path}");
            match std::str::from_utf8(&bytes) {
                Err(_) => binary += 1,
                Ok(text) if text.is_ascii() => {}
                Ok(text) => {
                    let units = text.encode_utf16().fold(0i32, |h, unit| {
                        h.wrapping_mul(31).wrapping_add(i32::from(unit))
                    });
                    assert_ne!(units.to_string(), stored, "{path}");
                    non_ascii.push((path, units));
                }
            }
        }
        assert_eq!(binary, 1, "the tarball is the one input that is not text");
        assert_eq!(
            non_ascii,
            [(
                "npm/private/test/vendored/is-odd/package.json",
                -2_025_121_710
            )]
        );

        // The file's own name is a hash too: base64 of the decimal hash of
        // the hub name joined to the lock label.
        let suffix = hash_bytes(b"npm//:pnpm-lock.yaml").to_string();
        assert_eq!(suffix, "-1877507065");
        let encoded = base64::engine::general_purpose::STANDARD.encode(suffix);
        assert_eq!(format!("npm_translate_lock_{encoded}"), name);
    }
}
