//! Yarn classic's `.yarnrc`: one `key value` pair per line, read the way
//! yarn 1's lockfile tokenizer reads it (yarn parses `.yarnrc` with the
//! lockfile grammar, falling back to YAML).
//!
//! Every `.yarnrc` reader goes through [`setting`] (the line walk) and
//! [`token`] (the value), or [`value`] for both, so the npm crawler's
//! `--modules-folder` read and the hosted redirect's `global-folder` and
//! `yarn-offline-mirror` reads cannot disagree on a line (#1901).

use crate::formats::text::strip_bom;

/// The raw text after the last `key_name` in a `.yarnrc` (`key value`,
/// `key: value` or `key:value` lines, the key optionally double-quoted,
/// `#` comment lines); later lines override earlier ones. Empty when the
/// key has no value. Decode it with [`token`].
pub fn setting<'a>(text: &'a str, key_name: &str) -> Option<&'a str> {
    let mut found = None;
    for line in strip_bom(text).lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, rest) = match line.strip_prefix('"') {
            Some(quoted) => match quoted.split_once('"') {
                Some((key, rest)) => (key, rest),
                None => continue,
            },
            // yarn's tokenizer also ends an unquoted key at `:`, so
            // `key: value` and `key:value` set the key like `key value`.
            None => match line.split_once(|c: char| c.is_whitespace() || c == ':') {
                Some((key, rest)) => (key, rest),
                None => (line, ""),
            },
        };
        if key == key_name {
            let rest = rest.trim_start();
            found = Some(rest.strip_prefix(':').unwrap_or(rest));
        }
    }
    found
}

/// The value token that starts `rest` (what follows a key in a `.yarnrc`
/// line), read like yarn's lockfile tokenizer: a double-quoted string is
/// JSON (escapes decoded), a bare word starts with a letter, `/`, `.` or
/// `-` and ends at a space, `:` or `,` (so a trailing `# comment` is not
/// part of it), and a run of digits is a number. A single-quoted string
/// is what yarn's YAML fallback reads in a `"key": '…'` line. Anything
/// else (`~/x`, an unterminated quote) is a token yarn can't read, and so
/// is a line that goes on past the value with anything but a `#` comment
/// (`C:\deps` is the word `C`, a `:` and an unreadable `\`): `None`.
pub fn token(rest: &str) -> Option<String> {
    let (value, tail) = split_token(rest)?;
    let tail = tail.trim();
    (tail.is_empty() || tail.starts_with('#')).then_some(value)
}

/// The value token that starts `rest` and the text after it (see
/// [`token`]).
fn split_token(rest: &str) -> Option<(String, &str)> {
    let rest = rest.trim_start_matches([' ', '\t']);
    if let Some(quoted) = rest.strip_prefix('\'') {
        let mut out = String::new();
        let mut chars = quoted.char_indices().peekable();
        while let Some((i, c)) = chars.next() {
            match c {
                '\'' if matches!(chars.peek(), Some((_, '\''))) => {
                    chars.next();
                    out.push('\'');
                }
                '\'' => return Some((out, &quoted[i + 1..])),
                c => out.push(c),
            }
        }
        return None;
    }
    if rest.starts_with('"') {
        let bytes = rest.as_bytes();
        let mut end = rest.len();
        for i in 1..bytes.len() {
            let escaped = bytes[i - 1] == b'\\' && (i < 2 || bytes[i - 2] != b'\\');
            if bytes[i] == b'"' && !escaped {
                end = i + 1;
                break;
            }
        }
        let value = serde_json::from_str(&rest[..end]).ok()?;
        return Some((value, &rest[end..]));
    }
    let first = rest.chars().next()?;
    let end = if first.is_ascii_digit() {
        rest.find(|c: char| !c.is_ascii_digit())
    } else if first.is_ascii_alphabetic() || matches!(first, '/' | '.' | '-') {
        rest.find([':', ' ', ',', '\r', '\n'])
    } else {
        return None;
    }
    .unwrap_or(rest.len());
    Some((rest[..end].to_string(), &rest[end..]))
}

/// The decoded value of the last `key_name` line in a `.yarnrc`
/// ([`setting`] then [`token`]). `None` when the key is unset, has no
/// value, or its last value is a token yarn can't read.
pub fn value(text: &str, key_name: &str) -> Option<String> {
    setting(text, key_name).and_then(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_reads_keys_and_values_like_yarn() {
        let v = |rc: &str| value(rc, "--modules-folder");
        assert_eq!(v("--modules-folder deps\n").as_deref(), Some("deps"));
        assert_eq!(v("--modules-folder: lib\n").as_deref(), Some("lib"));
        assert_eq!(v("--modules-folder:lib\n").as_deref(), Some("lib"));
        assert_eq!(
            v("\"--modules-folder\" \"./my deps\"\n").as_deref(),
            Some("./my deps")
        );
        assert_eq!(v("--modules-folder 'deps'\n").as_deref(), Some("deps"));
        assert_eq!(v("--modules-folder 'it''s'\n").as_deref(), Some("it's"));
        assert_eq!(
            v("--modules-folder \"C:\\\\deps\"\n").as_deref(),
            Some("C:\\deps")
        );
        assert_eq!(v("--modules-folder deps # c\n").as_deref(), Some("deps"));
        assert_eq!(
            v("\u{feff}# c\r\n--modules-folder deps\r\n").as_deref(),
            Some("deps")
        );
        assert_eq!(
            v("--modules-folder a\n--modules-folder b\n").as_deref(),
            Some("b")
        );
    }

    /// A value yarn can't tokenize, or none at all, sets nothing, and
    /// as the last setting it hides an earlier readable one.
    #[test]
    fn unreadable_or_missing_value_is_none() {
        for rc in [
            "",
            "# --modules-folder deps\n",
            "--modules-folder-x deps\n",
            "--modules-folder\n",
            "--modules-folder ~/x\n",
            "--modules-folder C:\\deps\n",
            "--modules-folder \"unterminated\n",
            "--modules-folder 'unterminated\n",
            "--modules-folder deps\n--modules-folder ~/x\n",
            "--modules-folder deps, more\n",
            "--modules-folder 'deps' x\n",
        ] {
            assert_eq!(value(rc, "--modules-folder"), None, "{rc:?}");
        }
    }
}
