//! The spellings a project file may give a path, folded to one: the
//! escapes a lock or config parser decodes (JSON / TOML `\uXXXX`, XML
//! character and named entities), JSON `\/` slash escapes (older
//! composer.lock), and single or doubled Windows backslashes.
//!
//! Discovery's identity sweep reads every file through
//! [`fold_path_spellings`], and the vendored deletion gates that ask "does a
//! project file still name this artifact?" answer through
//! [`mentions_path`], so a path the sweep recognizes is one a revert keeps.
//! Pure string functions: no filesystem access.

use std::borrow::Cow;

/// `text` with every escape decoded ([`decode_escapes`]) and every `\/`,
/// `\\` and `\` folded to `/`. Over-folding (a backslash that was not a
/// path separator) only ever ADDS matches, the safe direction for every
/// caller: a recognized reference keeps an artifact, never deletes one.
pub fn fold_path_spellings(text: &str) -> Cow<'_, str> {
    let decoded = decode_escapes(text);
    // The folds only ever touch a backslash.
    if decoded.contains('\\') {
        Cow::Owned(
            decoded
                .replace("\\/", "/")
                .replace("\\\\", "/")
                .replace('\\', "/"),
        )
    } else {
        decoded
    }
}

/// Whether `text` names the forward-slashed relative path `rel` in any
/// spelling [`fold_path_spellings`] folds, ASCII case-insensitively (a
/// Windows or macOS disk resolves `.Socket\Vendor` to the same dir). A
/// `./`, `../`, `file:` or `{root:uri}/` prefix is matched through, since
/// `rel` only has to occur somewhere in the text. Erring toward "mentioned"
/// is the point: callers keep the artifact `rel` names while this is true.
pub fn mentions_path(text: &str, rel: &str) -> bool {
    let needle = fold_path_spellings(rel).to_ascii_lowercase();
    fold_path_spellings(text)
        .to_ascii_lowercase()
        .contains(&needle)
}

/// Best-effort decode of `\uXXXX` / `\UXXXXXXXX` escapes and XML entities
/// (`&#x2F;`, `&#47;`, `&amp;`, …) — over-decoding (an escaped backslash
/// before `u`) only ever ADDS recognition, which can only make a discovery
/// claim dead, never live, and only keeps a vendored artifact.
pub fn decode_escapes(text: &str) -> Cow<'_, str> {
    if !text.contains("\\u") && !text.contains("\\U") && !text.contains('&') {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(['\\', '&']) {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        match decode_one_escape(tail) {
            Some((ch, used)) => {
                out.push(ch);
                rest = &tail[used..];
            }
            None => {
                // `\` and `&` are one byte each.
                out.push_str(&tail[..1]);
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    Cow::Owned(out)
}

/// The char one escape at the start of `tail` stands for, and its length.
fn decode_one_escape(tail: &str) -> Option<(char, usize)> {
    let hex_char = |digits: &str| char::from_u32(u32::from_str_radix(digits, 16).ok()?);
    if let Some(rest) = tail.strip_prefix("\\u") {
        return Some((hex_char(rest.get(..4)?)?, 6));
    }
    if let Some(rest) = tail.strip_prefix("\\U") {
        return Some((hex_char(rest.get(..8)?)?, 10));
    }
    if let Some(rest) = tail.strip_prefix("&#") {
        let end = rest.get(..rest.len().min(10))?.find(';')?;
        let body = &rest[..end];
        let ch = match body.strip_prefix(['x', 'X']) {
            Some(hex) => hex_char(hex)?,
            None => char::from_u32(body.parse().ok()?)?,
        };
        return Some((ch, end + 3));
    }
    [
        ("&amp;", '&'),
        ("&quot;", '"'),
        ("&apos;", '\''),
        ("&lt;", '<'),
        ("&gt;", '>'),
    ]
    .into_iter()
    .find(|(name, _)| tail.starts_with(name))
    .map(|(name, ch)| (ch, name.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REL: &str = ".socket/vendor/composer/11111111-2222-4333-8444-555555555555";

    #[test]
    fn mentions_path_matches_every_spelling() {
        for text in [
            format!("\"url\": \"{REL}/m/m@1.0.0\""),
            format!("\"url\": \"{}\\/m\\/m@1.0.0\"", REL.replace('/', "\\/")),
            format!("value=\"{}\\m\"", REL.replace('/', "\\")),
            format!("\"path\": \"{}\\\\m\"", REL.replace('/', "\\\\")),
            format!("\"path\": \"./{REL}/m\""),
            format!("\"version\": \"file:{REL}/m.tgz\""),
            format!("\"url\": \"{}\"", REL.replace('/', "\\u002F")),
            format!("<url>{}</url>", REL.replace('/', "&#x2F;")),
            format!("\"url\": \"{}\"", REL.to_ascii_uppercase()),
        ] {
            assert!(mentions_path(&text, REL), "{text}");
        }
    }

    #[test]
    fn mentions_path_misses_another_uuid() {
        let other = ".socket/vendor/composer/99999999-2222-4333-8444-555555555555/m";
        for text in [
            other.to_string(),
            other.replace('/', "\\/"),
            other.replace('/', "\\"),
        ] {
            assert!(!mentions_path(&text, REL), "{text}");
        }
        assert!(!mentions_path("", REL));
    }

    #[test]
    fn fold_leaves_plain_text_borrowed() {
        assert!(matches!(
            fold_path_spellings("a/b/c"),
            Cow::Borrowed("a/b/c")
        ));
        assert_eq!(fold_path_spellings("a\\/b\\\\c\\d"), "a/b/c/d");
    }
}
