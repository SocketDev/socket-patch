//! The spellings a project file may give a path, folded to one: the
//! escapes a lock or config parser decodes (JSON / TOML `\uXXXX`, XML
//! character and named entities), JSON `\/` slash escapes (older
//! composer.lock), and Windows backslashes, however many of them.
//!
//! Every vendored check that asks "does this project file still name this
//! `.socket/vendor/` path?" answers through one [`PathNeedle`]. It folds
//! each escape, collapses every run of `/` and `\` to one `/`, and
//! optionally ignores ASCII case. Every check whose miss lets an artifact
//! be deleted folds case ([`PathNeedle::keep`], [`mentions_path`]), even
//! where it refuses on a hit: a committed file is installed on
//! case-folding disks too, and erring toward "mentioned" keeps the
//! artifact. Only a refusal whose miss is safe (lifting another refusal, a
//! report) folds case where the project's file system does
//! (`vendor::common::refusal_needle`).
//!
//! Discovery's identity sweep keeps its own [`fold_path_spellings`], which
//! leaves separator runs alone: its hosted-url recognition anchors on `://`.
//! Pure string functions: no filesystem access.

use std::borrow::Cow;

/// A forward-slashed relative path, folded once, to search texts for in
/// every spelling (see the module doc). `found_in` is one linear pass over
/// the text with no copy of it: an exact `contains` first, then a KMP
/// search over the folded byte stream.
#[derive(Debug, Clone)]
pub struct PathNeedle {
    raw: String,
    folded: Vec<u8>,
    fail: Vec<usize>,
    fold_case: bool,
}

impl PathNeedle {
    /// `rel`, matched ASCII case-insensitively when `fold_case`.
    pub fn new(rel: &str, fold_case: bool) -> Self {
        let mut folded = Vec::with_capacity(rel.len());
        walk_folded(rel, fold_case, |b| {
            folded.push(b);
            false
        });
        let mut fail = vec![0; folded.len()];
        let mut k = 0;
        for i in 1..folded.len() {
            while k > 0 && folded[i] != folded[k] {
                k = fail[k - 1];
            }
            if folded[i] == folded[k] {
                k += 1;
            }
            fail[i] = k;
        }
        PathNeedle {
            raw: rel.to_string(),
            folded,
            fail,
            fold_case,
        }
    }

    /// The broad needle a keep-vs-delete decision searches with: every
    /// spelling, any ASCII case. A false "mentioned" only keeps an artifact.
    pub fn keep(rel: &str) -> Self {
        Self::new(rel, true)
    }

    /// The path as the caller spelled it (for messages).
    pub fn rel(&self) -> &str {
        &self.raw
    }

    /// Whether `text` names the path in any folded spelling. A `./`, `../`,
    /// `file:` or `{root:uri}/` prefix is matched through, since the path
    /// only has to occur somewhere in the text.
    pub fn found_in(&self, text: &str) -> bool {
        if text.contains(&self.raw) || self.folded.is_empty() {
            return true;
        }
        let mut k = 0;
        walk_folded(text, self.fold_case, |b| {
            while k > 0 && b != self.folded[k] {
                k = self.fail[k - 1];
            }
            if b == self.folded[k] {
                k += 1;
            }
            if k == self.folded.len() {
                return true;
            }
            false
        })
    }
}

/// Whether `text` names the forward-slashed relative path `rel` in any
/// spelling, ASCII case-insensitively: [`PathNeedle::keep`] for a one-off
/// probe. Callers keep the artifact `rel` names while this is true.
pub fn mentions_path(text: &str, rel: &str) -> bool {
    PathNeedle::keep(rel).found_in(text)
}

/// `text` with every escape decoded and every run of `/` and `\` collapsed
/// to one `/` (case kept), borrowed when nothing changes. For a scan that
/// must slice references out of the text (the CLI's vendor-reference scan)
/// rather than ask about one path.
pub fn canonical_path_text(text: &str) -> Cow<'_, str> {
    if !text.contains(['\\', '&']) && !text.contains("//") {
        return Cow::Borrowed(text);
    }
    let mut out = Vec::with_capacity(text.len());
    walk_folded(text, false, |b| {
        out.push(b);
        false
    });
    // Only whole UTF-8 sequences are ever emitted (copied runs of the input
    // or encoded decoded chars), so this never falls back.
    match String::from_utf8(out) {
        Ok(s) => Cow::Owned(s),
        Err(e) => Cow::Owned(String::from_utf8_lossy(e.as_bytes()).into_owned()),
    }
}

/// Feed `emit` the folded bytes of `text`: escapes decoded, every run of
/// `/` and `\` (raw or decoded) as one `/`, ASCII lower-cased when
/// `fold_case`. Stops, returning true, as soon as `emit` does.
fn walk_folded(text: &str, fold_case: bool, mut emit: impl FnMut(u8) -> bool) -> bool {
    let bytes = text.as_bytes();
    let mut in_sep = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let mut utf8 = [0u8; 4];
        let (chunk, used): (&[u8], usize) = match b {
            b'\\' | b'&' => match decode_one_escape(&text[i..]) {
                Some((ch, used)) => (ch.encode_utf8(&mut utf8).as_bytes(), used),
                None => (&bytes[i..i + 1], 1),
            },
            _ => (&bytes[i..i + 1], 1),
        };
        i += used;
        if matches!(chunk, [b'/'] | [b'\\']) {
            if !in_sep {
                in_sep = true;
                if emit(b'/') {
                    return true;
                }
            }
            continue;
        }
        in_sep = false;
        for &c in chunk {
            if emit(if fold_case { c.to_ascii_lowercase() } else { c }) {
                return true;
            }
        }
    }
    false
}

/// `text` with every escape decoded ([`decode_escapes`]) and every `\/`,
/// `\\` and `\` folded to `/` — discovery's identity-sweep fold. Separator
/// runs are deliberately kept (`https://` must stay a url); over-folding
/// only ever ADDS recognition.
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
            // Runs of any length: doubly-escaped JSON, `\\\/`, `//`.
            format!("\"url\": \"{}\"", REL.replace('/', "\\\\\\\\")),
            format!("\"url\": \"{}\"", REL.replace('/', "\\\\\\/")),
            format!("\"url\": \"{}\"", REL.replace('/', "//")),
            // An escape that decodes to a backslash is a separator too.
            format!("\"url\": \"{}\"", REL.replace('/', "\\u005c")),
        ] {
            assert!(mentions_path(&text, REL), "{text}");
            assert!(PathNeedle::new(REL, false).found_in(&text) || text.contains("SOCKET"));
        }
    }

    /// A refusal needle keeps case: a differently-cased path on a
    /// case-sensitive disk is another file.
    #[test]
    fn exact_case_needle_misses_another_case() {
        let upper = format!("\"url\": \"{}\"", REL.to_ascii_uppercase());
        assert!(!PathNeedle::new(REL, false).found_in(&upper));
        assert!(PathNeedle::new(REL, true).found_in(&upper));
        let escaped = REL.replace('/', "\\/");
        assert!(PathNeedle::new(REL, false).found_in(&escaped));
    }

    /// The KMP fallback restarts correctly on a partial match.
    #[test]
    fn needle_found_after_a_partial_overlap() {
        let needle = PathNeedle::new("a/a/b", false);
        assert!(needle.found_in("a\\a\\a\\b"));
        assert!(!needle.found_in("a\\a\\a\\c"));
    }

    #[test]
    fn canonical_text_collapses_runs_and_borrows_plain_text() {
        assert!(matches!(canonical_path_text("a/b"), Cow::Borrowed("a/b")));
        assert_eq!(canonical_path_text("a\\\\\\/b//c\\u002Fd é"), "a/b/c/d é");
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
