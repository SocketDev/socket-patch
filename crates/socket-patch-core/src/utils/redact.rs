//! The one place a URL is made safe to show.
//!
//! Every URL that reaches a human or a log (a warning, an error message,
//! a `--json` event, a debug line, a telemetry error) goes through
//! [`redact_urls_in`] or [`redact_url`] first. Three things in a URL are
//! credentials:
//!
//! * **userinfo** (`https://user:token@host/…`): GOPROXY, `.npmrc`
//!   registries, private Composer/PyPI indexes and CI git remotes all embed
//!   tokens there;
//! * **the grant token** of a Socket-served artifact or registry URL: the
//!   path level right before the patch uuid
//!   (`/patch/<eco>/…/<token>/<uuid>/<file>`,
//!   `/patch-registry/<eco>/<token>/<uuid>/…`). It authorizes the org's
//!   download;
//! * **secret query values** (`?token=…`, `X-Amz-Signature=…`, …).
//!
//! Each is replaced with [`REDACTED`]; the scheme, host, port, the other
//! path levels, the uuid and the file name stay, so the text still says
//! where the request went.
//!
//! [`strip_url_credentials`] is the identifier form: it drops userinfo and
//! secret query parameters outright, for a URL that is recorded as data
//! (a VEX product `@id`) rather than shown.
//!
//! Split by hand because the URLs here are often not well-formed enough
//! for a parser to accept (scp-like remotes, text that merely contains a
//! URL). Per RFC 3986 a raw `@` in the authority can only end the userinfo
//! (it is percent-encoded everywhere else), so the authority's tail after
//! its LAST `@` is exactly `host[:port]`.

use std::borrow::Cow;
use std::ops::Range;

/// What a redacted credential is spelled as.
pub const REDACTED: &str = "<redacted>";

/// Path levels under which Socket serves grant-tokenized URLs.
const SERVE_ROOTS: &[&str] = &["patch", "patch-registry"];

/// Byte range of `url`'s authority: after `scheme://` (or from the start
/// when there is no scheme) up to the first `/`, `?` or `#`.
fn authority_span(url: &str) -> Range<usize> {
    let start = url.find("://").map_or(0, |i| i + 3);
    let len = url[start..]
        .find(['/', '?', '#'])
        .unwrap_or(url.len() - start);
    start..start + len
}

/// Byte range of `url`'s userinfo (without the `@`), when it has one.
fn userinfo_span(url: &str) -> Option<Range<usize>> {
    let authority = authority_span(url);
    let at = url[authority.clone()].rfind('@')?;
    Some(authority.start..authority.start + at)
}

/// `scheme://[user[:pass]@]host[:port]/…` → `host[:port]`, never the
/// userinfo; `None` for an empty host. The port is kept (it is part of the
/// authority a lock records).
pub fn url_host(url: &str) -> Option<&str> {
    let authority = &url[authority_span(url)];
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    (!host.is_empty()).then_some(host)
}

/// A uuid-shaped path level (any hex case).
fn is_uuid_shaped(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// A query parameter whose value is a secret, by name.
fn is_secret_param(name: &str) -> bool {
    const MARKERS: &[&str] = &[
        "token", "auth", "key", "sig", "secret", "pass", "pwd", "cred", "session",
    ];
    let name = name.to_ascii_lowercase();
    MARKERS.iter().any(|m| name.contains(m))
}

/// Byte range of the grant-token path level of a Socket-served URL: the
/// level right before the LAST uuid-shaped level, when a serve root
/// (`patch`, `patch-registry`) precedes it. A URL without a serve root, or
/// whose uuid level directly follows the root, has none.
fn grant_token_span(url: &str) -> Option<Range<usize>> {
    let authority = authority_span(url);
    let path_start = authority.end;
    let path_len = url[path_start..]
        .find(['?', '#'])
        .unwrap_or(url.len() - path_start);
    let path = &url[path_start..path_start + path_len];
    let mut levels: Vec<Range<usize>> = Vec::new();
    let mut offset = 0;
    for level in path.split('/') {
        levels.push(path_start + offset..path_start + offset + level.len());
        offset += level.len() + 1;
    }
    let root = levels
        .iter()
        .position(|r| SERVE_ROOTS.contains(&&url[r.clone()]))?;
    let uuid = levels
        .iter()
        .rposition(|r| is_uuid_shaped(&url[r.clone()]))?;
    (uuid > root + 1)
        .then(|| levels[uuid - 1].clone())
        .filter(|r| !r.is_empty())
}

/// Byte range of `url`'s query (after the `?`, before any `#`).
fn query_span(url: &str) -> Option<Range<usize>> {
    let path_end = url.find(['?', '#'])?;
    if url.as_bytes()[path_end] != b'?' {
        return None;
    }
    let end = url[path_end..]
        .find('#')
        .map_or(url.len(), |i| path_end + i);
    Some(path_end + 1..end)
}

/// The `name=value` pairs of `url`'s query as `(pair, name, value)` byte
/// ranges.
fn query_pairs(url: &str) -> Vec<(Range<usize>, Range<usize>, Range<usize>)> {
    let Some(query) = query_span(url) else {
        return Vec::new();
    };
    let mut pairs = Vec::new();
    let mut pos = query.start;
    for pair in url[query.clone()].split('&') {
        let name_len = pair.find('=').unwrap_or(pair.len());
        let value_start = (pos + name_len + 1).min(pos + pair.len());
        pairs.push((
            pos..pos + pair.len(),
            pos..pos + name_len,
            value_start..pos + pair.len(),
        ));
        pos += pair.len() + 1;
    }
    pairs
}

/// Byte ranges of the secret query values of `url`.
fn secret_query_spans(url: &str) -> Vec<Range<usize>> {
    query_pairs(url)
        .into_iter()
        .filter(|(_, name, value)| !value.is_empty() && is_secret_param(&url[name.clone()]))
        .map(|(_, _, value)| value)
        .collect()
}

/// `url` with each span replaced by `with` (spans must not overlap).
fn replace_spans<'a>(url: &'a str, mut spans: Vec<Range<usize>>, with: &str) -> Cow<'a, str> {
    if spans.is_empty() {
        return Cow::Borrowed(url);
    }
    spans.sort_by_key(|r| r.start);
    let mut out = String::with_capacity(url.len());
    let mut at = 0;
    for span in spans {
        out.push_str(&url[at..span.start]);
        out.push_str(with);
        at = span.end;
    }
    out.push_str(&url[at..]);
    Cow::Owned(out)
}

/// `url` safe to show: userinfo, the Socket grant token and secret query
/// values each replaced with [`REDACTED`].
pub fn redact_url(url: &str) -> Cow<'_, str> {
    let mut spans: Vec<Range<usize>> = userinfo_span(url).into_iter().collect();
    spans.extend(grant_token_span(url));
    spans.extend(secret_query_spans(url));
    replace_spans(url, spans, REDACTED)
}

/// The userinfo of a `scheme://` URL (without the `@`), when it has one.
pub fn url_userinfo(url: &str) -> Option<&str> {
    if !url.contains("://") {
        return None;
    }
    userinfo_span(url).map(|r| &url[r])
}

/// `url` as an identifier: userinfo and secret query parameters dropped
/// outright (no marker), everything else as written. Only a `scheme://`
/// URL is touched: in an scp-like `user@host:path` the `user` is a login
/// name, and the text has no query.
pub fn strip_url_credentials(url: &str) -> Cow<'_, str> {
    if !url.contains("://") {
        return Cow::Borrowed(url);
    }
    let pairs = query_pairs(url);
    let secret: Vec<bool> = pairs
        .iter()
        .map(|(_, name, _)| is_secret_param(&url[name.clone()]))
        .collect();
    let userinfo = userinfo_span(url);
    if userinfo.is_none() && !secret.contains(&true) {
        return Cow::Borrowed(url);
    }
    let path_end = url.find(['?', '#']).unwrap_or(url.len());
    let mut out = String::with_capacity(url.len());
    match userinfo {
        // The `@` goes too.
        Some(r) => {
            out.push_str(&url[..r.start]);
            out.push_str(&url[r.end + 1..path_end]);
        }
        None => out.push_str(&url[..path_end]),
    }
    let kept: Vec<&str> = pairs
        .iter()
        .zip(&secret)
        .filter(|(_, secret)| !**secret)
        .map(|((pair, _, _), _)| &url[pair.clone()])
        .collect();
    if !kept.is_empty() {
        out.push('?');
        out.push_str(&kept.join("&"));
    }
    let fragment_start = query_span(url).map_or(path_end, |q| q.end);
    out.push_str(&url[fragment_start..]);
    Cow::Owned(out)
}

/// A byte that cannot be part of a URL quoted in free text.
fn ends_url(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '<' | '>' | ')' | ']' | '}' | '|')
}

/// `text` with every `scheme://…` URL in it passed through [`redact_url`].
/// Trailing sentence punctuation (`.`, `,`, `;`, `:`) is not taken as part
/// of a URL.
pub fn redact_urls_in(text: &str) -> Cow<'_, str> {
    if !text.contains("://") {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    let mut changed = false;
    while let Some(i) = text[at..].find("://").map(|i| at + i) {
        let start = text[at..i]
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
            .map_or(at, |j| at + j + 1);
        let tail = &text[i..];
        let end = i + tail.find(ends_url).unwrap_or(tail.len());
        let end = start
            + text[start..end]
                .trim_end_matches(['.', ',', ';', ':'])
                .len();
        if end <= i + 3 {
            out.push_str(&text[at..i + 3]);
            at = i + 3;
            continue;
        }
        let url = &text[start..end];
        let redacted = redact_url(url);
        out.push_str(&text[at..start]);
        changed |= redacted != url;
        out.push_str(&redacted);
        at = end;
    }
    if !changed {
        return Cow::Borrowed(text);
    }
    out.push_str(&text[at..]);
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    const TOKEN: &str = "0f1e2d3c-4b5a-4968-8776-655443322110";

    #[test]
    fn userinfo_is_redacted_and_the_host_kept() {
        assert_eq!(
            redact_url("https://user:s3cret@goproxy.corp:8443/mod/@v/v1.zip"),
            "https://<redacted>@goproxy.corp:8443/mod/@v/v1.zip",
            "the `@` in the path is not userinfo"
        );
        assert_eq!(
            redact_url("https://ghp_TOKEN@github.com/o/r.git"),
            "https://<redacted>@github.com/o/r.git"
        );
        let plain = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
        assert!(matches!(redact_url(plain), Cow::Borrowed(_)));
    }

    /// The grant token is the level before the patch uuid, in both serve
    /// shapes, whatever it looks like; the uuid, host, leaf and any
    /// non-secret query stay.
    #[test]
    fn the_grant_token_level_is_redacted() {
        let url = format!(
            "https://patch.socket.dev/patch/npm/left-pad/1.3.0/{TOKEN}/{UUID}/left-pad-1.3.0.tgz?x=1"
        );
        assert_eq!(
            redact_url(&url),
            format!(
                "https://patch.socket.dev/patch/npm/left-pad/1.3.0/<redacted>/{UUID}/left-pad-1.3.0.tgz?x=1"
            )
        );
        let registry = format!("http://127.0.0.1:9/patch-registry/npm/tok/{UUID}");
        assert_eq!(
            redact_url(&registry),
            format!("http://127.0.0.1:9/patch-registry/npm/<redacted>/{UUID}")
        );
        let composer = format!("http://h/patch/composer/acme/rlib/1.0.0/tok/{UUID}/rlib-1.0.0.zip");
        assert!(!redact_url(&composer).contains("/tok/"));
        for untouched in [
            format!("https://patch.socket.dev/patch/{UUID}/x.tgz"),
            format!("https://registry.example/{TOKEN}/{UUID}/x.tgz"),
            "https://patch.socket.dev/patch/npm/left-pad/1.3.0/x.tgz".to_string(),
        ] {
            assert_eq!(redact_url(&untouched), untouched, "no grant level");
        }
    }

    #[test]
    fn secret_query_values_are_redacted() {
        assert_eq!(
            redact_url("https://s3/b/x.zip?X-Amz-Signature=abc&v=1&access_token=t#f"),
            "https://s3/b/x.zip?X-Amz-Signature=<redacted>&v=1&access_token=<redacted>#f"
        );
    }

    #[test]
    fn credentials_are_stripped_from_an_identifier() {
        assert_eq!(
            strip_url_credentials("https://gitlab-ci-token:glcbt-SECRET@gitlab.corp/g/s/app.git"),
            "https://gitlab.corp/g/s/app.git"
        );
        assert_eq!(
            strip_url_credentials("https://u@h/r.git?private_token=x&ref=main#frag"),
            "https://h/r.git?ref=main#frag"
        );
        assert_eq!(
            strip_url_credentials("https://h/r.git?token=x"),
            "https://h/r.git"
        );
        for plain in [
            "https://git.example.com/team/repo.git",
            "git@git.corp:team/repo.git",
        ] {
            assert_eq!(strip_url_credentials(plain), plain);
        }
    }

    /// Every URL quoted in free text is redacted, wherever it sits, and the
    /// text around it (punctuation included) is kept byte for byte.
    #[test]
    fn urls_in_text_are_redacted_in_place() {
        let url = format!("https://patch.socket.dev/patch/npm/a/1.0.0/{TOKEN}/{UUID}/a-1.0.0.tgz");
        let text =
            format!("GET {url}: HTTP 403 (also git+https://u:p@git.corp/r.git, see \"{url}\".)");
        let got = redact_urls_in(&text);
        assert!(!got.contains(TOKEN), "{got}");
        assert!(!got.contains("u:p@"), "{got}");
        assert_eq!(
            got,
            format!(
                "GET https://patch.socket.dev/patch/npm/a/1.0.0/<redacted>/{UUID}/a-1.0.0.tgz: \
                 HTTP 403 (also git+https://<redacted>@git.corp/r.git, see \
                 \"https://patch.socket.dev/patch/npm/a/1.0.0/<redacted>/{UUID}/a-1.0.0.tgz\".)"
            )
        );
        let none = "nothing here: a://, b";
        assert!(matches!(redact_urls_in(none), Cow::Borrowed(_)));
    }

    /// The `vendor_prebuilt_downloaded` advisory, which quotes the
    /// grant-tokenized service URL, is built in exactly one place
    /// (`VerifiedArchive::downloaded_warning`); a backend that spells its
    /// own copy again fails here.
    #[test]
    fn the_service_download_advisory_has_one_builder() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        walk(&src, &mut files);
        let mut builders = Vec::new();
        for path in files {
            let rel = path
                .strip_prefix(&src)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if rel.ends_with("tests.rs") || rel.contains("test_support") {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .unwrap()
                .replace("\r\n", "\n");
            let production = text
                .find("#[cfg(test)]\nmod tests {")
                .map_or(text.as_str(), |at| &text[..at]);
            for _ in production.matches("\"vendor_prebuilt_downloaded\",") {
                builders.push(rel.clone());
            }
        }
        assert_eq!(builders, vec!["vendor/service_fetch.rs".to_string()]);
    }

    #[test]
    fn url_host_never_returns_userinfo() {
        assert_eq!(
            url_host("https://u:p@h.example:8443/x"),
            Some("h.example:8443")
        );
        assert_eq!(url_host("h.example/x"), Some("h.example"));
        assert_eq!(url_host("https:///x"), None);
    }
}
