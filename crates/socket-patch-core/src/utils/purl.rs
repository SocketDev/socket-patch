use std::borrow::Cow;

/// Strip the trailing `?qualifiers` and `#subpath` components from a PURL,
/// leaving the canonical `pkg:type/namespace/name@version` base.
///
/// The PURL grammar is `pkg:type/ns/name@version?qualifiers#subpath`, so a
/// subpath can appear *with or without* a preceding qualifier. Cutting only
/// at `?` would let a bare `#subpath` (no qualifier) leak into the base —
/// corrupting the version when the result is later split on `@`, and
/// breaking the grouping/matching keys callers build from it (two PURLs for
/// the same `name@version` differing only by subpath must collapse to one
/// base). So we cut at whichever of `?`/`#` comes first.
///
/// e.g. `"pkg:pypi/requests@2.28.0?artifact_id=abc"` -> `"pkg:pypi/requests@2.28.0"`
/// and `"pkg:golang/github.com/foo/bar@v1.0.0#cmd/tool"` -> `"pkg:golang/github.com/foo/bar@v1.0.0"`
pub fn strip_purl_qualifiers(purl: &str) -> &str {
    match purl.find(['?', '#']) {
        Some(idx) => &purl[..idx],
        None => purl,
    }
}

/// Strictly percent-decode ONE purl path component (a scope, namespace
/// segment, name, or version) AFTER it has been split out of the purl.
///
/// The patches API serves purls in canonical percent-encoded form
/// (`pkg:npm/%40scope/name@1.0.0`), while crawlers build purls from the
/// literal on-disk names (`pkg:npm/@scope/name@1.0.0`). Parsers must
/// decode the API form to find installed packages.
///
/// SECURITY: this must only ever be called on a component AFTER the purl
/// has been split on `/` and the version `@` — so an encoded separator
/// (`%2f`) cannot create new path segments at parse time; it surfaces as
/// a literal `/` *inside* one component — and BEFORE the path-safety
/// guards run, so `%2e%2e`, `%2f`, `%5c`, `%00` are rejected post-decode
/// by the same `is_safe_*` gates that reject their literal forms.
/// Guarding the encoded form instead would be a traversal bypass.
///
/// Decoding is all-or-nothing: an invalid escape (`%G1`, trailing `%4`)
/// or a non-UTF8 decode returns the input unchanged (fail-safe — the
/// undecoded form contains no separators, and `%` is not a legal
/// character in any real package name). Zero-alloc when no `%`.
pub fn percent_decode_purl_component(component: &str) -> Cow<'_, str> {
    if !component.contains('%') {
        return Cow::Borrowed(component);
    }
    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let bytes = component.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let (Some(hi), Some(lo)) = (
                bytes.get(i + 1).copied().and_then(hex_val),
                bytes.get(i + 2).copied().and_then(hex_val),
            ) else {
                // Invalid escape: leave the whole component verbatim.
                return Cow::Borrowed(component);
            };
            out.push(hi * 16 + lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    match String::from_utf8(out) {
        Ok(s) => Cow::Owned(s),
        // Decoded bytes are not UTF-8: leave the component verbatim.
        Err(_) => Cow::Borrowed(component),
    }
}

/// Canonical string form for purl-to-purl comparison and display:
/// percent-decode each `/`-separated component of the
/// `pkg:type/...@version` base; qualifiers/subpath are appended verbatim.
///
/// Used ONLY for string equality (`purl_eq`) and human output — never to
/// build filesystem paths (a `%2f` decoding into a name can at worst make
/// two distinct purls compare equal, not change a write location).
pub fn normalize_purl(purl: &str) -> Cow<'_, str> {
    if !purl.contains('%') {
        return Cow::Borrowed(purl);
    }
    let split = purl.find(['?', '#']).unwrap_or(purl.len());
    let (base, suffix) = purl.split_at(split);
    let mut out = String::with_capacity(purl.len());
    for (i, seg) in base.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        out.push_str(&percent_decode_purl_component(seg));
    }
    out.push_str(suffix);
    Cow::Owned(out)
}

/// Purl equality up to percent-encoding of the base components
/// (`pkg:npm/%40scope/x@1` ≡ `pkg:npm/@scope/x@1`).
pub fn purl_eq(a: &str, b: &str) -> bool {
    normalize_purl(a) == normalize_purl(b)
}

/// Parse a PyPI PURL to extract name and version.
///
/// e.g., `"pkg:pypi/requests@2.28.0?artifact_id=abc"` -> `Some(("requests", "2.28.0"))`
pub fn parse_pypi_purl(purl: &str) -> Option<(&str, &str)> {
    let base = strip_purl_qualifiers(purl);
    let rest = base.strip_prefix("pkg:pypi/")?;
    let at_idx = rest.rfind('@')?;
    let name = &rest[..at_idx];
    let version = &rest[at_idx + 1..];
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}

/// Parse a gem PURL to extract name and version.
///
/// e.g., `"pkg:gem/rails@7.1.0"` -> `Some(("rails", "7.1.0"))`
pub fn parse_gem_purl(purl: &str) -> Option<(&str, &str)> {
    let base = strip_purl_qualifiers(purl);
    let rest = base.strip_prefix("pkg:gem/")?;
    let at_idx = rest.rfind('@')?;
    let name = &rest[..at_idx];
    let version = &rest[at_idx + 1..];
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}

/// Build a gem PURL from components.
pub fn build_gem_purl(name: &str, version: &str) -> String {
    format!("pkg:gem/{name}@{version}")
}

/// Parse a Maven PURL to extract groupId, artifactId, and version.
///
/// e.g., `"pkg:maven/org.apache.commons/commons-lang3@3.12.0"` -> `Some(("org.apache.commons", "commons-lang3", "3.12.0"))`
#[cfg(feature = "maven")]
pub fn parse_maven_purl(purl: &str) -> Option<(&str, &str, &str)> {
    let base = strip_purl_qualifiers(purl);
    let rest = base.strip_prefix("pkg:maven/")?;
    let at_idx = rest.rfind('@')?;
    let name_part = &rest[..at_idx];
    let version = &rest[at_idx + 1..];

    if name_part.is_empty() || version.is_empty() {
        return None;
    }

    // Split groupId/artifactId
    let slash_idx = name_part.find('/')?;
    let group_id = &name_part[..slash_idx];
    let artifact_id = &name_part[slash_idx + 1..];

    if group_id.is_empty() || artifact_id.is_empty() {
        return None;
    }

    Some((group_id, artifact_id, version))
}

/// Build a Maven PURL from components.
#[cfg(feature = "maven")]
pub fn build_maven_purl(group_id: &str, artifact_id: &str, version: &str) -> String {
    format!("pkg:maven/{group_id}/{artifact_id}@{version}")
}

/// Parse a Go module PURL to extract module path and version.
///
/// e.g., `"pkg:golang/github.com/gin-gonic/gin@v1.9.1"` -> `Some(("github.com/gin-gonic/gin", "v1.9.1"))`
#[cfg(feature = "golang")]
pub fn parse_golang_purl(purl: &str) -> Option<(&str, &str)> {
    let base = strip_purl_qualifiers(purl);
    let rest = base.strip_prefix("pkg:golang/")?;
    let at_idx = rest.rfind('@')?;
    let module_path = &rest[..at_idx];
    let version = &rest[at_idx + 1..];
    if module_path.is_empty() || version.is_empty() {
        return None;
    }
    Some((module_path, version))
}

/// Build a Go module PURL from components.
#[cfg(feature = "golang")]
pub fn build_golang_purl(module_path: &str, version: &str) -> String {
    format!("pkg:golang/{module_path}@{version}")
}

/// Parse a Composer PURL to extract namespace, name, and version.
///
/// Composer packages always have a namespace (vendor).
/// e.g., `"pkg:composer/monolog/monolog@3.5.0"` -> `Some((("monolog", "monolog"), "3.5.0"))`
#[cfg(feature = "composer")]
pub fn parse_composer_purl(purl: &str) -> Option<((&str, &str), &str)> {
    let base = strip_purl_qualifiers(purl);
    let rest = base.strip_prefix("pkg:composer/")?;
    let at_idx = rest.rfind('@')?;
    let name_part = &rest[..at_idx];
    let version = &rest[at_idx + 1..];

    if name_part.is_empty() || version.is_empty() {
        return None;
    }

    // Split namespace/name
    let slash_idx = name_part.find('/')?;
    let namespace = &name_part[..slash_idx];
    let name = &name_part[slash_idx + 1..];

    if namespace.is_empty() || name.is_empty() {
        return None;
    }

    Some(((namespace, name), version))
}

/// Build a Composer PURL from components.
#[cfg(feature = "composer")]
pub fn build_composer_purl(namespace: &str, name: &str, version: &str) -> String {
    format!("pkg:composer/{namespace}/{name}@{version}")
}

/// Parse a JSR PURL to extract scope, name, and version.
///
/// JSR (https://jsr.io) is Deno's package registry. Packages are
/// always scoped (`@scope/name`). PURL form:
/// `pkg:jsr/<scope>/<name>@<version>` — e.g.
/// `"pkg:jsr/@std/path@0.220.0"` -> `Some((("@std", "path"), "0.220.0"))`.
///
/// `pkg:jsr/` isn't a standardized purl-type upstream as of writing,
/// but the convention is informally adopted by some Deno tooling.
/// We follow the same shape as `parse_composer_purl` since both
/// have a `<scope>/<name>` namespace structure. The leading `@` on
/// the scope is preserved (matching npm's `@scope/name` convention).
/// `((scope, name), version)` from a JSR purl, percent-decoded.
#[cfg(feature = "deno")]
pub type JsrPurlParts<'a> = ((Cow<'a, str>, Cow<'a, str>), Cow<'a, str>);

#[cfg(feature = "deno")]
pub fn parse_jsr_purl(purl: &str) -> Option<JsrPurlParts<'_>> {
    let base = strip_purl_qualifiers(purl);
    let rest = base.strip_prefix("pkg:jsr/")?;
    let at_idx = rest.rfind('@')?;
    let name_part = &rest[..at_idx];
    let version = &rest[at_idx + 1..];

    if name_part.is_empty() || version.is_empty() {
        return None;
    }

    let slash_idx = name_part.find('/')?;
    // Decode AFTER splitting on `/`/`@` and BEFORE the shape checks below
    // (and the caller's `is_safe_jsr_component` gate) — see
    // `percent_decode_purl_component`. The API serves `%40scope`.
    let scope = percent_decode_purl_component(&name_part[..slash_idx]);
    let name = percent_decode_purl_component(&name_part[slash_idx + 1..]);
    let version = percent_decode_purl_component(version);

    // Scope must be `@<non-empty>`. The bare `@` (length 1) is
    // invalid — there's no actual scope after the marker.
    if name.is_empty() || !scope.starts_with('@') || scope.len() < 2 {
        return None;
    }

    Some(((scope, name), version))
}

/// Build a JSR PURL from components.
#[cfg(feature = "deno")]
pub fn build_jsr_purl(scope: &str, name: &str, version: &str) -> String {
    format!("pkg:jsr/{scope}/{name}@{version}")
}

/// Parse a NuGet PURL to extract name and version.
///
/// e.g., `"pkg:nuget/Newtonsoft.Json@13.0.3"` -> `Some(("Newtonsoft.Json", "13.0.3"))`
#[cfg(feature = "nuget")]
pub fn parse_nuget_purl(purl: &str) -> Option<(&str, &str)> {
    let base = strip_purl_qualifiers(purl);
    let rest = base.strip_prefix("pkg:nuget/")?;
    let at_idx = rest.rfind('@')?;
    let name = &rest[..at_idx];
    let version = &rest[at_idx + 1..];
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}

/// Build a NuGet PURL from components.
#[cfg(feature = "nuget")]
pub fn build_nuget_purl(name: &str, version: &str) -> String {
    format!("pkg:nuget/{name}@{version}")
}

/// Parse a Cargo PURL to extract name and version.
///
/// e.g., `"pkg:cargo/serde@1.0.200"` -> `Some(("serde", "1.0.200"))`
#[cfg(feature = "cargo")]
pub fn parse_cargo_purl(purl: &str) -> Option<(&str, &str)> {
    let base = strip_purl_qualifiers(purl);
    let rest = base.strip_prefix("pkg:cargo/")?;
    let at_idx = rest.rfind('@')?;
    let name = &rest[..at_idx];
    let version = &rest[at_idx + 1..];
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}

/// Build a Cargo PURL from components.
#[cfg(feature = "cargo")]
pub fn build_cargo_purl(name: &str, version: &str) -> String {
    format!("pkg:cargo/{name}@{version}")
}

/// Check if a string looks like a PURL.
pub fn is_purl(s: &str) -> bool {
    s.starts_with("pkg:")
}

/// Does a manifest PURL key match a user-supplied PURL identifier?
///
/// PyPI patches are keyed in the manifest by their fully-qualified PURL
/// (`pkg:pypi/foo@1.0?artifact_id=...`), one entry per release variant.
/// A user removing or rolling back a package usually types the *base*
/// PURL without a qualifier and expects it to cover every variant. So:
///
/// * a **base** identifier (no `?`) matches any key whose base equals it
///   — i.e. all release variants of that `package@version`, and
/// * a **qualified** identifier (`?artifact_id=...`) matches only the
///   exact key, so a single variant can still be targeted precisely.
///
/// Non-PyPI keys never carry a `?`, so for them this reduces to plain
/// equality.
///
/// Comparison is encoding-tolerant (`purl_eq`): manifest keys come from
/// the API in percent-encoded form (`pkg:npm/%40scope/x@1`) while users
/// type the literal form — both spellings must match either way around.
pub fn purl_matches_identifier(manifest_key: &str, identifier: &str) -> bool {
    if identifier.contains('?') {
        purl_eq(manifest_key, identifier)
    } else {
        // Base identifier: compare bases. Strip both sides so a subpath
        // (`#...`) carried by either the key or the identifier doesn't
        // defeat the match — `strip_purl_qualifiers(identifier)` is a no-op
        // for a plain base PURL, so existing behaviour is unchanged.
        purl_eq(
            strip_purl_qualifiers(manifest_key),
            strip_purl_qualifiers(identifier),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_qualifiers() {
        assert_eq!(
            strip_purl_qualifiers("pkg:pypi/requests@2.28.0?artifact_id=abc"),
            "pkg:pypi/requests@2.28.0"
        );
        assert_eq!(
            strip_purl_qualifiers("pkg:npm/lodash@4.17.21"),
            "pkg:npm/lodash@4.17.21"
        );
    }

    #[test]
    fn test_parse_pypi_purl() {
        assert_eq!(
            parse_pypi_purl("pkg:pypi/requests@2.28.0"),
            Some(("requests", "2.28.0"))
        );
        assert_eq!(
            parse_pypi_purl("pkg:pypi/requests@2.28.0?artifact_id=abc"),
            Some(("requests", "2.28.0"))
        );
        assert_eq!(parse_pypi_purl("pkg:npm/lodash@4.17.21"), None);
        assert_eq!(parse_pypi_purl("pkg:pypi/@2.28.0"), None);
        assert_eq!(parse_pypi_purl("pkg:pypi/requests@"), None);
    }

    #[test]
    fn test_purl_matches_identifier() {
        // Base identifier matches every qualified variant + the bare base.
        assert!(purl_matches_identifier(
            "pkg:pypi/requests@2.28.0?artifact_id=abc",
            "pkg:pypi/requests@2.28.0"
        ));
        assert!(purl_matches_identifier(
            "pkg:pypi/requests@2.28.0",
            "pkg:pypi/requests@2.28.0"
        ));
        // Base identifier does NOT match a different version.
        assert!(!purl_matches_identifier(
            "pkg:pypi/requests@2.29.0?artifact_id=abc",
            "pkg:pypi/requests@2.28.0"
        ));
        // Qualified identifier matches only the exact key.
        assert!(purl_matches_identifier(
            "pkg:pypi/requests@2.28.0?artifact_id=abc",
            "pkg:pypi/requests@2.28.0?artifact_id=abc"
        ));
        assert!(!purl_matches_identifier(
            "pkg:pypi/requests@2.28.0?artifact_id=xyz",
            "pkg:pypi/requests@2.28.0?artifact_id=abc"
        ));
        // A qualified identifier must not match the bare base key.
        assert!(!purl_matches_identifier(
            "pkg:pypi/requests@2.28.0",
            "pkg:pypi/requests@2.28.0?artifact_id=abc"
        ));
        // Non-PyPI keys: plain equality.
        assert!(purl_matches_identifier(
            "pkg:npm/lodash@4.17.21",
            "pkg:npm/lodash@4.17.21"
        ));
        assert!(!purl_matches_identifier(
            "pkg:npm/lodash@4.17.21",
            "pkg:npm/lodash@4.17.20"
        ));
    }

    #[test]
    fn test_is_purl() {
        assert!(is_purl("pkg:npm/lodash@4.17.21"));
        assert!(is_purl("pkg:pypi/requests@2.28.0"));
        assert!(!is_purl("lodash"));
        assert!(!is_purl("CVE-2024-1234"));
    }

    #[cfg(feature = "cargo")]
    #[test]
    fn test_parse_cargo_purl() {
        assert_eq!(
            parse_cargo_purl("pkg:cargo/serde@1.0.200"),
            Some(("serde", "1.0.200"))
        );
        assert_eq!(
            parse_cargo_purl("pkg:cargo/serde_json@1.0.120"),
            Some(("serde_json", "1.0.120"))
        );
        assert_eq!(parse_cargo_purl("pkg:npm/lodash@4.17.21"), None);
        assert_eq!(parse_cargo_purl("pkg:cargo/@1.0.0"), None);
        assert_eq!(parse_cargo_purl("pkg:cargo/serde@"), None);
    }

    #[cfg(feature = "cargo")]
    #[test]
    fn test_build_cargo_purl() {
        assert_eq!(
            build_cargo_purl("serde", "1.0.200"),
            "pkg:cargo/serde@1.0.200"
        );
    }

    #[cfg(feature = "cargo")]
    #[test]
    fn test_cargo_purl_round_trip() {
        let purl = build_cargo_purl("tokio", "1.38.0");
        let (name, version) = parse_cargo_purl(&purl).unwrap();
        assert_eq!(name, "tokio");
        assert_eq!(version, "1.38.0");
    }

    #[test]
    fn test_parse_gem_purl() {
        assert_eq!(
            parse_gem_purl("pkg:gem/rails@7.1.0"),
            Some(("rails", "7.1.0"))
        );
        assert_eq!(
            parse_gem_purl("pkg:gem/nokogiri@1.16.5"),
            Some(("nokogiri", "1.16.5"))
        );
        assert_eq!(parse_gem_purl("pkg:npm/lodash@4.17.21"), None);
        assert_eq!(parse_gem_purl("pkg:gem/@1.0.0"), None);
        assert_eq!(parse_gem_purl("pkg:gem/rails@"), None);
    }

    #[test]
    fn test_build_gem_purl() {
        assert_eq!(build_gem_purl("rails", "7.1.0"), "pkg:gem/rails@7.1.0");
    }

    #[test]
    fn test_gem_purl_round_trip() {
        let purl = build_gem_purl("nokogiri", "1.16.5");
        let (name, version) = parse_gem_purl(&purl).unwrap();
        assert_eq!(name, "nokogiri");
        assert_eq!(version, "1.16.5");
    }

    #[cfg(feature = "maven")]
    #[test]
    fn test_parse_maven_purl() {
        assert_eq!(
            parse_maven_purl("pkg:maven/org.apache.commons/commons-lang3@3.12.0"),
            Some(("org.apache.commons", "commons-lang3", "3.12.0"))
        );
        assert_eq!(
            parse_maven_purl("pkg:maven/com.google.guava/guava@32.1.3-jre"),
            Some(("com.google.guava", "guava", "32.1.3-jre"))
        );
        assert_eq!(parse_maven_purl("pkg:npm/lodash@4.17.21"), None);
        assert_eq!(parse_maven_purl("pkg:maven/@3.12.0"), None);
        assert_eq!(
            parse_maven_purl("pkg:maven/org.apache.commons/@3.12.0"),
            None
        );
        assert_eq!(
            parse_maven_purl("pkg:maven/org.apache.commons/commons-lang3@"),
            None
        );
    }

    #[cfg(feature = "maven")]
    #[test]
    fn test_build_maven_purl() {
        assert_eq!(
            build_maven_purl("org.apache.commons", "commons-lang3", "3.12.0"),
            "pkg:maven/org.apache.commons/commons-lang3@3.12.0"
        );
    }

    #[cfg(feature = "maven")]
    #[test]
    fn test_maven_purl_round_trip() {
        let purl = build_maven_purl("com.google.guava", "guava", "32.1.3-jre");
        let (group_id, artifact_id, version) = parse_maven_purl(&purl).unwrap();
        assert_eq!(group_id, "com.google.guava");
        assert_eq!(artifact_id, "guava");
        assert_eq!(version, "32.1.3-jre");
    }

    #[cfg(feature = "golang")]
    #[test]
    fn test_parse_golang_purl() {
        assert_eq!(
            parse_golang_purl("pkg:golang/github.com/gin-gonic/gin@v1.9.1"),
            Some(("github.com/gin-gonic/gin", "v1.9.1"))
        );
        assert_eq!(
            parse_golang_purl("pkg:golang/golang.org/x/text@v0.14.0"),
            Some(("golang.org/x/text", "v0.14.0"))
        );
        assert_eq!(parse_golang_purl("pkg:npm/lodash@4.17.21"), None);
        assert_eq!(parse_golang_purl("pkg:golang/@v1.0.0"), None);
        assert_eq!(parse_golang_purl("pkg:golang/github.com/foo/bar@"), None);
    }

    #[cfg(feature = "golang")]
    #[test]
    fn test_build_golang_purl() {
        assert_eq!(
            build_golang_purl("github.com/gin-gonic/gin", "v1.9.1"),
            "pkg:golang/github.com/gin-gonic/gin@v1.9.1"
        );
    }

    #[cfg(feature = "golang")]
    #[test]
    fn test_golang_purl_round_trip() {
        let purl = build_golang_purl("golang.org/x/text", "v0.14.0");
        let (module_path, version) = parse_golang_purl(&purl).unwrap();
        assert_eq!(module_path, "golang.org/x/text");
        assert_eq!(version, "v0.14.0");
    }

    #[cfg(feature = "composer")]
    #[test]
    fn test_parse_composer_purl() {
        assert_eq!(
            parse_composer_purl("pkg:composer/monolog/monolog@3.5.0"),
            Some((("monolog", "monolog"), "3.5.0"))
        );
        assert_eq!(
            parse_composer_purl("pkg:composer/symfony/console@6.4.1"),
            Some((("symfony", "console"), "6.4.1"))
        );
        assert_eq!(parse_composer_purl("pkg:npm/lodash@4.17.21"), None);
        assert_eq!(parse_composer_purl("pkg:composer/@3.5.0"), None);
        assert_eq!(parse_composer_purl("pkg:composer/monolog/@3.5.0"), None);
        assert_eq!(parse_composer_purl("pkg:composer/monolog/monolog@"), None);
    }

    #[cfg(feature = "composer")]
    #[test]
    fn test_build_composer_purl() {
        assert_eq!(
            build_composer_purl("monolog", "monolog", "3.5.0"),
            "pkg:composer/monolog/monolog@3.5.0"
        );
    }

    #[cfg(feature = "deno")]
    fn jsr_parts(purl: &str) -> Option<(String, String, String)> {
        parse_jsr_purl(purl)
            .map(|((s, n), v)| (s.into_owned(), n.into_owned(), v.into_owned()))
    }

    #[cfg(feature = "deno")]
    #[test]
    fn test_parse_jsr_purl() {
        assert_eq!(
            jsr_parts("pkg:jsr/@std/path@0.220.0"),
            Some(("@std".into(), "path".into(), "0.220.0".into()))
        );
        assert_eq!(
            jsr_parts("pkg:jsr/@luca/flag@1.0.0"),
            Some(("@luca".into(), "flag".into(), "1.0.0".into()))
        );
        // Scope must start with `@`.
        assert_eq!(jsr_parts("pkg:jsr/std/path@0.220.0"), None);
        // Empty pieces.
        assert_eq!(jsr_parts("pkg:jsr/@/path@0.220.0"), None);
        assert_eq!(jsr_parts("pkg:jsr/@std/@0.220.0"), None);
        assert_eq!(jsr_parts("pkg:jsr/@std/path@"), None);
        // Wrong scheme.
        assert_eq!(jsr_parts("pkg:npm/@std/path@0.220.0"), None);
    }

    #[cfg(feature = "deno")]
    #[test]
    fn test_build_jsr_purl() {
        assert_eq!(
            build_jsr_purl("@std", "path", "0.220.0"),
            "pkg:jsr/@std/path@0.220.0"
        );
    }

    #[cfg(feature = "deno")]
    #[test]
    fn test_jsr_purl_round_trip() {
        let purl = build_jsr_purl("@std", "path", "0.220.0");
        let ((scope, name), version) = parse_jsr_purl(&purl).unwrap();
        assert_eq!(scope, "@std");
        assert_eq!(name, "path");
        assert_eq!(version, "0.220.0");
    }

    #[cfg(feature = "composer")]
    #[test]
    fn test_composer_purl_round_trip() {
        let purl = build_composer_purl("symfony", "console", "6.4.1");
        let ((namespace, name), version) = parse_composer_purl(&purl).unwrap();
        assert_eq!(namespace, "symfony");
        assert_eq!(name, "console");
        assert_eq!(version, "6.4.1");
    }

    #[cfg(feature = "nuget")]
    #[test]
    fn test_parse_nuget_purl() {
        assert_eq!(
            parse_nuget_purl("pkg:nuget/Newtonsoft.Json@13.0.3"),
            Some(("Newtonsoft.Json", "13.0.3"))
        );
        assert_eq!(
            parse_nuget_purl("pkg:nuget/System.Text.Json@8.0.0"),
            Some(("System.Text.Json", "8.0.0"))
        );
        assert_eq!(parse_nuget_purl("pkg:npm/lodash@4.17.21"), None);
        assert_eq!(parse_nuget_purl("pkg:nuget/@1.0.0"), None);
        assert_eq!(parse_nuget_purl("pkg:nuget/Newtonsoft.Json@"), None);
    }

    #[cfg(feature = "nuget")]
    #[test]
    fn test_build_nuget_purl() {
        assert_eq!(
            build_nuget_purl("Newtonsoft.Json", "13.0.3"),
            "pkg:nuget/Newtonsoft.Json@13.0.3"
        );
    }

    #[cfg(feature = "nuget")]
    #[test]
    fn test_nuget_purl_round_trip() {
        let purl = build_nuget_purl("System.Text.Json", "8.0.0");
        let (name, version) = parse_nuget_purl(&purl).unwrap();
        assert_eq!(name, "System.Text.Json");
        assert_eq!(version, "8.0.0");
    }

    // --- Regression: qualifier handling -------------------------------------
    //
    // Qualifiers are stripped *before* the version is split off with
    // `rfind('@')`. This matters because a qualifier *value* can itself
    // contain an `@` (e.g. a `git@github.com` source URL). If stripping
    // ran after the `@` search, that trailing `@` would be mistaken for
    // the version separator and corrupt both name and version.

    #[test]
    fn test_strip_qualifiers_with_embedded_at() {
        assert_eq!(
            strip_purl_qualifiers("pkg:pypi/requests@2.28.0?vcs_url=git@github.com:psf/requests"),
            "pkg:pypi/requests@2.28.0"
        );
    }

    #[test]
    fn test_parse_pypi_qualifier_with_embedded_at() {
        // The `@github.com` inside the qualifier value must not be read
        // as the version separator.
        assert_eq!(
            parse_pypi_purl("pkg:pypi/requests@2.28.0?vcs_url=git@github.com"),
            Some(("requests", "2.28.0"))
        );
    }

    #[test]
    fn test_parse_gem_with_trailing_qualifier() {
        assert_eq!(
            parse_gem_purl("pkg:gem/nokogiri@1.16.5?platform=java"),
            Some(("nokogiri", "1.16.5"))
        );
    }

    #[cfg(feature = "maven")]
    #[test]
    fn test_parse_maven_qualifier_with_embedded_at() {
        // groupId/artifactId split must survive an `@` buried in a
        // qualifier value.
        assert_eq!(
            parse_maven_purl(
                "pkg:maven/org.apache.commons/commons-lang3@3.12.0?repository_url=user@host"
            ),
            Some(("org.apache.commons", "commons-lang3", "3.12.0"))
        );
    }

    #[cfg(feature = "composer")]
    #[test]
    fn test_parse_composer_qualifier_with_embedded_at() {
        assert_eq!(
            parse_composer_purl("pkg:composer/monolog/monolog@3.5.0?source=git@github.com"),
            Some((("monolog", "monolog"), "3.5.0"))
        );
    }

    #[cfg(feature = "golang")]
    #[test]
    fn test_parse_golang_keeps_full_module_path() {
        // The module path retains its internal slashes — only the
        // version is split off. A trailing qualifier is ignored.
        assert_eq!(
            parse_golang_purl("pkg:golang/github.com/gin-gonic/gin@v1.9.1?type=module"),
            Some(("github.com/gin-gonic/gin", "v1.9.1"))
        );
    }

    #[cfg(feature = "deno")]
    #[test]
    fn test_parse_jsr_with_trailing_qualifier() {
        // Scope `@` + version `@` + qualifier `@` all coexist; only the
        // version `@` should be honored.
        assert_eq!(
            jsr_parts("pkg:jsr/@std/path@0.220.0?download_url=x@y"),
            Some(("@std".into(), "path".into(), "0.220.0".into()))
        );
    }

    // --- Regression: purl_matches_identifier for non-PyPI keys --------------

    #[test]
    fn test_purl_matches_identifier_qualified_id_needs_exact_key() {
        // A qualified identifier must not match an unqualified manifest
        // key, even when their bases are equal.
        assert!(!purl_matches_identifier(
            "pkg:npm/lodash@4.17.21",
            "pkg:npm/lodash@4.17.21?foo=bar"
        ));
    }

    #[test]
    fn test_purl_matches_identifier_base_id_matches_qualified_nonpypi_key() {
        // A base identifier matches a qualified manifest key in any
        // ecosystem (gems can carry a `?platform=` qualifier).
        assert!(purl_matches_identifier(
            "pkg:gem/nokogiri@1.16.5?platform=java",
            "pkg:gem/nokogiri@1.16.5"
        ));
    }

    // --- Regression: PURL subpath (`#...`) handling -------------------------
    //
    // The PURL grammar is `pkg:type/ns/name@version?qualifiers#subpath`. A
    // subpath can appear *without* a preceding qualifier, so stripping only
    // at `?` lets it leak into the base — which then corrupts the version
    // (split on `@`) and breaks every grouping/matching key built from it.

    #[test]
    fn test_strip_subpath_without_qualifier() {
        // No `?`, but a trailing `#subpath` must still be removed.
        assert_eq!(
            strip_purl_qualifiers("pkg:golang/github.com/foo/bar@v1.0.0#cmd/tool"),
            "pkg:golang/github.com/foo/bar@v1.0.0"
        );
    }

    #[test]
    fn test_strip_qualifier_and_subpath_together() {
        // Cutting at the first of `?`/`#` removes both components at once.
        assert_eq!(
            strip_purl_qualifiers("pkg:pypi/requests@2.28.0?artifact_id=abc#dist/info"),
            "pkg:pypi/requests@2.28.0"
        );
    }

    #[test]
    fn test_parse_pypi_subpath_not_folded_into_version() {
        // The `#dist` must not bleed into the parsed version.
        assert_eq!(
            parse_pypi_purl("pkg:pypi/requests@2.28.0#dist"),
            Some(("requests", "2.28.0"))
        );
    }

    #[cfg(feature = "golang")]
    #[test]
    fn test_parse_golang_subpath_stripped() {
        // Go subpaths point at a sub-package of the same module; the parsed
        // version must remain clean.
        assert_eq!(
            parse_golang_purl("pkg:golang/github.com/gin-gonic/gin@v1.9.1#middleware"),
            Some(("github.com/gin-gonic/gin", "v1.9.1"))
        );
    }

    #[test]
    fn test_purl_matches_identifier_base_id_matches_subpath_bearing_key() {
        // A manifest key carrying a subpath must still match its own base
        // identifier — they describe the same package@version.
        assert!(purl_matches_identifier(
            "pkg:golang/github.com/foo/bar@v1.0.0#cmd/tool",
            "pkg:golang/github.com/foo/bar@v1.0.0"
        ));
        // ...but a different version still must not match.
        assert!(!purl_matches_identifier(
            "pkg:golang/github.com/foo/bar@v2.0.0#cmd/tool",
            "pkg:golang/github.com/foo/bar@v1.0.0"
        ));
    }

    // --- Percent-decoding: API purls carry %-encoded components --------------

    #[test]
    fn test_percent_decode_purl_component() {
        // The canonical case: an encoded npm scope marker.
        assert_eq!(
            percent_decode_purl_component("%40modelcontextprotocol"),
            "@modelcontextprotocol"
        );
        // Traversal sequences decode — the post-decode safety guards are
        // what reject them, not this helper.
        assert_eq!(percent_decode_purl_component("%2e%2e"), "..");
        assert_eq!(percent_decode_purl_component("a%2fb"), "a/b");
        assert_eq!(percent_decode_purl_component("%00"), "\0");
        // Invalid escapes leave the WHOLE component verbatim (all-or-nothing).
        assert_eq!(percent_decode_purl_component("%G1abc"), "%G1abc");
        assert_eq!(percent_decode_purl_component("abc%4"), "abc%4");
        assert_eq!(percent_decode_purl_component("abc%"), "abc%");
        // Non-UTF8 decode (lone continuation byte) leaves it verbatim.
        assert_eq!(percent_decode_purl_component("%FF"), "%FF");
        // No '%' is zero-alloc (borrowed).
        assert!(matches!(
            percent_decode_purl_component("plain-name"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn test_normalize_purl_and_purl_eq() {
        assert_eq!(
            normalize_purl("pkg:npm/%40modelcontextprotocol/sdk@1.12.0"),
            "pkg:npm/@modelcontextprotocol/sdk@1.12.0"
        );
        assert!(purl_eq(
            "pkg:npm/%40scope/x@1.0.0",
            "pkg:npm/@scope/x@1.0.0"
        ));
        assert!(purl_eq(
            "pkg:npm/@scope/x@1.0.0",
            "pkg:npm/%40scope/x@1.0.0"
        ));
        assert!(!purl_eq("pkg:npm/%40scope/x@1.0.0", "pkg:npm/@scope/x@2.0.0"));
        // Qualifiers/subpath are preserved verbatim (not decoded).
        assert_eq!(
            normalize_purl("pkg:npm/%40s/x@1?artifact_id=a%2Fb"),
            "pkg:npm/@s/x@1?artifact_id=a%2Fb"
        );
        // Unencoded input is unchanged (and borrowed).
        assert!(matches!(
            normalize_purl("pkg:npm/lodash@4.17.21"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn test_purl_matches_identifier_decodes_encoded_key() {
        // Encoded manifest key vs literal identifier — and vice versa.
        assert!(purl_matches_identifier(
            "pkg:npm/%40scope/x@1.0.0",
            "pkg:npm/@scope/x@1.0.0"
        ));
        assert!(purl_matches_identifier(
            "pkg:npm/@scope/x@1.0.0",
            "pkg:npm/%40scope/x@1.0.0"
        ));
        assert!(!purl_matches_identifier(
            "pkg:npm/%40scope/x@1.0.0",
            "pkg:npm/@scope/y@1.0.0"
        ));
    }

    #[cfg(feature = "deno")]
    #[test]
    fn test_parse_jsr_purl_percent_encoded_scope() {
        let ((scope, name), version) = parse_jsr_purl("pkg:jsr/%40std/path@0.220.0").unwrap();
        assert_eq!(scope, "@std");
        assert_eq!(name, "path");
        assert_eq!(version, "0.220.0");
        // The encoded bare `@` is still rejected post-decode.
        assert_eq!(jsr_parts("pkg:jsr/%40/path@0.220.0"), None);
    }

    // --- Regression: name must not absorb the version separator -------------

    #[test]
    fn test_parse_multiple_at_takes_last_as_version_separator() {
        // `rfind('@')` (not `find`) ensures the *last* `@` splits the
        // version, so a name/path that itself contained an `@` keeps it.
        assert_eq!(
            parse_pypi_purl("pkg:pypi/weird@name@1.0.0"),
            Some(("weird@name", "1.0.0"))
        );
    }
}
