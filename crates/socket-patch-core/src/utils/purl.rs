/// Strip query string qualifiers from a PURL.
///
/// e.g., `"pkg:pypi/requests@2.28.0?artifact_id=abc"` -> `"pkg:pypi/requests@2.28.0"`
pub fn strip_purl_qualifiers(purl: &str) -> &str {
    match purl.find('?') {
        Some(idx) => &purl[..idx],
        None => purl,
    }
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
#[cfg(feature = "deno")]
pub fn parse_jsr_purl(purl: &str) -> Option<((&str, &str), &str)> {
    let base = strip_purl_qualifiers(purl);
    let rest = base.strip_prefix("pkg:jsr/")?;
    let at_idx = rest.rfind('@')?;
    let name_part = &rest[..at_idx];
    let version = &rest[at_idx + 1..];

    if name_part.is_empty() || version.is_empty() {
        return None;
    }

    let slash_idx = name_part.find('/')?;
    let scope = &name_part[..slash_idx];
    let name = &name_part[slash_idx + 1..];

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
pub fn purl_matches_identifier(manifest_key: &str, identifier: &str) -> bool {
    if identifier.contains('?') {
        manifest_key == identifier
    } else {
        strip_purl_qualifiers(manifest_key) == identifier
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
        assert_eq!(
            build_gem_purl("rails", "7.1.0"),
            "pkg:gem/rails@7.1.0"
        );
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
        assert_eq!(parse_maven_purl("pkg:maven/org.apache.commons/@3.12.0"), None);
        assert_eq!(parse_maven_purl("pkg:maven/org.apache.commons/commons-lang3@"), None);
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
    #[test]
    fn test_parse_jsr_purl() {
        assert_eq!(
            parse_jsr_purl("pkg:jsr/@std/path@0.220.0"),
            Some((("@std", "path"), "0.220.0"))
        );
        assert_eq!(
            parse_jsr_purl("pkg:jsr/@luca/flag@1.0.0"),
            Some((("@luca", "flag"), "1.0.0"))
        );
        // Scope must start with `@`.
        assert_eq!(parse_jsr_purl("pkg:jsr/std/path@0.220.0"), None);
        // Empty pieces.
        assert_eq!(parse_jsr_purl("pkg:jsr/@/path@0.220.0"), None);
        assert_eq!(parse_jsr_purl("pkg:jsr/@std/@0.220.0"), None);
        assert_eq!(parse_jsr_purl("pkg:jsr/@std/path@"), None);
        // Wrong scheme.
        assert_eq!(parse_jsr_purl("pkg:npm/@std/path@0.220.0"), None);
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

}
