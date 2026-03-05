/// Strip query string qualifiers from a PURL.
///
/// e.g., `"pkg:pypi/requests@2.28.0?artifact_id=abc"` -> `"pkg:pypi/requests@2.28.0"`
pub fn strip_purl_qualifiers(purl: &str) -> &str {
    match purl.find('?') {
        Some(idx) => &purl[..idx],
        None => purl,
    }
}

/// Check if a PURL is a PyPI package.
pub fn is_pypi_purl(purl: &str) -> bool {
    purl.starts_with("pkg:pypi/")
}

/// Check if a PURL is an npm package.
pub fn is_npm_purl(purl: &str) -> bool {
    purl.starts_with("pkg:npm/")
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

/// Parse an npm PURL to extract namespace, name, and version.
///
/// e.g., `"pkg:npm/@types/node@20.0.0"` -> `Some((Some("@types"), "node", "20.0.0"))`
/// e.g., `"pkg:npm/lodash@4.17.21"` -> `Some((None, "lodash", "4.17.21"))`
pub fn parse_npm_purl(purl: &str) -> Option<(Option<&str>, &str, &str)> {
    let base = strip_purl_qualifiers(purl);
    let rest = base.strip_prefix("pkg:npm/")?;

    // Find the last @ that separates name from version
    let at_idx = rest.rfind('@')?;
    let name_part = &rest[..at_idx];
    let version = &rest[at_idx + 1..];

    if name_part.is_empty() || version.is_empty() {
        return None;
    }

    // Check for scoped package (@scope/name)
    if name_part.starts_with('@') {
        let slash_idx = name_part.find('/')?;
        let namespace = &name_part[..slash_idx];
        let name = &name_part[slash_idx + 1..];
        if name.is_empty() {
            return None;
        }
        Some((Some(namespace), name, version))
    } else {
        Some((None, name_part, version))
    }
}

/// Check if a PURL is a Ruby gem.
#[cfg(feature = "gem")]
pub fn is_gem_purl(purl: &str) -> bool {
    purl.starts_with("pkg:gem/")
}

/// Parse a gem PURL to extract name and version.
///
/// e.g., `"pkg:gem/rails@7.1.0"` -> `Some(("rails", "7.1.0"))`
#[cfg(feature = "gem")]
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
#[cfg(feature = "gem")]
pub fn build_gem_purl(name: &str, version: &str) -> String {
    format!("pkg:gem/{name}@{version}")
}

/// Check if a PURL is a Maven package.
#[cfg(feature = "maven")]
pub fn is_maven_purl(purl: &str) -> bool {
    purl.starts_with("pkg:maven/")
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

/// Check if a PURL is a Go module.
#[cfg(feature = "golang")]
pub fn is_golang_purl(purl: &str) -> bool {
    purl.starts_with("pkg:golang/")
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

/// Check if a PURL is a Composer/PHP package.
#[cfg(feature = "composer")]
pub fn is_composer_purl(purl: &str) -> bool {
    purl.starts_with("pkg:composer/")
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

/// Check if a PURL is a NuGet/.NET package.
#[cfg(feature = "nuget")]
pub fn is_nuget_purl(purl: &str) -> bool {
    purl.starts_with("pkg:nuget/")
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

/// Check if a PURL is a Cargo/Rust crate.
#[cfg(feature = "cargo")]
pub fn is_cargo_purl(purl: &str) -> bool {
    purl.starts_with("pkg:cargo/")
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

/// Parse a PURL into ecosystem, package directory path, and version.
/// Supports npm, pypi, and (with `cargo` feature) cargo PURLs.
pub fn parse_purl(purl: &str) -> Option<(&str, String, &str)> {
    let base = strip_purl_qualifiers(purl);
    if let Some(rest) = base.strip_prefix("pkg:npm/") {
        let at_idx = rest.rfind('@')?;
        let pkg_dir = &rest[..at_idx];
        let version = &rest[at_idx + 1..];
        if pkg_dir.is_empty() || version.is_empty() {
            return None;
        }
        Some(("npm", pkg_dir.to_string(), version))
    } else if let Some(rest) = base.strip_prefix("pkg:pypi/") {
        let at_idx = rest.rfind('@')?;
        let name = &rest[..at_idx];
        let version = &rest[at_idx + 1..];
        if name.is_empty() || version.is_empty() {
            return None;
        }
        Some(("pypi", name.to_string(), version))
    } else {
        #[cfg(feature = "cargo")]
        if let Some(rest) = base.strip_prefix("pkg:cargo/") {
            let at_idx = rest.rfind('@')?;
            let name = &rest[..at_idx];
            let version = &rest[at_idx + 1..];
            if name.is_empty() || version.is_empty() {
                return None;
            }
            return Some(("cargo", name.to_string(), version));
        }
        #[cfg(feature = "golang")]
        if let Some(rest) = base.strip_prefix("pkg:golang/") {
            let at_idx = rest.rfind('@')?;
            let module_path = &rest[..at_idx];
            let version = &rest[at_idx + 1..];
            if module_path.is_empty() || version.is_empty() {
                return None;
            }
            return Some(("golang", module_path.to_string(), version));
        }
        #[cfg(feature = "gem")]
        if let Some(rest) = base.strip_prefix("pkg:gem/") {
            let at_idx = rest.rfind('@')?;
            let name = &rest[..at_idx];
            let version = &rest[at_idx + 1..];
            if name.is_empty() || version.is_empty() {
                return None;
            }
            return Some(("gem", name.to_string(), version));
        }
        #[cfg(feature = "maven")]
        if let Some(rest) = base.strip_prefix("pkg:maven/") {
            let at_idx = rest.rfind('@')?;
            let name_part = &rest[..at_idx];
            let version = &rest[at_idx + 1..];
            if name_part.is_empty() || version.is_empty() {
                return None;
            }
            return Some(("maven", name_part.to_string(), version));
        }
        #[cfg(feature = "composer")]
        if let Some(rest) = base.strip_prefix("pkg:composer/") {
            let at_idx = rest.rfind('@')?;
            let name_part = &rest[..at_idx];
            let version = &rest[at_idx + 1..];
            if name_part.is_empty() || version.is_empty() {
                return None;
            }
            return Some(("composer", name_part.to_string(), version));
        }
        #[cfg(feature = "nuget")]
        if let Some(rest) = base.strip_prefix("pkg:nuget/") {
            let at_idx = rest.rfind('@')?;
            let name = &rest[..at_idx];
            let version = &rest[at_idx + 1..];
            if name.is_empty() || version.is_empty() {
                return None;
            }
            return Some(("nuget", name.to_string(), version));
        }
        None
    }
}

/// Check if a string looks like a PURL.
pub fn is_purl(s: &str) -> bool {
    s.starts_with("pkg:")
}

/// Build an npm PURL from components.
pub fn build_npm_purl(namespace: Option<&str>, name: &str, version: &str) -> String {
    match namespace {
        Some(ns) => format!("pkg:npm/{}/{name}@{version}", ns),
        None => format!("pkg:npm/{name}@{version}"),
    }
}

/// Build a PyPI PURL from components.
pub fn build_pypi_purl(name: &str, version: &str) -> String {
    format!("pkg:pypi/{name}@{version}")
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
    fn test_is_pypi_purl() {
        assert!(is_pypi_purl("pkg:pypi/requests@2.28.0"));
        assert!(!is_pypi_purl("pkg:npm/lodash@4.17.21"));
    }

    #[test]
    fn test_is_npm_purl() {
        assert!(is_npm_purl("pkg:npm/lodash@4.17.21"));
        assert!(!is_npm_purl("pkg:pypi/requests@2.28.0"));
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
    fn test_parse_npm_purl() {
        assert_eq!(
            parse_npm_purl("pkg:npm/lodash@4.17.21"),
            Some((None, "lodash", "4.17.21"))
        );
        assert_eq!(
            parse_npm_purl("pkg:npm/@types/node@20.0.0"),
            Some((Some("@types"), "node", "20.0.0"))
        );
        assert_eq!(parse_npm_purl("pkg:pypi/requests@2.28.0"), None);
    }

    #[test]
    fn test_parse_purl() {
        let (eco, dir, ver) = parse_purl("pkg:npm/lodash@4.17.21").unwrap();
        assert_eq!(eco, "npm");
        assert_eq!(dir, "lodash");
        assert_eq!(ver, "4.17.21");

        let (eco, dir, ver) = parse_purl("pkg:npm/@types/node@20.0.0").unwrap();
        assert_eq!(eco, "npm");
        assert_eq!(dir, "@types/node");
        assert_eq!(ver, "20.0.0");

        let (eco, dir, ver) = parse_purl("pkg:pypi/requests@2.28.0").unwrap();
        assert_eq!(eco, "pypi");
        assert_eq!(dir, "requests");
        assert_eq!(ver, "2.28.0");
    }

    #[test]
    fn test_is_purl() {
        assert!(is_purl("pkg:npm/lodash@4.17.21"));
        assert!(is_purl("pkg:pypi/requests@2.28.0"));
        assert!(!is_purl("lodash"));
        assert!(!is_purl("CVE-2024-1234"));
    }

    #[test]
    fn test_build_npm_purl() {
        assert_eq!(
            build_npm_purl(None, "lodash", "4.17.21"),
            "pkg:npm/lodash@4.17.21"
        );
        assert_eq!(
            build_npm_purl(Some("@types"), "node", "20.0.0"),
            "pkg:npm/@types/node@20.0.0"
        );
    }

    #[test]
    fn test_build_pypi_purl() {
        assert_eq!(
            build_pypi_purl("requests", "2.28.0"),
            "pkg:pypi/requests@2.28.0"
        );
    }

    #[cfg(feature = "cargo")]
    #[test]
    fn test_is_cargo_purl() {
        assert!(is_cargo_purl("pkg:cargo/serde@1.0.200"));
        assert!(!is_cargo_purl("pkg:npm/lodash@4.17.21"));
        assert!(!is_cargo_purl("pkg:pypi/requests@2.28.0"));
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

    #[cfg(feature = "cargo")]
    #[test]
    fn test_parse_purl_cargo() {
        let (eco, dir, ver) = parse_purl("pkg:cargo/serde@1.0.200").unwrap();
        assert_eq!(eco, "cargo");
        assert_eq!(dir, "serde");
        assert_eq!(ver, "1.0.200");
    }

    #[cfg(feature = "gem")]
    #[test]
    fn test_is_gem_purl() {
        assert!(is_gem_purl("pkg:gem/rails@7.1.0"));
        assert!(!is_gem_purl("pkg:npm/lodash@4.17.21"));
        assert!(!is_gem_purl("pkg:pypi/requests@2.28.0"));
    }

    #[cfg(feature = "gem")]
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

    #[cfg(feature = "gem")]
    #[test]
    fn test_build_gem_purl() {
        assert_eq!(
            build_gem_purl("rails", "7.1.0"),
            "pkg:gem/rails@7.1.0"
        );
    }

    #[cfg(feature = "gem")]
    #[test]
    fn test_gem_purl_round_trip() {
        let purl = build_gem_purl("nokogiri", "1.16.5");
        let (name, version) = parse_gem_purl(&purl).unwrap();
        assert_eq!(name, "nokogiri");
        assert_eq!(version, "1.16.5");
    }

    #[cfg(feature = "gem")]
    #[test]
    fn test_parse_purl_gem() {
        let (eco, dir, ver) = parse_purl("pkg:gem/rails@7.1.0").unwrap();
        assert_eq!(eco, "gem");
        assert_eq!(dir, "rails");
        assert_eq!(ver, "7.1.0");
    }

    #[cfg(feature = "maven")]
    #[test]
    fn test_is_maven_purl() {
        assert!(is_maven_purl("pkg:maven/org.apache.commons/commons-lang3@3.12.0"));
        assert!(!is_maven_purl("pkg:npm/lodash@4.17.21"));
        assert!(!is_maven_purl("pkg:pypi/requests@2.28.0"));
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

    #[cfg(feature = "maven")]
    #[test]
    fn test_parse_purl_maven() {
        let (eco, dir, ver) = parse_purl("pkg:maven/org.apache.commons/commons-lang3@3.12.0").unwrap();
        assert_eq!(eco, "maven");
        assert_eq!(dir, "org.apache.commons/commons-lang3");
        assert_eq!(ver, "3.12.0");
    }

    #[cfg(feature = "golang")]
    #[test]
    fn test_is_golang_purl() {
        assert!(is_golang_purl("pkg:golang/github.com/gin-gonic/gin@v1.9.1"));
        assert!(!is_golang_purl("pkg:npm/lodash@4.17.21"));
        assert!(!is_golang_purl("pkg:pypi/requests@2.28.0"));
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

    #[cfg(feature = "golang")]
    #[test]
    fn test_parse_purl_golang() {
        let (eco, dir, ver) = parse_purl("pkg:golang/github.com/gin-gonic/gin@v1.9.1").unwrap();
        assert_eq!(eco, "golang");
        assert_eq!(dir, "github.com/gin-gonic/gin");
        assert_eq!(ver, "v1.9.1");
    }

    #[cfg(feature = "composer")]
    #[test]
    fn test_is_composer_purl() {
        assert!(is_composer_purl("pkg:composer/monolog/monolog@3.5.0"));
        assert!(!is_composer_purl("pkg:npm/lodash@4.17.21"));
        assert!(!is_composer_purl("pkg:pypi/requests@2.28.0"));
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

    #[cfg(feature = "composer")]
    #[test]
    fn test_composer_purl_round_trip() {
        let purl = build_composer_purl("symfony", "console", "6.4.1");
        let ((namespace, name), version) = parse_composer_purl(&purl).unwrap();
        assert_eq!(namespace, "symfony");
        assert_eq!(name, "console");
        assert_eq!(version, "6.4.1");
    }

    #[cfg(feature = "composer")]
    #[test]
    fn test_parse_purl_composer() {
        let (eco, dir, ver) = parse_purl("pkg:composer/monolog/monolog@3.5.0").unwrap();
        assert_eq!(eco, "composer");
        assert_eq!(dir, "monolog/monolog");
        assert_eq!(ver, "3.5.0");
    }

    #[cfg(feature = "nuget")]
    #[test]
    fn test_is_nuget_purl() {
        assert!(is_nuget_purl("pkg:nuget/Newtonsoft.Json@13.0.3"));
        assert!(!is_nuget_purl("pkg:npm/lodash@4.17.21"));
        assert!(!is_nuget_purl("pkg:pypi/requests@2.28.0"));
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

    #[cfg(feature = "nuget")]
    #[test]
    fn test_parse_purl_nuget() {
        let (eco, dir, ver) = parse_purl("pkg:nuget/Newtonsoft.Json@13.0.3").unwrap();
        assert_eq!(eco, "nuget");
        assert_eq!(dir, "Newtonsoft.Json");
        assert_eq!(ver, "13.0.3");
    }
}
