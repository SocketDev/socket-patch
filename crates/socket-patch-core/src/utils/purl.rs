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
}
