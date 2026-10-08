//! The root `pom.xml` reader (repositories and dependencies, see
//! [`parse_pom`]), the Maven coordinate grammars and the hosted
//! `<base>-socket.<hex8>` version split. Pure: text in, structure out.

use std::collections::BTreeMap;

use super::xml::{blank_non_markup, child_text, elements, open_tags, Element};

// ── pure reader ──

/// The hosted version suffix marker (`<base>-socket.<hex8>`).
const SOCKET_SUFFIX: &str = "-socket.";

/// `<base>`, `<hex8>` of a `<base>-socket.<hex8>` version (lowercase hex,
/// exactly 8 digits — the rewriter's `mavenSuffixedVersion` grammar).
pub(crate) fn split_socket_version(version: &str) -> Option<(&str, &str)> {
    let (base, hex8) = version.rsplit_once(SOCKET_SUFFIX)?;
    (!base.is_empty()
        && hex8.len() == 8
        && hex8
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then_some((base, hex8))
}

/// The parts of a root pom the extractor reads.
#[derive(Debug, Default)]
pub(crate) struct Pom {
    pub(crate) repos: Vec<PomRepo>,
    pub(crate) deps: Vec<PomDep>,
}

#[derive(Debug)]
pub(crate) struct PomRepo {
    pub(crate) id: String,
    pub(crate) url: String,
    pub(crate) in_profile: bool,
}

#[derive(Debug)]
pub(crate) struct PomDep {
    pub(crate) group: String,
    pub(crate) artifact: String,
    /// Trimmed literal version, `${prop}` resolved from the root
    /// `<properties>` when possible; `None` when the declaration has none.
    pub(crate) version: Option<String>,
    /// Inside `<dependencyManagement>`.
    pub(crate) managed: bool,
    pub(crate) in_profile: bool,
}

/// A bounded, dependency-free scan of the pom's element structure — enough
/// for the handful of elements the Socket wirings touch. Comments and CDATA
/// sections are blanked first (Maven reads neither as elements); an
/// unterminated element or CDATA section is an error (fail-closed: nothing
/// is discovered from a pom that is not well-formed where it matters).
pub(crate) fn parse_pom(raw: &str) -> Result<Pom, String> {
    let text = blank_non_markup(raw)?;
    if open_tags(&text, "project")?.is_empty() || !text.contains("</project>") {
        return Err("no <project> element".to_string());
    }
    let ignored = [
        elements(&text, "build")?,
        elements(&text, "reporting")?,
        elements(&text, "pluginRepositories")?,
        elements(&text, "distributionManagement")?,
    ]
    .concat();
    let profiles = elements(&text, "profiles")?;
    let managed = elements(&text, "dependencyManagement")?;
    let inside = |pos: usize, set: &[Element]| set.iter().any(|e| pos >= e.start && pos < e.end);

    let properties = properties(&text, &ignored, &profiles)?;
    let mut pom = Pom::default();

    for repo in elements(&text, "repository")? {
        if inside(repo.start, &ignored) {
            continue;
        }
        let body = repo.inner(&text);
        pom.repos.push(PomRepo {
            id: child_text(body, "id")?.unwrap_or_default(),
            url: child_text(body, "url")?.unwrap_or_default(),
            in_profile: inside(repo.start, &profiles),
        });
    }

    for dep in elements(&text, "dependency")? {
        if inside(dep.start, &ignored) {
            continue;
        }
        // `<exclusions>` carry their own groupId/artifactId children.
        let body = blank_elements(dep.inner(&text), "exclusions")?;
        let (Some(group), Some(artifact)) = (
            child_text(&body, "groupId")?,
            child_text(&body, "artifactId")?,
        ) else {
            continue;
        };
        let version = child_text(&body, "version")?.map(|v| resolve_property(&v, &properties));
        pom.deps.push(PomDep {
            group,
            artifact,
            version,
            managed: inside(dep.start, &managed),
            in_profile: inside(dep.start, &profiles),
        });
    }
    Ok(pom)
}

/// The root `<properties>` (outside ignored sections and profiles) as
/// `name -> trimmed value`.
fn properties(
    text: &str,
    ignored: &[Element],
    profiles: &[Element],
) -> Result<BTreeMap<String, String>, String> {
    let mut map = BTreeMap::new();
    for props in elements(text, "properties")? {
        let pos = props.start;
        if ignored
            .iter()
            .chain(profiles)
            .any(|e| pos >= e.start && pos < e.end)
        {
            continue;
        }
        let body = props.inner(text);
        let mut from = 0;
        while let Some(rel) = body[from..].find('<') {
            let lt = from + rel;
            let Some(gt) = body[lt..].find('>').map(|r| lt + r) else {
                return Err("unterminated tag in <properties>".to_string());
            };
            let name = &body[lt + 1..gt];
            if !is_property_name(name) {
                from = gt + 1;
                continue;
            }
            let close = format!("</{name}>");
            let Some(end) = body[gt + 1..].find(&close).map(|r| gt + 1 + r) else {
                return Err(format!("unterminated <{name}> in <properties>"));
            };
            map.entry(name.to_string())
                .or_insert_with(|| body[gt + 1..end].trim().to_string());
            from = end + close.len();
        }
    }
    Ok(map)
}

/// `${name}` → the property's value (one level, no recursion); anything
/// else, or an undefined property, is returned unchanged.
fn resolve_property(version: &str, properties: &BTreeMap<String, String>) -> String {
    version
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
        .filter(|name| is_property_name(name))
        .and_then(|name| properties.get(name))
        .cloned()
        .unwrap_or_else(|| version.to_string())
}

fn is_property_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// A Maven groupId / artifactId: Maven's own id grammar (`[A-Za-z0-9_.-]+`).
pub(crate) fn is_maven_coordinate(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// A literal version: printable ASCII with no markup / interpolation bytes
/// ([`maven_purl`](crate::utils::purl::maven_purl) adds the path-safety rules).
pub(crate) fn is_maven_version_text(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_graphic() && !b"<>&\"'${}".contains(&b))
}

/// `text` with every `<name>…</name>` element blanked (offsets kept).
fn blank_elements(text: &str, name: &str) -> Result<String, String> {
    let mut bytes = text.as_bytes().to_vec();
    for e in elements(text, name)? {
        bytes[e.start..e.end].fill(b' ');
    }
    Ok(String::from_utf8(bytes).expect("blanking whole ASCII-delimited spans keeps UTF-8 valid"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn suffix_grammar_is_exact() {
        assert_eq!(
            super::split_socket_version("1.7.36-socket.77777777"),
            Some(("1.7.36", "77777777"))
        );
        for bad in [
            "1.7.36",
            "-socket.77777777",
            "1.7.36-socket.7777777",
            "1.7.36-socket.777777777",
            "1.7.36-socket.7777777G",
            "1.7.36-socket.ABCDEF01",
        ] {
            assert_eq!(super::split_socket_version(bad), None, "{bad}");
        }
    }
}
