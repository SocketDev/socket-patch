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
    /// The non-empty `<classifier>`: a sibling artifact of the GA (sources,
    /// tests, a native build), managed and resolved apart from the main jar.
    pub(crate) classifier: Option<String>,
    /// Inside `<dependencyManagement>`.
    pub(crate) managed: bool,
    pub(crate) in_profile: bool,
}

/// Where Maven reads a root pom's model from: its text with comments and
/// CDATA blanked (offsets kept), and the sections that are not the
/// project's own resolution. `<build>` / `<reporting>` hold plugin
/// classpaths, `<pluginRepositories>` / `<distributionManagement>` plugin
/// and deploy repositories; `<profiles>` apply only when activated. Shared
/// by the VEX reader ([`parse_pom`]) and the hosted rewriter, so the
/// rewriter edits exactly the markup VEX later attests.
#[derive(Debug)]
pub(crate) struct PomScope {
    /// The pom with comments and CDATA blanked byte-for-byte.
    pub(crate) masked: String,
    ignored: Vec<Element>,
    profiles: Vec<Element>,
}

impl PomScope {
    /// Fails (fail-closed) on a pom that is not well-formed where it
    /// matters: no `<project>`, or an unterminated element or CDATA.
    pub(crate) fn new(raw: &str) -> Result<PomScope, String> {
        let masked = blank_non_markup(raw)?;
        if open_tags(&masked, "project")?.is_empty() || !masked.contains("</project>") {
            return Err("no <project> element".to_string());
        }
        let ignored = [
            elements(&masked, "build")?,
            elements(&masked, "reporting")?,
            elements(&masked, "pluginRepositories")?,
            elements(&masked, "distributionManagement")?,
        ]
        .concat();
        let profiles = elements(&masked, "profiles")?;
        Ok(PomScope {
            masked,
            ignored,
            profiles,
        })
    }

    /// Inside a plugin / deploy section (never project resolution).
    pub(crate) fn is_ignored(&self, pos: usize) -> bool {
        inside(pos, &self.ignored)
    }

    /// Inside `<profiles>` (read only when that profile is active).
    pub(crate) fn in_profile(&self, pos: usize) -> bool {
        inside(pos, &self.profiles)
    }

    /// Every `<name>` element outside ignored sections (profiles included).
    pub(crate) fn elements(&self, name: &str) -> Result<Vec<Element>, String> {
        Ok(elements(&self.masked, name)?
            .into_iter()
            .filter(|e| !self.is_ignored(e.start))
            .collect())
    }

    /// Every `<name>` element Maven always reads: outside ignored sections
    /// and profiles.
    pub(crate) fn live(&self, name: &str) -> Result<Vec<Element>, String> {
        Ok(self
            .elements(name)?
            .into_iter()
            .filter(|e| !self.in_profile(e.start))
            .collect())
    }

    /// The `<` of the closing `</project>` tag.
    pub(crate) fn project_close(&self) -> Option<usize> {
        self.masked.rfind("</project>")
    }
}

fn inside(pos: usize, set: &[Element]) -> bool {
    set.iter().any(|e| pos >= e.start && pos < e.end)
}

/// One `<dependency>` element of a [`PomScope`] (outside ignored sections),
/// with offsets into the pom.
#[derive(Debug)]
pub(crate) struct ScopedDep {
    pub(crate) element: Element,
    pub(crate) group: Option<String>,
    pub(crate) artifact: Option<String>,
    /// Inner-text byte range of the literal `<version>`, when present.
    pub(crate) version_inner: Option<(usize, usize)>,
    /// Trimmed `<version>` text as written (no property resolution).
    pub(crate) version_text: Option<String>,
    pub(crate) type_text: Option<String>,
    /// Trimmed non-empty `<classifier>` text.
    pub(crate) classifier: Option<String>,
    pub(crate) in_profile: bool,
}

impl PomScope {
    /// Every `<dependency>` outside ignored sections, children read with
    /// `<exclusions>` blanked (they carry their own groupId/artifactId).
    pub(crate) fn dependencies(&self) -> Result<Vec<ScopedDep>, String> {
        let mut out = Vec::new();
        for dep in self.elements("dependency")? {
            let body = blank_elements(dep.inner(&self.masked), "exclusions")?;
            let version = elements(&body, "version")?.into_iter().next();
            out.push(ScopedDep {
                element: dep,
                group: child_text(&body, "groupId")?,
                artifact: child_text(&body, "artifactId")?,
                version_inner: version.map(|v| {
                    (
                        dep.inner_start + v.inner_start,
                        dep.inner_start + v.inner_end,
                    )
                }),
                version_text: version.map(|v| v.inner(&body).trim().to_string()),
                type_text: child_text(&body, "type")?,
                classifier: child_text(&body, "classifier")?.filter(|c| !c.is_empty()),
                in_profile: self.in_profile(dep.start),
            });
        }
        Ok(out)
    }
}

/// A bounded, dependency-free scan of the pom's element structure — enough
/// for the handful of elements the Socket wirings touch. Comments and CDATA
/// sections are blanked first (Maven reads neither as elements); an
/// unterminated element or CDATA section is an error (fail-closed: nothing
/// is discovered from a pom that is not well-formed where it matters).
pub(crate) fn parse_pom(raw: &str) -> Result<Pom, String> {
    let scope = PomScope::new(raw)?;
    let text = &scope.masked;
    let managed = elements(text, "dependencyManagement")?;

    let properties = properties(text, &scope.ignored, &scope.profiles)?;
    let mut pom = Pom::default();

    for repo in scope.elements("repository")? {
        let body = repo.inner(text);
        pom.repos.push(PomRepo {
            id: child_text(body, "id")?.unwrap_or_default(),
            url: child_text(body, "url")?.unwrap_or_default(),
            in_profile: scope.in_profile(repo.start),
        });
    }

    for dep in scope.dependencies()? {
        let (Some(group), Some(artifact)) = (dep.group, dep.artifact) else {
            continue;
        };
        pom.deps.push(PomDep {
            group,
            artifact,
            version: dep.version_text.map(|v| resolve_property(&v, &properties)),
            classifier: dep.classifier,
            managed: inside(dep.element.start, &managed),
            in_profile: dep.in_profile,
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
    use super::PomScope;

    #[test]
    fn scope_skips_comments_and_plugin_sections_and_flags_profiles() {
        let pom = "<project><dependencies>\
            <!-- <dependency><groupId>g</groupId><artifactId>a</artifactId><version>0</version></dependency> -->\
            <dependency><groupId>g</groupId><artifactId>a</artifactId><version> 1 </version>\
              <exclusions><exclusion><groupId>x</groupId><artifactId>y</artifactId></exclusion></exclusions></dependency>\
            <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1</version><classifier>sources</classifier></dependency>\
            </dependencies>\
            <build><plugins><plugin><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>2</version></dependency></dependencies></plugin></plugins></build>\
            <profiles><profile><repositories/><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>3</version></dependency></dependencies></profile></profiles>\
            <repositories/></project>";
        let scope = PomScope::new(pom).unwrap();
        let deps = scope.dependencies().unwrap();
        let seen: Vec<_> = deps
            .iter()
            .map(|d| {
                (
                    d.group.as_deref().unwrap(),
                    d.version_text.as_deref().unwrap(),
                    d.classifier.as_deref(),
                    d.in_profile,
                )
            })
            .collect();
        assert_eq!(
            seen,
            [
                ("g", "1", None, false),
                ("g", "1", Some("sources"), false),
                ("g", "3", None, true),
            ]
        );
        let (s, e) = deps[0].version_inner.unwrap();
        assert_eq!(&pom[s..e], " 1 ", "offsets index the original pom");
        let repos = scope.live("repositories").unwrap();
        assert_eq!(repos.len(), 1, "the profile's section is not live");
        assert_eq!(repos[0].open_tag(pom), "<repositories/>");
        assert_eq!(scope.project_close(), pom.rfind("</project>"));
        assert!(PomScope::new("<project><![CDATA[ open</project>").is_err());
        assert!(PomScope::new("<!-- <project></project> -->").is_err());
    }

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
