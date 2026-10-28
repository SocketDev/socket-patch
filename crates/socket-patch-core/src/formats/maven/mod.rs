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
    /// The root `<properties>` (see [`properties`]).
    properties: BTreeMap<String, String>,
    /// [`Self::properties`] plus the `${project.*}` model references a
    /// coordinate may name (see [`model_refs`]).
    coordinate_refs: BTreeMap<String, String>,
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
        let properties = properties(&masked, &ignored, &profiles)?;
        let mut coordinate_refs = properties.clone();
        for (name, value) in model_refs(&masked)? {
            coordinate_refs.entry(name).or_insert(value);
        }
        Ok(PomScope {
            masked,
            ignored,
            profiles,
            properties,
            coordinate_refs,
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
    /// `<groupId>` / `<artifactId>` with every `${prop}` the root
    /// `<properties>` or the project's own coordinates define
    /// interpolated (see [`interpolate`]); an
    /// undefined one stays as written, so [`may_name`] can tell it apart.
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
                group: child_text(&body, "groupId")?
                    .map(|g| interpolate(&g, &self.coordinate_refs)),
                artifact: child_text(&body, "artifactId")?
                    .map(|a| interpolate(&a, &self.coordinate_refs)),
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
            version: dep
                .version_text
                .map(|v| resolve_property(&v, &scope.properties)),
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

/// `text` with every `${name}` the root `<properties>` defines replaced by
/// its value (one level, no recursion, as Maven interpolates a coordinate
/// such as `org.${vendor}`); an undefined or malformed reference is kept as
/// written.
fn interpolate(text: &str, properties: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find("${") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        match after
            .find('}')
            .map(|close| (&after[..close], close))
            .filter(|(name, _)| is_property_name(name))
            .and_then(|(name, close)| properties.get(name).map(|v| (v, close)))
        {
            Some((value, close)) => {
                out.push_str(value);
                rest = &after[close + 1..];
            }
            None => {
                out.push_str("${");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The model references a sibling declaration commonly uses
/// (`${project.groupId}`, `${pom.version}`, the deprecated bare
/// `${groupId}`), read from the project's own `<groupId>` / `<artifactId>`
/// / `<version>`; groupId and version fall back to the `<parent>`'s, which
/// the project inherits when it omits them.
fn model_refs(masked: &str) -> Result<BTreeMap<String, String>, String> {
    let Some(project) = elements(masked, "project")?.into_iter().next() else {
        return Ok(BTreeMap::new());
    };
    let body = project.inner(masked);
    let parent = elements(body, "parent")?.into_iter().next();
    let parent_text = |tag: &str| match &parent {
        Some(p) => child_text(p.inner(body), tag),
        None => Ok(None),
    };
    // The project's own coordinates: what is left once every section that
    // nests a groupId / artifactId / version of something else is blanked.
    let mut own = body.to_string();
    for section in [
        "build",
        "reporting",
        "profiles",
        "distributionManagement",
        "dependencyManagement",
        "parent",
        "dependencies",
    ] {
        own = blank_elements(&own, section)?;
    }
    let mut refs = BTreeMap::new();
    for (field, inherited) in [("groupId", true), ("artifactId", false), ("version", true)] {
        let value = match child_text(&own, field)? {
            Some(v) => Some(v),
            None if inherited => parent_text(field)?,
            None => None,
        };
        if let Some(value) = value.filter(|v| !v.is_empty() && !v.contains("${")) {
            for prefix in ["project.", "pom.", ""] {
                refs.insert(format!("{prefix}{field}"), value.clone());
            }
        }
    }
    Ok(refs)
}

/// Whether a dependency's (interpolated) `coordinate` may be `want`: it
/// is, or it still holds a `${…}` this pom does not define (a parent's or
/// the build's property) and Maven might resolve it to `want` — each such
/// reference may stand for any text, while the literal text around it must
/// still match. A reader that cannot rule a declaration out must not pin or
/// attest past it.
pub(crate) fn may_name(coordinate: &str, want: &str) -> bool {
    if !coordinate.contains("${") {
        return coordinate == want;
    }
    // The literal pieces between the references (an unterminated `${`
    // reads as a reference running to the end).
    let mut pieces = Vec::new();
    let mut rest = coordinate;
    while let Some(open) = rest.find("${") {
        pieces.push(&rest[..open]);
        rest = match rest[open..].find('}') {
            Some(close) => &rest[open + close + 1..],
            None => "",
        };
    }
    pieces.push(rest);
    let (first, last) = (pieces[0], pieces[pieces.len() - 1]);
    if want.len() < first.len() + last.len() || !want.starts_with(first) || !want.ends_with(last) {
        return false;
    }
    let mut middle = &want[first.len()..want.len() - last.len()];
    for piece in &pieces[1..pieces.len() - 1] {
        match middle.find(piece) {
            Some(at) => middle = &middle[at + piece.len()..],
            None => return false,
        }
    }
    true
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

    /// #683: a coordinate property the pom defines, or a project model
    /// reference, is resolved; an undefined one may name only what its
    /// literal text around it allows.
    #[test]
    fn coordinate_references() {
        let pom = "<project><parent><groupId>org.parent</groupId><version>9</version></parent>\
                   <artifactId>app</artifactId><properties><v>org.slf4j</v></properties>\
                   <dependencies>\
                   <dependency><groupId>${v}</groupId><artifactId>${project.artifactId}-core</artifactId></dependency>\
                   <dependency><groupId>${project.groupId}</groupId><artifactId>x-${undefined}</artifactId></dependency>\
                   </dependencies></project>";
        let deps = PomScope::new(pom).unwrap().dependencies().unwrap();
        assert_eq!(deps[0].group.as_deref(), Some("org.slf4j"));
        assert_eq!(deps[0].artifact.as_deref(), Some("app-core"));
        assert_eq!(deps[1].group.as_deref(), Some("org.parent"));
        assert_eq!(deps[1].artifact.as_deref(), Some("x-${undefined}"));

        assert!(super::may_name("slf4j-api", "slf4j-api"));
        assert!(!super::may_name("slf4j-apix", "slf4j-api"));
        assert!(super::may_name("${a}", "slf4j-api"));
        assert!(super::may_name("slf4j-${a}", "slf4j-api"));
        assert!(super::may_name("${a}-${b}", "slf4j-api"));
        assert!(super::may_name("${a", "slf4j-api"));
        assert!(!super::may_name("${a}-core", "slf4j-api"));
        assert!(!super::may_name("x-${a}", "slf4j-api"));
        assert!(!super::may_name("sl${a}api-${b}x", "slf4j-api"));
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
