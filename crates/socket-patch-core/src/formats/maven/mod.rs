//! The root `pom.xml` reader (repositories and dependencies, see
//! [`parse_pom`]), the Maven coordinate grammars and the hosted
//! `<base>-socket.<hex8>` version split. Pure: text in, structure out.

mod properties;

use std::collections::BTreeMap;

use properties::{interpolate_lenient, read_properties, Interpolate};
pub(crate) use properties::{
    interpolate_strict, is_model_reference, lookup_property, profile_combinations, Definitions,
    PomLayer, MAX_COMBINED_PROFILES, MAX_INTERPOLATION_DEPTH,
};

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
    /// Trimmed version, every `${prop}` interpolated
    /// ([`interpolate_strict`]) from the project model (`project.*` /
    /// `pom.*`), the `<properties>` of the profile holding the declaration
    /// (if any), then the root `<properties>`: the version the pom itself
    /// spells, which the hosted rewriter writes and rolls back. As written
    /// when that fails (undefined, cyclic, too deep); `None` when the
    /// declaration has none.
    pub(crate) version: Option<String>,
    /// [`Self::version`] as the build resolves it: the build's user
    /// properties (`.mvn/maven.config`'s `-D`) come before the profile's
    /// and the root `<properties>` at every level — Maven's own lookup
    /// order (the model still comes first).
    pub(crate) build_version: Option<String>,
    /// The trimmed `<version>` text as written.
    pub(crate) version_text: Option<String>,
    /// The other versions [`Self::build_version`] becomes when some
    /// combination of profiles is active whose `<properties>` redefine a
    /// property it names, directly, through another, or through the
    /// project model ([`PomScope::resolve_in_build`]); the smallest
    /// combination that moves it first. Empty when no profile can move it.
    pub(crate) version_alternatives: Vec<Alternative>,
    /// The non-empty `<classifier>`: a sibling artifact of the GA (sources,
    /// tests, a native build), managed and resolved apart from the main jar.
    pub(crate) classifier: Option<String>,
    /// The trimmed `<type>`, when written.
    pub(crate) type_text: Option<String>,
    /// Inside `<dependencyManagement>`.
    pub(crate) managed: bool,
    pub(crate) in_profile: bool,
}

/// A value some combination of active profiles gives a `${…}` text other
/// than its resolution with none active, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Alternative {
    /// The value, or the text as written when that combination leaves it
    /// unresolved (undefined, cyclic, too deep) or it could not be worked
    /// out.
    pub(crate) value: String,
    pub(crate) by: MovedBy,
}

/// What gives an [`Alternative`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MovedBy {
    /// These profiles (their `<id>`s) active together.
    Profiles(Vec<String>),
    /// More profiles may change it than are combined
    /// ([`MAX_COMBINED_PROFILES`]): not worked out, fail closed.
    TooManyProfiles,
    /// A `<profiles>` `<properties>` this reader cannot parse: fail closed.
    Unreadable(String),
}

impl std::fmt::Display for MovedBy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MovedBy::Profiles(ids) => {
                let s = if ids.len() == 1 { "" } else { "s" };
                write!(f, "profile{s} {}", ids.join(" + "))
            }
            MovedBy::TooManyProfiles => write!(
                f,
                "some combination of the more than {MAX_COMBINED_PROFILES} profiles that redefine \
                 what it names"
            ),
            MovedBy::Unreadable(e) => {
                write!(f, "a <profiles> section this reader cannot parse ({e})")
            }
        }
    }
}

/// One `<properties>` inside `<profiles>`: the `<profile>` element that
/// holds it (when the scan finds one), that profile's `<id>`, and its
/// `name -> trimmed value` pairs.
#[derive(Debug)]
struct ProfileProperties {
    holder: Option<Element>,
    id: String,
    props: BTreeMap<String, String>,
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
    /// The build's user properties (`.mvn/maven.config`'s `-D`).
    user: BTreeMap<String, String>,
    /// The project model references, raw (see [`model_refs`]).
    model: BTreeMap<String, String>,
    /// Each `<properties>` inside `<profiles>`, once [`Self::read_profiles`]
    /// has read them: merged over the root's while that profile is active.
    profile_properties: Vec<ProfileProperties>,
    /// Why [`Self::read_profiles`] could not read them (every `${…}` then
    /// fails closed in [`Self::resolve_in_build`]).
    profiles_unreadable: Option<String>,
}

/// No user properties: the view of a version as the pom spells it.
static NO_USER_PROPERTIES: BTreeMap<String, String> = BTreeMap::new();

impl PomScope {
    /// Fails (fail-closed) on a pom that is not well-formed where it
    /// matters: no `<project>`, or an unterminated element or CDATA.
    #[cfg(test)]
    pub(crate) fn new(raw: &str) -> Result<PomScope, String> {
        PomScope::with_user_properties(raw, &BTreeMap::new())
    }

    /// [`Self::new`], with the user properties the build passes Maven
    /// (`.mvn/maven.config`'s `-D`, see [`maven_config_properties`]): they
    /// override a same-named pom property when a coordinate or a version is
    /// interpolated, as Maven's model interpolator looks them up before the
    /// pom's own. Profile `<properties>` are not read (see
    /// [`Self::read_profiles`]).
    pub(crate) fn with_user_properties(
        raw: &str,
        user: &BTreeMap<String, String>,
    ) -> Result<PomScope, String> {
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
        let model = model_refs(&masked)?;
        Ok(PomScope {
            masked,
            ignored,
            profiles,
            properties,
            user: user.clone(),
            model,
            profile_properties: Vec::new(),
            profiles_unreadable: None,
        })
    }

    /// Read every `<properties>` inside `<profiles>`, which only
    /// [`Self::resolve_in_build`] weighs. One this reader cannot parse
    /// does not fail the pom: it is recorded, and every `${…}` resolution
    /// then fails closed ([`MovedBy::Unreadable`]).
    pub(crate) fn read_profiles(&mut self) {
        match profile_properties(&self.masked, &self.ignored, &self.profiles) {
            Ok(found) => self.profile_properties = found,
            Err(e) => self.profiles_unreadable = Some(e),
        }
    }

    /// The indices into [`Self::profile_properties`] of the profile that
    /// holds `pos` (none outside one).
    fn own_profile(&self, pos: usize) -> Vec<usize> {
        (0..self.profile_properties.len())
            .filter(|&i| {
                self.profile_properties[i]
                    .holder
                    .is_some_and(|p| pos >= p.start && pos < p.end)
            })
            .collect()
    }

    /// A model reference's raw text (an empty element binds nothing).
    fn model_ref(&self, name: &str) -> Option<String> {
        self.model.get(name).filter(|v| !v.is_empty()).cloned()
    }

    /// What `${name}` reads ([`lookup_property`]) with the profiles `active`
    /// (indices, in pom order) active, with or without the build's user
    /// properties.
    fn lookup(&self, name: &str, active: &[usize], user: bool) -> Option<String> {
        let layer = PomLayer {
            own: &self.properties,
            profiles: active
                .iter()
                .map(|&i| &self.profile_properties[i].props)
                .collect(),
        };
        let user = if user {
            &self.user
        } else {
            &NO_USER_PROPERTIES
        };
        lookup_property(name, &|n| self.model_ref(n), user, [layer])
    }

    /// Where `${name}` may be defined in the build, for
    /// [`profile_combinations`]: the model or a user property fixes it;
    /// otherwise the root's, every profile's (each but `own`, which is
    /// always active, may be the one read) and a bare model reference.
    fn definitions(&self, name: &str, own: &[usize]) -> Definitions {
        if let Some(v) = is_model_reference(name)
            .then(|| self.model_ref(name))
            .flatten()
            .or_else(|| self.user.get(name).cloned())
        {
            return Definitions {
                texts: vec![v],
                profiles: Vec::new(),
            };
        }
        let mut d = Definitions::default();
        d.texts.extend(self.properties.get(name).cloned());
        d.texts.extend(self.model_ref(name));
        for (i, p) in self.profile_properties.iter().enumerate() {
            if let Some(v) = p.props.get(name) {
                d.texts.push(v.clone());
                if !own.contains(&i) {
                    d.profiles.push(i);
                }
            }
        }
        d
    }

    /// The `<version>` text of the declaration at `pos`, resolved as
    /// [`PomDep::version`], [`PomDep::build_version`] and
    /// [`PomDep::version_alternatives`] describe.
    fn resolve_version(&self, text: &str, pos: usize) -> (String, String, Vec<Alternative>) {
        if !text.contains("${") {
            return (text.to_string(), text.to_string(), Vec::new());
        }
        let own = self.own_profile(pos);
        let spelled = interpolate_strict(text, &|name| self.lookup(name, &own, false))
            .unwrap_or_else(|| text.to_string());
        match self.resolve_in_build(text, pos, interpolate_strict) {
            (Some(build), alternatives) => (spelled, build, alternatives),
            (None, _) => (spelled, text.to_string(), Vec::new()),
        }
    }

    /// What `text` (written in the declaration at `pos`) resolves to in the
    /// build with no profile active but the one holding it, through
    /// `interpolate` ([`interpolate_strict`] for a version), and each other
    /// value a combination of active profiles gives it
    /// ([`profile_combinations`], the vendored reactor's too), the
    /// smallest combination first; a combination `interpolate` cannot
    /// resolve gives the text as written. Fails closed: when the
    /// combinations cannot be enumerated or a profile's `<properties>` is
    /// unreadable, the text as written is an alternative.
    pub(crate) fn resolve_in_build(
        &self,
        text: &str,
        pos: usize,
        interpolate: Interpolate,
    ) -> (Option<String>, Vec<Alternative>) {
        let own = self.own_profile(pos);
        let base = interpolate(text, &|name| self.lookup(name, &own, true));
        if !text.contains("${") {
            return (base, Vec::new());
        }
        let as_written = |by: MovedBy| Alternative {
            value: text.to_string(),
            by,
        };
        if let Some(e) = &self.profiles_unreadable {
            return (base, vec![as_written(MovedBy::Unreadable(e.clone()))]);
        }
        let Some(combinations) = profile_combinations(text, &|name| self.definitions(name, &own))
        else {
            return (base, vec![as_written(MovedBy::TooManyProfiles)]);
        };
        let mut alternatives: Vec<Alternative> = Vec::new();
        for combination in combinations {
            let mut active: Vec<usize> = own.iter().chain(&combination).copied().collect();
            active.sort_unstable();
            active.dedup();
            let value = interpolate(text, &|name| self.lookup(name, &active, true))
                .unwrap_or_else(|| text.to_string());
            if Some(&value) != base.as_ref() && alternatives.iter().all(|a| a.value != value) {
                let ids = combination
                    .iter()
                    .map(|&i| self.profile_properties[i].id.clone())
                    .collect();
                alternatives.push(Alternative {
                    value,
                    by: MovedBy::Profiles(ids),
                });
            }
        }
        (base, alternatives)
    }

    /// `text` (a coordinate) with every `${name}` the build defines with
    /// no profile active interpolated, an undefined one kept as written
    /// ([`interpolate_lenient`]).
    fn interpolate_coordinate(&self, text: &str) -> String {
        interpolate_lenient(text, &|name| self.lookup(name, &[], true))
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
    /// `<groupId>` / `<artifactId>` with every `${prop}` the build defines
    /// with no profile active (user properties, the project model, the
    /// root `<properties>`) interpolated
    /// ([`PomScope::interpolate_coordinate`]); an undefined one stays as
    /// written, so [`may_name`] can tell it apart.
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
                group: child_text(&body, "groupId")?.map(|g| self.interpolate_coordinate(&g)),
                artifact: child_text(&body, "artifactId")?.map(|a| self.interpolate_coordinate(&a)),
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
    parse_pom_with(raw, &BTreeMap::new())
}

/// [`parse_pom`] with the build's user properties (see
/// [`PomScope::with_user_properties`]).
pub(crate) fn parse_pom_with(raw: &str, user: &BTreeMap<String, String>) -> Result<Pom, String> {
    let mut scope = PomScope::with_user_properties(raw, user)?;
    scope.read_profiles();
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
        let (version, build_version, version_alternatives) = match &dep.version_text {
            Some(text) => {
                let (spelled, build, alternatives) = scope.resolve_version(text, dep.element.start);
                (Some(spelled), Some(build), alternatives)
            }
            None => (None, None, Vec::new()),
        };
        pom.deps.push(PomDep {
            group,
            artifact,
            version,
            build_version,
            version_text: dep.version_text,
            version_alternatives,
            classifier: dep.classifier,
            type_text: dep.type_text,
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
        read_properties(props.inner(text), &mut map)?;
    }
    Ok(map)
}

/// Each `<properties>` inside `<profiles>` (outside ignored sections) as
/// `name -> trimmed value`, with the `<profile>` element that holds it.
fn profile_properties(
    text: &str,
    ignored: &[Element],
    profiles: &[Element],
) -> Result<Vec<ProfileProperties>, String> {
    let live = |pos: usize| inside(pos, profiles) && !inside(pos, ignored);
    // A `<properties>` no `<profile>` is found around (a scan this simple
    // cannot place) belongs to no profile: it is then only ever an
    // alternative, never a declaration's own, which reads more versions
    // into [`PomDep::version_alternatives`], not fewer.
    let holders: Vec<Element> = elements(text, "profile")
        .unwrap_or_default()
        .into_iter()
        .filter(|p| live(p.start))
        .collect();
    let mut out = Vec::new();
    for props in elements(text, "properties")? {
        if !live(props.start) {
            continue;
        }
        let holder = holders
            .iter()
            .find(|p| props.start >= p.start && props.start < p.end)
            .copied();
        let id = holder
            .and_then(|p| child_text(p.inner(text), "id").ok().flatten())
            .filter(|id| !id.is_empty())
            .unwrap_or_else(|| format!("#{}", out.len() + 1));
        let mut map = BTreeMap::new();
        read_properties(props.inner(text), &mut map)?;
        out.push(ProfileProperties {
            holder,
            id,
            props: map,
        });
    }
    Ok(out)
}

/// The model references a sibling declaration commonly uses
/// (`${project.groupId}`, `${pom.version}`, the deprecated bare
/// `${groupId}`, `${project.parent.groupId}`), read from the project's own
/// `<groupId>` / `<artifactId>` / `<version>` and its `<parent>`'s; groupId
/// and version fall back to the parent's, which the project inherits when
/// it omits them. Each is bound raw: one written through a property
/// (`<version>${revision}</version>`) is interpolated wherever it is read,
/// with the user properties and active profiles of that read, as Maven
/// interpolates the model itself (never inherited instead: Maven
/// interpolates a present element).
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
        "properties",
    ] {
        own = blank_elements(&own, section)?;
    }
    let mut refs = BTreeMap::new();
    for (field, inherited) in [("groupId", true), ("artifactId", false), ("version", true)] {
        let parent_value = parent_text(field)?;
        let value = match child_text(&own, field)? {
            Some(v) => Some(v),
            None if inherited => parent_value.clone(),
            None => None,
        };
        if let Some(value) = value {
            for prefix in ["project.", "pom.", ""] {
                refs.insert(format!("{prefix}{field}"), value.clone());
            }
        }
        if let Some(value) = parent_value {
            for prefix in ["project.parent.", "pom.parent.", "parent."] {
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

/// The user properties a `maven.config` defines, as Maven 3.9+ reads it:
/// one argument per line, `#` lines are comments (older Maven rejects
/// them), and a wholly quoted argument is unquoted. A property is
/// `-Dk=v`, `-D k=v`, `--define=k=v` or `--define k=v`, or a bare `-D` /
/// `--define` whose `k=v` is the next line. The value is the rest of the
/// argument, so `-Dv=1.0 # note` defines `1.0 # note`, as in Maven.
/// `-Dk` sets `k=true`; a later definition wins. Maven before 3.9 splits
/// the file on whitespace instead, so a `-Dk=v` token that only that reading
/// finds (`-B -Dk=v` on one line) is kept too, unless a line defines `k`.
pub(crate) fn maven_config_properties(config: &str) -> BTreeMap<String, String> {
    // Java's `String.trim`: every char up to U+0020, nothing beyond.
    fn trim(s: &str) -> &str {
        s.trim_matches(|c: char| c <= ' ')
    }
    fn unquote(s: &str) -> &str {
        s.strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .map_or(s, trim)
    }
    let mut args = config
        .lines()
        .map(|line| unquote(trim(line)))
        .filter(|arg| !arg.is_empty() && !arg.starts_with('#'))
        .peekable();
    let mut props = BTreeMap::new();
    while let Some(arg) = args.next() {
        let def = match arg.strip_prefix("--define") {
            Some(rest) => rest
                .strip_prefix('=')
                .or_else(|| (rest.is_empty() || rest.starts_with(' ')).then_some(rest)),
            None => arg.strip_prefix("-D"),
        };
        let Some(def) = def.map(trim) else {
            continue;
        };
        let def = match def {
            "" => match args.next_if(|next| !next.starts_with('-')) {
                Some(next) => next,
                None => continue,
            },
            def => def,
        };
        let (k, v) = def.split_once('=').unwrap_or((def, "true"));
        if !k.is_empty() {
            props.insert(k.to_string(), v.to_string());
        }
    }
    let tokens = config
        .lines()
        .filter(|line| !trim(line).starts_with('#'))
        .flat_map(str::split_whitespace)
        .filter_map(|t| t.strip_prefix("-D")?.split_once('='));
    let mut legacy = BTreeMap::new();
    for (k, v) in tokens {
        if !k.is_empty() && !props.contains_key(k) {
            legacy.insert(k.to_string(), v.to_string());
        }
    }
    props.extend(legacy);
    props
}

/// Whether a declaration Maven always reads (outside `<profiles>` when
/// `in_profile` is false) whose coordinates are not `group:artifact` as
/// written may still be that GA's main jar through an undefined coordinate
/// property (#683): a jar-typed (or untyped, or typed through a property
/// that may be `jar`), classifier-less declaration
/// whose coordinates [`may_name`] it. The hosted rewriter and VEX share this
/// rule, so what one pins the other attests.
pub(crate) fn may_shadow(
    (dep_group, dep_artifact): (&str, &str),
    type_text: Option<&str>,
    classifier: Option<&str>,
    (group, artifact): (&str, &str),
) -> bool {
    (dep_group != group || dep_artifact != artifact)
        && classifier.is_none()
        && type_text.is_none_or(|t| t == "jar" || t.contains("${"))
        && may_name(dep_group, group)
        && may_name(dep_artifact, artifact)
}

/// The classifiers whose jars never run on a classpath: `sources` and
/// `javadoc`. Every other classifier copy of a patched GA (tests, a native
/// or JDK-specific build) carries code, so it must resolve the patched
/// release too. The hosted rewriter, VEX discovery and the vendored
/// reactor's attestation share this rule.
pub(crate) const NON_EXECUTABLE_CLASSIFIERS: &[&str] = &["sources", "javadoc"];

/// Whether a `<classifier>` copy of a GA carries code onto a classpath
/// (see [`NON_EXECUTABLE_CLASSIFIERS`]).
pub(crate) fn is_executable_classifier(classifier: &str) -> bool {
    !NON_EXECUTABLE_CLASSIFIERS.contains(&classifier)
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
    use std::collections::BTreeMap;

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
    fn exponential_property_expansion_is_capped() {
        // Each property names the previous one 40 times: uncapped, `${p6}`
        // would expand to 40^6 bytes.
        let mut props = String::from("<p0>x</p0>");
        for i in 1..=6 {
            props.push_str(&format!(
                "<p{i}>{}</p{i}>",
                format!("${{p{}}}", i - 1).repeat(40)
            ));
        }
        let pom = format!(
            "<project><groupId>${{p6}}</groupId><properties>{props}</properties><dependencies>\
             <dependency><groupId>${{p6}}</groupId><artifactId>a</artifactId><version>1</version></dependency>\
             </dependencies></project>"
        );
        let deps = PomScope::new(&pom).unwrap().dependencies().unwrap();
        let group = deps[0].group.as_deref().unwrap();
        assert!(
            group.len() <= super::properties::MAX_RESOLVED_LEN,
            "{}",
            group.len()
        );
        assert!(group.contains("${"), "left unresolved, so it fails closed");
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

        // A property defined through another, the parent's coordinates,
        // and the model winning over a same-named property.
        let pom = "<project><parent><groupId>org.parent</groupId></parent><groupId>com.acme</groupId>\
                   <properties><base>org.slf4j</base><g>${base}</g><project.groupId>org.slf4j</project.groupId></properties>\
                   <dependencies>\
                   <dependency><groupId>${g}</groupId><artifactId>a</artifactId></dependency>\
                   <dependency><groupId>${project.parent.groupId}</groupId><artifactId>b</artifactId></dependency>\
                   <dependency><groupId>${project.groupId}</groupId><artifactId>c</artifactId></dependency>\
                   </dependencies></project>";
        let deps = PomScope::new(pom).unwrap().dependencies().unwrap();
        let groups: Vec<_> = deps.iter().map(|d| d.group.as_deref().unwrap()).collect();
        assert_eq!(groups, ["org.slf4j", "org.parent", "com.acme"]);

        let ga = ("org.slf4j", "slf4j-api");
        assert!(super::may_shadow(("${g}", "slf4j-api"), None, None, ga));
        assert!(super::may_shadow(
            ("${g}", "slf4j-api"),
            Some("jar"),
            None,
            ga
        ));
        assert!(!super::may_shadow(("${g}", "${b}"), Some("pom"), None, ga));
        assert!(!super::may_shadow(
            ("${g}", "slf4j-api"),
            None,
            Some("tests"),
            ga
        ));
        assert!(super::may_shadow(
            ("${g}", "slf4j-api"),
            Some("${t}"),
            None,
            ga
        ));
        assert!(!super::may_shadow(ga, None, None, ga));

        // Bugbot: a project coordinate written through a property is
        // interpolated, not inherited from the parent, and a same-named
        // element inside <properties> is not the project's own.
        let pom = "<project><parent><groupId>org.parent</groupId><version>9</version></parent>\
                   <properties><groupId>org.wrong</groupId><g>com.acme</g></properties>\
                   <groupId>${g}</groupId><version>${undefined}</version>\
                   <dependencies>\
                   <dependency><groupId>${project.groupId}</groupId><artifactId>a</artifactId>\
                   <version>${project.version}</version></dependency>\
                   </dependencies></project>";
        let scope = PomScope::new(pom).unwrap();
        let deps = scope.dependencies().unwrap();
        assert_eq!(deps[0].group.as_deref(), Some("com.acme"));
        let dep = super::parse_pom(pom).unwrap().deps.remove(0);
        assert_eq!(
            dep.build_version.as_deref(),
            Some("${project.version}"),
            "an unresolvable project version is not the parent's"
        );
    }

    /// Maven's model interpolator reads user properties (`.mvn/maven.config`'s
    /// `-D`) before the pom's own `<properties>`, for a `<version>` just as
    /// for a coordinate: `-Dv=1.0` makes `${v}` the base release whatever
    /// the pom defines.
    #[test]
    fn version_property_reads_user_properties_first() {
        let pom = "<project><properties><v>1.0-socket.77777777</v><w>2</w></properties>\
                   <dependencies>\
                   <dependency><groupId>g</groupId><artifactId>a</artifactId><version>${v}</version></dependency>\
                   <dependency><groupId>g</groupId><artifactId>b</artifactId><version>${w}</version></dependency>\
                   <dependency><groupId>g</groupId><artifactId>c</artifactId><version>${u}</version></dependency>\
                   </dependencies></project>";
        let versions = |user: &[(&str, &str)]| {
            let user = user
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            super::parse_pom_with(pom, &user)
                .unwrap()
                .deps
                .into_iter()
                .map(|d| (d.version.unwrap(), d.build_version.unwrap()))
                .collect::<Vec<_>>()
        };
        let both = |v: &str| (v.to_string(), v.to_string());
        assert_eq!(
            versions(&[]),
            [both("1.0-socket.77777777"), both("2"), both("${u}")]
        );
        assert_eq!(
            versions(&[("v", "1.0"), ("u", "3")]),
            [
                ("1.0-socket.77777777".to_string(), "1.0".to_string()),
                both("2"),
                ("${u}".to_string(), "3".to_string()),
            ],
            "the build's user property wins over the pom's and defines one it lacks; \
             `version` keeps what the pom spells"
        );
    }

    /// Maven reads `${project.*}` / `${pom.*}` from the model before any
    /// user property: `-Dproject.version=` does not move a dependency
    /// version written through the model.
    #[test]
    fn model_reference_version_ignores_user_properties() {
        let pom = "<project><version>1</version><dependencies>\
                   <dependency><groupId>g</groupId><artifactId>a</artifactId><version>${project.version}</version></dependency>\
                   <dependency><groupId>g</groupId><artifactId>b</artifactId><version>${pom.version}</version></dependency>\
                   </dependencies></project>";
        let user = [
            ("project.version".to_string(), "9".to_string()),
            ("pom.version".to_string(), "9".to_string()),
        ]
        .into_iter()
        .collect();
        let deps = super::parse_pom_with(pom, &user).unwrap().deps;
        for d in &deps {
            assert_eq!(d.build_version, d.version, "{d:?}");
            assert!(
                d.build_version.as_deref().is_some_and(|v| v != "9"),
                "{d:?}"
            );
        }
    }

    /// A `${property}` version is interpolated through every property it
    /// names, user properties first at each level; a cycle, an undefined
    /// name or a chain deeper than [`super::MAX_INTERPOLATION_DEPTH`]
    /// leaves it as written.
    #[test]
    fn version_properties_resolve_recursively_and_fail_closed() {
        // (as the pom spells it, as the build resolves it)
        let both = |props: &str, user: &[(&str, &str)], text: &str| {
            let pom = format!(
                "<project><properties>{props}</properties><dependencies>\
                 <dependency><groupId>g</groupId><artifactId>a</artifactId>\
                 <version>{text}</version></dependency></dependencies></project>"
            );
            let user = user
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let dep = super::parse_pom_with(&pom, &user).unwrap().deps.remove(0);
            assert!(dep.version_alternatives.is_empty(), "{props}");
            (dep.version.unwrap(), dep.build_version.unwrap())
        };
        let version = |props: &str, user: &[(&str, &str)], text: &str| {
            let (spelled, built) = both(props, user, text);
            if user.is_empty() {
                assert_eq!(spelled, built, "{props}");
            }
            built
        };
        assert_eq!(
            both("<a>${b}</a><b>1.0</b>", &[("b", "2.0")], "${a}"),
            ("1.0".to_string(), "2.0".to_string()),
            "a nested user property moves the build's version, not the pom's"
        );
        // `<p0>${p1}</p0>` ... `<p{n-1}>1.0</p{n-1}>`.
        let chain = |n: usize| -> String {
            (0..n)
                .map(|i| match i + 1 == n {
                    true => format!("<p{i}>1.0</p{i}>"),
                    false => format!("<p{i}>${{p{}}}</p{i}>", i + 1),
                })
                .collect()
        };
        assert_eq!(
            version("<a>${b}</a><b>${c}</b><c>1.0</c>", &[], "${a}"),
            "1.0"
        );
        assert_eq!(
            version("<a>${b}</a><b>1.0</b>", &[("b", "2.0")], "${a}"),
            "2.0"
        );
        assert_eq!(version("<a>1</a><b>0</b>", &[], "${a}.${b}-x"), "1.0-x");
        assert_eq!(
            version("", &[], "${project.version}"),
            "${project.version}",
            "no project version here"
        );
        assert_eq!(version(&chain(16), &[], "${p0}"), "1.0");
        assert_eq!(version(&chain(17), &[], "${p0}"), "${p0}", "too deep");
        for cyclic in [
            "<a>${a}</a>",
            "<a>${b}</a><b>${a}</b>",
            "<a>x${b}</a><b>${a}y</b>",
        ] {
            assert_eq!(version(cyclic, &[], "${a}"), "${a}", "{cyclic}");
        }
        assert_eq!(version("<a>${b}</a>", &[], "${a}"), "${a}", "undefined");
        assert_eq!(version("<a>1</a>", &[], "${a"), "${a", "unterminated");
    }

    /// The versions a profile's `<properties>` may move a declaration to:
    /// every profile, and every set of profiles active together, counts; a
    /// declaration inside a profile reads that profile's own first; user
    /// properties and model references no profile can redefine.
    #[test]
    fn profile_properties_give_version_alternatives() {
        fn values(alternatives: Vec<super::Alternative>) -> Vec<String> {
            alternatives.into_iter().map(|a| a.value).collect()
        }
        let resolve = |props: &str, profiles: &[&str], user: &[(&str, &str)], deps: &str| {
            let profiles: String = profiles
                .iter()
                .map(|p| format!("<profile><properties>{p}</properties></profile>"))
                .collect();
            let pom = format!(
                "<project><version>9</version><properties>{props}</properties>\
                 <dependencies>{deps}</dependencies><profiles>{profiles}</profiles></project>"
            );
            let user = user
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            super::parse_pom_with(&pom, &user)
                .unwrap()
                .deps
                .into_iter()
                .map(|d| (d.build_version.unwrap(), values(d.version_alternatives)))
                .collect::<Vec<_>>()
        };
        let dep = |v: &str| {
            format!(
                "<dependency><groupId>g</groupId><artifactId>a</artifactId>\
                 <version>{v}</version></dependency>"
            )
        };
        let one = |props, profiles: &[&str], user: &[(&str, &str)]| {
            resolve(props, profiles, user, &dep("${v}")).remove(0)
        };
        let s = |v: &[&str]| v.iter().map(|v| v.to_string()).collect::<Vec<_>>();
        assert_eq!(one("<v>1</v>", &["<v>2</v>"], &[]), ("1".into(), s(&["2"])));
        assert_eq!(one("<v>1</v>", &["<v>1</v>"], &[]), ("1".into(), s(&[])));
        assert_eq!(one("<v>1</v>", &["<x>2</x>"], &[]), ("1".into(), s(&[])));
        assert_eq!(
            one("<v>${w}</v><w>1</w>", &["<w>2</w>", "<w>3</w>"], &[]),
            ("1".into(), s(&["2", "3"]))
        );
        // Two profiles that move it only together.
        assert_eq!(
            one("<v>1</v><w>1</w>", &["<v>${w}</v>", "<w>2</w>"], &[]),
            ("1".into(), s(&["2"]))
        );
        // A profile value this pom cannot resolve, or a cycle.
        assert_eq!(
            one("<v>1</v>", &["<v>${nope}</v>"], &[]),
            ("1".into(), s(&["${v}"]))
        );
        assert_eq!(
            one("<v>1</v>", &["<v>${v}</v>"], &[]),
            ("1".into(), s(&["${v}"]))
        );
        // User properties and model references win over every profile's.
        assert_eq!(
            one("<v>1</v>", &["<v>2</v>"], &[("v", "3")]),
            ("3".into(), s(&[]))
        );
        assert_eq!(
            resolve(
                "",
                &["<project.version>2</project.version>"],
                &[],
                &dep("${project.version}")
            )
            .remove(0),
            ("9".into(), s(&[]))
        );
        // More alternatives than are enumerated: unresolved.
        let many: Vec<String> = (0..17).map(|i| format!("<v>{i}</v>")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert_eq!(one("<v>x</v>", &many, &[]), ("x".into(), s(&["${v}"])));

        // A profile's own declaration reads its own properties first.
        let pom = format!(
            "<project><properties><v>1</v></properties><dependencies>{}</dependencies>\
             <profiles><profile><id>a</id><properties><v>2</v></properties>\
             <dependencies>{}</dependencies></profile>\
             <profile><id>b</id><properties><v>3</v></properties></profile></profiles></project>",
            dep("${v}"),
            dep("${v}")
        );
        let deps: Vec<_> = super::parse_pom(&pom)
            .unwrap()
            .deps
            .into_iter()
            .map(|d| {
                (
                    d.in_profile,
                    d.build_version.unwrap(),
                    d.version_alternatives,
                )
            })
            .collect();
        let moved = |value: &str, ids: &[&str]| super::Alternative {
            value: value.to_string(),
            by: super::MovedBy::Profiles(s(ids)),
        };
        assert_eq!(
            deps,
            [
                (
                    false,
                    "1".to_string(),
                    vec![moved("2", &["a"]), moved("3", &["b"])]
                ),
                (true, "2".to_string(), vec![moved("3", &["b"])]),
            ]
        );

        // `${project.version}` spelled through a property moves with it.
        let pom = format!(
            "<project><version>${{revision}}</version><properties><revision>1</revision>\
             </properties><dependencies>{}</dependencies><profiles><profile><id>ci</id>\
             <properties><revision>2</revision></properties></profile></profiles></project>",
            dep("${project.version}")
        );
        let user = [("revision".to_string(), "3".to_string())].into();
        for (user, built, alternatives) in [
            (BTreeMap::new(), "1", vec![moved("2", &["ci"])]),
            (user, "3", vec![]),
        ] {
            let d = super::parse_pom_with(&pom, &user).unwrap().deps.remove(0);
            assert_eq!(d.version.as_deref(), Some("1"));
            assert_eq!(d.build_version.as_deref(), Some(built));
            assert_eq!(d.version_alternatives, alternatives);
        }

        // An unreadable profile `<properties>` fails a `${…}` closed, and
        // only for the reader that weighs profiles.
        let pom = format!(
            "<project><properties><v>1</v></properties><dependencies>{}{}</dependencies>\
             <profiles><profile><properties><v>2</properties></profile></profiles></project>",
            dep("${v}"),
            dep("1")
        );
        assert!(PomScope::new(&pom).unwrap().dependencies().is_ok());
        let deps = super::parse_pom(&pom).unwrap().deps;
        assert!(matches!(
            deps[0].version_alternatives[..],
            [super::Alternative {
                by: super::MovedBy::Unreadable(_),
                ..
            }]
        ));
        assert!(deps[1].version_alternatives.is_empty());
    }

    /// The shared interpolator's work bounds: a value naming the next
    /// property many times over fails instead of growing exponentially.
    #[test]
    fn interpolation_is_bounded() {
        let props: std::collections::BTreeMap<String, String> = (0..12)
            .map(|i| (format!("p{i}"), format!("${{p{}}}", i + 1).repeat(8)))
            .chain([("p12".to_string(), "x".to_string())])
            .collect();
        let lookup = |name: &str| props.get(name).cloned();
        assert_eq!(super::interpolate_strict("${p0}", &lookup), None);
        assert_eq!(
            super::interpolate_strict("${p11}", &lookup).as_deref(),
            Some("xxxxxxxx")
        );
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
