//! What a Maven project says about the Maven that builds it (the model its
//! root pom declares, the release its Maven Wrapper pins), and the property
//! a `.mvn/maven.config` line has to name the project's root directory
//! through on that Maven. Pure: text in, verdict out.
//!
//! Every reader of "is this a Maven 4 project" goes through here, so the
//! hosted rewriter, its unwind, discovery and the vendored planner cannot
//! answer differently for one pom.

use crate::formats::xml;

/// The model version a pom declares, as Maven reads it: its
/// `<modelVersion>` (`model_version`, the element's text) when it has one,
/// else the version its namespace names (`project_tag`, the `<project …>`
/// open tag: `xmlns="http://maven.apache.org/POM/4.1.0"`).
///
/// Measured on Maven 3.9.9 and 4.0.0-rc-7:
/// * `<modelVersion>4.0.0</modelVersion>` under the 4.1.0 namespace is a
///   4.0.0 pom. Maven 3 never looks at the namespace and builds it; Maven 4
///   does not discover its subprojects.
/// * A pom with no `<modelVersion>` takes the namespace's version on
///   Maven 4 (under the 4.1.0 namespace it discovers subprojects; under the
///   4.0.0 one it does not). Maven 3 reads no pom without the element.
/// * `<modelVersion>4.1.0</modelVersion>` is a 4.1.0 pom whatever the
///   namespace says, and Maven 3 refuses it.
pub(crate) fn model_version_of(model_version: Option<&str>, project_tag: &str) -> Option<String> {
    let declared = model_version.map(str::trim).filter(|v| !v.is_empty());
    let version = match declared {
        Some(version) => version,
        None => {
            let namespace = xml::attr(project_tag, "xmlns")?;
            let (_, version) = namespace.rsplit_once(POM_NAMESPACE)?;
            version
        }
    };
    Some(version.to_string())
}

/// What a pom's namespace ends in ahead of its version.
const POM_NAMESPACE: &str = "maven.apache.org/POM/";

/// [`model_version_of`] a pom's text. `None` for a pom that declares no
/// model either way, or that does not scan.
pub(crate) fn pom_model_version(pom: &str) -> Option<String> {
    let text = xml::blank_non_markup(pom).ok()?;
    let project = *xml::elements(&text, "project").ok()?.first()?;
    let model = xml::children(&text, &project, "modelVersion")
        .ok()
        .and_then(|found| found.first().map(|e| e.inner(&text)));
    model_version_of(model, project.open_tag(&text))
}

/// Whether `version` names a model newer than 4.0.0: one only Maven 4
/// reads (4.1.0 today).
pub(crate) fn is_maven_4_model(version: &str) -> bool {
    let mut parts = version.split('.').map(str::parse::<u32>);
    matches!(
        (parts.next(), parts.next()),
        (Some(Ok(major)), Some(Ok(minor))) if (major, minor) > (4, 0)
    )
}

/// The Apache Maven release a `maven-wrapper.properties` pins, taken from its
/// `distributionUrl` (`…/apache-maven-<version>-bin.zip` or `.tar.gz`). None
/// for a missing key or any other distribution (e.g. mvnd).
pub(crate) fn wrapper_maven_version(props: &str) -> Option<String> {
    props.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with('!') {
            return None;
        }
        let rest = line.strip_prefix("distributionUrl")?;
        if !rest.starts_with(|c: char| c == '=' || c == ':' || c.is_whitespace()) {
            return None;
        }
        let value = rest
            .trim_start()
            .strip_prefix(['=', ':'])
            .unwrap_or(rest)
            .trim();
        let file = value.rsplit('/').next()?;
        let version = file
            .strip_prefix("apache-maven-")?
            .strip_suffix(".zip")
            .or_else(|| file.strip_prefix("apache-maven-")?.strip_suffix(".tar.gz"))?
            .strip_suffix("-bin")?;
        (!version.is_empty()).then(|| version.to_string())
    })
}

/// `[major, minor, patch]` of a Maven version (a pre-release suffix such as
/// `-rc-6` compares as its release).
pub(crate) fn release(version: &str) -> [u32; 3] {
    let mut parts = [0u32; 3];
    for (slot, part) in parts.iter_mut().zip(version.split(['.', '-'])) {
        *slot = part.parse().unwrap_or(0);
    }
    parts
}

/// The Maven a project declares: the two things in a checkout that name
/// one. Nothing else does (a Maven on the `PATH` is not the project's), so
/// a project with neither says nothing about its Maven.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct DeclaredMaven {
    /// The Apache Maven release the Maven Wrapper pins.
    release: Option<String>,
    /// The root pom is of a model only Maven 4 reads
    /// ([`is_maven_4_model`]).
    maven_4_model: bool,
}

impl DeclaredMaven {
    /// Read from the Maven Wrapper's properties file (`wrapper`) and the
    /// root pom (`root_pom`), either of which may be absent.
    pub(crate) fn of(wrapper: Option<&str>, root_pom: Option<&str>) -> DeclaredMaven {
        DeclaredMaven {
            release: wrapper.and_then(wrapper_maven_version),
            maven_4_model: root_pom
                .and_then(pom_model_version)
                .is_some_and(|version| is_maven_4_model(&version)),
        }
    }

    /// The release the Maven Wrapper pins, when it names an Apache Maven.
    pub(crate) fn release(&self) -> Option<&str> {
        self.release.as_deref()
    }

    /// Whether the root pom is of a model only Maven 4 reads.
    pub(crate) fn maven_4_model(&self) -> bool {
        self.maven_4_model
    }

    /// Whether the project declares Maven 4: its wrapper pins Apache Maven
    /// 4 or later, or its root pom is of a model only Maven 4 reads (then a
    /// wrapper pinning Maven 3 cannot build the project, and whatever does
    /// is a Maven 4).
    pub(crate) fn is_maven_4(&self) -> bool {
        self.maven_4_model
            || self
                .release()
                .is_some_and(|version| release(version)[0] >= 4)
    }
}

/// The property a `.mvn/maven.config` line names the project's root
/// directory through. No property is right on every Maven. Measured with
/// real Maven (3.6.3, 3.8.9, 3.9.0, 3.9.2 to 3.9.9, 3.9.16, 4.0.0-rc-7),
/// from the project root, from a module directory and with
/// `-f <project>/pom.xml` from outside the project:
///
/// * `${session.rootDirectory}` is undefined on Maven 3.9.2 to 3.9.8 when
///   the build is started with `-f` from outside the project, and Maven
///   then does not start at all (`Illegal use of undefined property:
///   session.rootDirectory`). From 3.9.9 on, and on Maven 4, it is defined
///   in every invocation. Before 3.9.2 it is not interpolated.
/// * `${maven.multiModuleProjectDirectory}` is defined by every Maven 3
///   launcher in every invocation, so it breaks no build. Maven 4 does not
///   interpolate it: a line that uses it names no directory there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootDirectory {
    /// `${maven.multiModuleProjectDirectory}`: breaks no build. The
    /// property for every project that does not declare Maven 4.
    Launcher,
    /// `${session.rootDirectory}`: the property for a project that declares
    /// Maven 4, the only Maven that needs it.
    Session,
}

// The two properties as literals, so a setting that embeds one can be a
// `const` (`concat!`) and still cannot drift from [`RootDirectory`].
macro_rules! launcher_root {
    () => {
        "${maven.multiModuleProjectDirectory}"
    };
}
macro_rules! session_root {
    () => {
        "${session.rootDirectory}"
    };
}
pub(crate) use {launcher_root, session_root};

impl RootDirectory {
    /// The property, as `maven.config` spells it.
    pub(crate) const fn property(self) -> &'static str {
        match self {
            RootDirectory::Launcher => launcher_root!(),
            RootDirectory::Session => session_root!(),
        }
    }

    /// The other property.
    pub(crate) const fn other(self) -> RootDirectory {
        match self {
            RootDirectory::Launcher => RootDirectory::Session,
            RootDirectory::Session => RootDirectory::Launcher,
        }
    }

    /// The property for a project that declares `maven`:
    /// [`RootDirectory::Session`] when it declares Maven 4
    /// ([`DeclaredMaven::is_maven_4`]), else [`RootDirectory::Launcher`],
    /// which breaks no build.
    pub(crate) fn for_maven(maven: &DeclaredMaven) -> RootDirectory {
        if maven.is_maven_4() {
            RootDirectory::Session
        } else {
            RootDirectory::Launcher
        }
    }

    /// Whether the Maven the project declares is known not to interpolate
    /// this property: only [`RootDirectory::Launcher`] in a project that
    /// declares Maven 4. (A Maven too old to interpolate either is not a
    /// difference between the two.)
    pub(crate) fn unread_by(self, maven: &DeclaredMaven) -> bool {
        self == RootDirectory::Launcher && maven.is_maven_4()
    }

    /// What the Maven the project declares (`maven`) makes of a
    /// `.mvn/maven.config` line that names a directory of the checkout
    /// through this property, for a setting Maven acts on from the release
    /// `since` on. The one answer for every such line hosted mode writes:
    /// the Trusted Checksums directory and the repository filter's.
    pub(crate) fn read_by(self, maven: &DeclaredMaven, since: [u32; 3]) -> Reads {
        // A wrapper that pins a Maven 3 cannot build a pom only Maven 4
        // reads, so its release then says nothing about the Maven that does.
        if let Some(version) = maven.release().filter(|_| !maven.maven_4_model()) {
            if release(version) < since {
                return Reads::TooOld(version.to_string());
            }
        }
        if self.unread_by(maven) {
            Reads::UnreadByMaven4
        } else if self == RootDirectory::Launcher && maven.release().is_none() {
            Reads::Maven3Only
        } else {
            Reads::Read
        }
    }
}

/// What the Maven a project declares makes of a `.mvn/maven.config` line
/// that names a directory of the checkout through a root-directory property
/// ([`RootDirectory::read_by`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reads {
    /// The Maven Wrapper pins this Apache Maven release, which is older
    /// than the first that acts on the setting.
    TooOld(String),
    /// The project declares Maven 4 and the line names the directory
    /// through [`RootDirectory::Launcher`], which Maven 4 does not
    /// interpolate.
    UnreadByMaven4,
    /// The project declares no Maven and the line names the directory
    /// through [`RootDirectory::Launcher`]: Maven 3 reads it, a Maven 4
    /// build does not, and nothing in the checkout says which builds it.
    Maven3Only,
    /// The Maven the project declares reads the line; or it declares none,
    /// and the line is spelled so that every Maven that acts on the
    /// setting at all finds the directory.
    Read,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pom(namespace: Option<&str>, model: Option<&str>) -> String {
        let xmlns = namespace.map_or(String::new(), |v| {
            format!(" xmlns=\"http://maven.apache.org/POM/{v}\"")
        });
        let model = model.map_or(String::new(), |v| {
            format!("  <modelVersion>{v}</modelVersion>\n")
        });
        format!(
            "<project{xmlns}>\n{model}  <groupId>g</groupId>\n  <artifactId>a</artifactId>\n  \
             <version>1</version>\n</project>\n"
        )
    }

    /// The cells measured on Maven 3.9.9 and 4.0.0-rc-7 (see
    /// [`model_version_of`]).
    #[test]
    fn the_model_is_the_model_version_else_the_namespace() {
        for (namespace, model, want) in [
            (Some("4.0.0"), Some("4.0.0"), Some("4.0.0")),
            // A 4.0.0 model under the 4.1.0 namespace: Maven 3 builds it.
            (Some("4.1.0"), Some("4.0.0"), Some("4.0.0")),
            (Some("4.1.0"), Some("4.1.0"), Some("4.1.0")),
            (Some("4.0.0"), Some("4.1.0"), Some("4.1.0")),
            (None, Some("4.1.0"), Some("4.1.0")),
            // No <modelVersion>: the namespace's version.
            (Some("4.1.0"), None, Some("4.1.0")),
            (Some("4.0.0"), None, Some("4.0.0")),
            (None, None, None),
        ] {
            assert_eq!(
                pom_model_version(&pom(namespace, model)).as_deref(),
                want,
                "{namespace:?} {model:?}"
            );
        }
        // An empty element is no declaration; a commented-out one is none.
        let empty = pom(Some("4.1.0"), Some(" "));
        assert_eq!(pom_model_version(&empty).as_deref(), Some("4.1.0"));
        let commented = pom(Some("4.0.0"), None).replace(
            "  <groupId>",
            "  <!-- <modelVersion>4.1.0</modelVersion> -->\n  <groupId>",
        );
        assert_eq!(pom_model_version(&commented).as_deref(), Some("4.0.0"));
        // Another attribute that names the namespace is not the namespace.
        let schema_only = "<project xsi:schemaLocation=\"http://maven.apache.org/POM/4.1.0 \
                           https://maven.apache.org/xsd/maven-4.1.0.xsd\">\n</project>\n";
        assert_eq!(pom_model_version(schema_only), None);
        assert_eq!(pom_model_version("not a pom"), None);
    }

    #[test]
    fn only_a_model_newer_than_4_0_0_needs_maven_4() {
        for (version, want) in [
            ("4.0.0", false),
            ("4.1.0", true),
            ("4.2.0", true),
            ("5.0.0", true),
            ("4.0", false),
            ("3.0.0", false),
            ("", false),
            ("four", false),
        ] {
            assert_eq!(is_maven_4_model(version), want, "{version}");
        }
    }

    fn wrapper(version: &str) -> String {
        format!(
            "distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/\
             {version}/apache-maven-{version}-bin.zip\n"
        )
    }

    /// The `distributionUrl` parse: escaped or plain `:`, `=`/`:`/space
    /// separators, `.tar.gz` distributions, comments and CRLF.
    #[test]
    fn the_wrapper_release_is_parsed_from_the_distribution_url() {
        let escaped = "# Licensed to the Apache Software Foundation (ASF)\nwrapperVersion=3.3.2\n\
                       distributionType=only-script\ndistributionUrl=https\\://repo.maven.apache.org/\
                       maven2/org/apache/maven/apache-maven/3.9.3/apache-maven-3.9.3-bin.zip\n";
        assert_eq!(wrapper_maven_version(escaped).as_deref(), Some("3.9.3"));
        assert_eq!(
            wrapper_maven_version(
                "distributionUrl : https://archive.apache.org/dist/maven/maven-3/3.9.2/binaries/\
                 apache-maven-3.9.2-bin.tar.gz\r\n"
            )
            .as_deref(),
            Some("3.9.2")
        );
        assert_eq!(
            wrapper_maven_version(
                "! comment\r\ndistributionUrl=https\\://repo/apache-maven-4.0.0-rc-6-bin.zip\r\n"
            )
            .as_deref(),
            Some("4.0.0-rc-6")
        );
        assert_eq!(wrapper_maven_version("wrapperVersion=3.3.2\n"), None);
        assert_eq!(
            wrapper_maven_version("distributionUrlOld=https://x/apache-maven-3.9.3-bin.zip\n"),
            None
        );
        assert_eq!(
            wrapper_maven_version(
                "# distributionUrl=https\\://x/apache-maven/3.9.3/apache-maven-3.9.3-bin.zip\n"
            ),
            None
        );
        assert_eq!(release("3.9.16"), [3, 9, 16]);
        assert_eq!(release("4.0.0-rc-7"), [4, 0, 0]);
        assert_eq!(release("3.10"), [3, 10, 0]);
    }

    #[test]
    fn a_project_declares_maven_4_by_its_wrapper_or_its_model() {
        let declared = |wrapper: Option<&str>, pom: Option<&str>| DeclaredMaven::of(wrapper, pom);
        let nothing = declared(None, None);
        assert_eq!(nothing, DeclaredMaven::default());
        assert!(!nothing.is_maven_4());
        assert_eq!(nothing.release(), None);

        let maven_3 = declared(
            Some(&wrapper("3.9.9")),
            Some(&pom(Some("4.0.0"), Some("4.0.0"))),
        );
        assert_eq!(maven_3.release(), Some("3.9.9"));
        assert!(!maven_3.is_maven_4());

        for version in ["4.0.0", "4.0.0-rc-7", "4.1.2", "5.0.0"] {
            assert!(
                declared(Some(&wrapper(version)), None).is_maven_4(),
                "{version}"
            );
        }
        // The model alone, with no wrapper or under one that pins Maven 3.
        let model = pom(Some("4.1.0"), Some("4.1.0"));
        assert!(declared(None, Some(&model)).is_maven_4());
        assert!(declared(Some(&wrapper("3.9.9")), Some(&model)).is_maven_4());
        assert!(declared(None, Some(&pom(Some("4.1.0"), None))).is_maven_4());
        // A 4.0.0 model under the 4.1.0 namespace is a pom Maven 3 builds.
        assert!(!declared(None, Some(&pom(Some("4.1.0"), Some("4.0.0")))).is_maven_4());
        // Another distribution names no Apache Maven release.
        let mvnd = "distributionUrl=https://example.test/maven-mvnd-1.0.2-bin.zip\n";
        assert_eq!(declared(Some(mvnd), None), DeclaredMaven::default());
    }

    #[test]
    fn the_root_directory_property_follows_the_declared_maven() {
        use RootDirectory::{Launcher, Session};
        let maven_4 = DeclaredMaven::of(Some(&wrapper("4.0.0")), None);
        let maven_3 = DeclaredMaven::of(Some(&wrapper("3.9.9")), None);
        let unknown = DeclaredMaven::default();
        assert_eq!(RootDirectory::for_maven(&maven_4), Session);
        assert_eq!(RootDirectory::for_maven(&maven_3), Launcher);
        assert_eq!(RootDirectory::for_maven(&unknown), Launcher);
        assert_eq!(Launcher.property(), "${maven.multiModuleProjectDirectory}");
        assert_eq!(Session.property(), "${session.rootDirectory}");
        assert_eq!(Launcher.other(), Session);
        assert_eq!(Session.other(), Launcher);
        // Only the launcher's property is unread, and only by Maven 4.
        assert!(Launcher.unread_by(&maven_4));
        assert!(!Session.unread_by(&maven_4));
        for maven in [&maven_3, &unknown] {
            assert!(!Launcher.unread_by(maven));
            assert!(!Session.unread_by(maven));
        }
    }
}
