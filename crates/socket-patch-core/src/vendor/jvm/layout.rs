//! The one place JVM layout facts are spelled: where a GAV lives in a
//! maven2 tree, which coordinates may be joined onto a path, the committed
//! vendor trees and their marker, the ledger name of a JVM entry, and the
//! files that make a directory a JVM build.
//!
//! Every crawler, planner, verifier and redirect that needs one of these
//! asks this module, so a layout rule cannot drift between the copies.

use std::path::{Path, PathBuf};

use crate::patch::path_safety;

// ── maven2 repository layout ────────────────────────────────────────────

/// A dotted groupId as maven2 path segments: `org.apache.commons` →
/// `org/apache/commons`. Run only on coordinates that passed
/// [`is_path_safe`] (or [`safe_coordinates`]).
pub fn group_path(group_id: &str) -> String {
    group_id.replace('.', "/")
}

/// A GAV's version directory, relative to a maven2 root:
/// `<group/path>/<artifact>/<version>`.
pub fn version_dir(group_id: &str, artifact_id: &str, version: &str) -> String {
    format!("{}/{artifact_id}/{version}", group_path(group_id))
}

/// [`version_dir`] joined onto `root`, one component per level (so the
/// group keeps the platform separator the caller's root uses below it).
pub fn version_dir_path(root: &Path, group_id: &str, artifact_id: &str, version: &str) -> PathBuf {
    root.join(group_path(group_id))
        .join(artifact_id)
        .join(version)
}

/// An artifact's file name: `<artifact>-<version>[-<classifier>].<ext>`.
pub fn file_name(artifact_id: &str, version: &str, classifier: Option<&str>, ext: &str) -> String {
    match classifier {
        Some(c) => format!("{artifact_id}-{version}-{c}.{ext}"),
        None => format!("{artifact_id}-{version}.{ext}"),
    }
}

/// An artifact's path, relative to a maven2 root:
/// `<group/path>/<artifact>/<version>/<file name>`.
pub fn artifact_path(
    group_id: &str,
    artifact_id: &str,
    version: &str,
    classifier: Option<&str>,
    ext: &str,
) -> String {
    format!(
        "{}/{}",
        version_dir(group_id, artifact_id, version),
        file_name(artifact_id, version, classifier, ext)
    )
}

/// The maven2 registry upstream artifacts are fetched and verified from,
/// overridable with `SOCKET_MAVEN_REGISTRY` (the private-mirror / test
/// escape hatch). Default is Maven Central's maven2 endpoint.
pub fn registry_base() -> String {
    std::env::var("SOCKET_MAVEN_REGISTRY")
        .ok()
        .map(|v| v.trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "https://repo1.maven.org/maven2".to_string())
}

/// The [`registry_base`] URL of an artifact.
pub fn registry_url(
    group_id: &str,
    artifact_id: &str,
    version: &str,
    classifier: Option<&str>,
    ext: &str,
) -> String {
    format!(
        "{}/{}",
        registry_base(),
        artifact_path(group_id, artifact_id, version, classifier, ext)
    )
}

// ── coordinates ─────────────────────────────────────────────────────────

/// Whether untrusted coordinates are safe to join onto a maven2 root (the
/// path guard every crawler and the single-pom backend apply). Fails
/// closed.
///
/// - `artifact_id` and `version` are each a single path segment, so a real
///   one never contains a separator, a `.`/`..` segment, a backslash, a
///   colon, or a NUL — [`path_safety::is_safe_single_segment`].
/// - `group_id` is dot-separated and run through [`group_path`] (each `.`
///   becomes `/`), so every dot-split segment must independently satisfy
///   [`path_safety::is_safe_single_segment`]. That rejects the forms that
///   would convert to an absolute or `..`-bearing path (`.` -> `/`, `.a` ->
///   `/a`, `a..b` -> `a//b`) and a `/` smuggled inside a dot-split segment
///   (`/etc`, `com/evil`).
///
/// The delegation also rejects `:` everywhere — a Windows drive-relative
/// coordinate (`C:evil`) joins as an absolute path.
pub fn is_path_safe(group_id: &str, artifact_id: &str, version: &str) -> bool {
    group_id.split('.').all(path_safety::is_safe_single_segment)
        && path_safety::is_safe_single_segment(artifact_id)
        && path_safety::is_safe_single_segment(version)
}

/// The stricter grammar of the v5 JVM backend: coordinates that every file
/// it writes (Gradle scripts, XML comments, the sbt file, the index rows)
/// accepts unescaped. g is dot-separated `[A-Za-z0-9_-]` segments, a is
/// `[A-Za-z0-9_.-]`, v is `[A-Za-z0-9_.+-]` not ending in `+` nor starting
/// with `latest.`; neither a nor v is all dots, and none holds `--` (it
/// ends an XML comment). The single-pom backend writes none of those, so
/// it keeps [`is_path_safe`] only.
pub fn safe_coordinates(g: &str, a: &str, v: &str) -> bool {
    let seg = |s: &str, extra: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "_-".contains(c) || extra.contains(c))
    };
    g.split('.').all(|s| seg(s, ""))
        && seg(a, ".")
        && seg(v, ".+")
        && !a.chars().all(|c| c == '.')
        && !v.chars().all(|c| c == '.')
        && !v.ends_with('+')
        && !v.starts_with("latest.")
        && ![g, a, v].iter().any(|s| s.contains("--"))
}

// ── committed vendor trees ──────────────────────────────────────────────

/// The reactor's (and the sbt build's) suffixed maven2 tree.
pub const MAVEN2_TREE: &str = ".socket/vendor/maven2";
/// The Gradle-only artifact tree.
pub const GRADLE_TREE: &str = ".socket/vendor/gradle";
/// The scala-cli Coursier tree.
pub const COURSIER_TREE: &str = ".socket/vendor/coursier";
/// Every vendored repository tree JVM entries write under `.socket/vendor`.
pub const VENDOR_TREES: &[&str] = &[MAVEN2_TREE, GRADLE_TREE, COURSIER_TREE];
/// The per-version marker every tree (and every `<eco>/<uuid>` unit) holds.
pub(crate) use crate::vendor::state::VENDOR_MARKER_FILE as MARKER_FILE;

/// Paths whose presence without a vendor ledger means JVM artifacts were
/// orphaned (`vendor --check`'s `vendor_ledger_missing`).
pub const ORPHAN_PATHS: &[&str] = &[
    MAVEN2_TREE,
    GRADLE_TREE,
    super::gradle::INDEX_REL,
    super::sbt::BUILD_FILE,
    COURSIER_TREE,
    super::coursier_tree::INDEX_REL,
];

/// The JVM backend's files under `.socket/` a group commit captures.
pub const CAPTURED_FILES: &[&str] = &[
    super::gradle::INDEX_REL,
    super::gradle::SCRIPT_REL,
    super::maven_reactor::GITATTRIBUTES_REL,
    super::gradle::GITATTRIBUTES_REL,
    super::coursier_tree::INDEX_REL,
    super::coursier_tree::GITIGNORE_REL,
    super::coursier_tree::GITATTRIBUTES_REL,
    super::scala_cli::GUARD_REL,
    super::sbt::TREE_GITIGNORE_REL,
];

/// A tree's version directory: `<tree>/<group/path>/<artifact>/<version>`.
pub fn tree_dir(tree: &str, group_id: &str, artifact_id: &str, version: &str) -> String {
    format!("{tree}/{}", version_dir(group_id, artifact_id, version))
}

/// The columns of a tree index row (`<g:a:v>\t<rel>\t<sha256>\t<uuid>`)
/// whose GAV passes [`safe_coordinates`], whose `rel` is a file directly in
/// that GAV's version directory and named after it, and whose sha256 is 64
/// lowercase hex. The uuid column is returned unchecked: each index applies
/// its own rule.
pub(crate) fn index_row(row: &str) -> Option<[&str; 4]> {
    let cols: Vec<&str> = row.split('\t').collect();
    let [gav, rel, sha, uuid] = cols.as_slice() else {
        return None;
    };
    let parts: Vec<&str> = gav.split(':').collect();
    let [g, a, v] = parts.as_slice() else {
        return None;
    };
    let dir = format!("{}/", version_dir(g, a, v));
    let ok = safe_coordinates(g, a, v)
        && rel
            .strip_prefix(&dir)
            .is_some_and(|n| n.starts_with(&format!("{a}-{v}")) && !n.contains('/'))
        && crate::utils::digest::is_hex64_lower(sha);
    ok.then_some([*gav, *rel, *sha, *uuid])
}

// ── ledger ──────────────────────────────────────────────────────────────

/// The ledger ecosystem of every v5 JVM-backend entry (the single-pom
/// backend records `maven`).
pub const LEDGER_ECOSYSTEM: &str = "jvm";

/// The package ecosystem a vendor-ledger entry's name stands for: a
/// [`LEDGER_ECOSYSTEM`] entry is a `maven` package (its purl, its
/// `--ecosystems` name, its revert backend); every other name is itself.
pub fn ledger_ecosystem(eco: &str) -> &str {
    if eco == LEDGER_ECOSYSTEM {
        "maven"
    } else {
        eco
    }
}

// ── build markers ───────────────────────────────────────────────────────

/// Maven's project file.
pub const POM_FILE: &str = "pom.xml";
/// Gradle's root scripts, settings first.
pub const GRADLE_ROOT_FILES: &[&str] = &[
    "settings.gradle",
    "settings.gradle.kts",
    "build.gradle",
    "build.gradle.kts",
];
/// Gradle's settings scripts: Groovy, then Kotlin (indexed by
/// `usize::from(kotlin)`).
pub const GRADLE_SETTINGS_FILES: &[&str] = &[GRADLE_ROOT_FILES[0], GRADLE_ROOT_FILES[1]];
/// Whether a `/`-separated path names a Gradle settings script (by its
/// basename, at any depth).
pub fn is_gradle_settings(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    GRADLE_SETTINGS_FILES.contains(&name)
}
/// Gradle's build scripts.
pub const GRADLE_BUILD_FILES: &[&str] = &[GRADLE_ROOT_FILES[2], GRADLE_ROOT_FILES[3]];
/// Mill's build files.
pub const MILL_BUILD_FILES: &[&str] = &["build.mill", "build.mill.yaml", "build.sc"];
/// Mill's version pin: a Mill marker for hosted guidance and build
/// ambiguity, but no build file of its own.
pub const MILL_VERSION_FILE: &str = ".mill-version";
/// [`MILL_BUILD_FILES`] and [`MILL_VERSION_FILE`].
pub const MILL_MARKERS: &[&str] = &[
    MILL_BUILD_FILES[0],
    MILL_BUILD_FILES[1],
    MILL_BUILD_FILES[2],
    MILL_VERSION_FILE,
];
/// A scala-cli directory build's project file.
pub const SCALA_CLI_FILE: &str = "project.scala";
/// scala-cli's build output directory.
pub const SCALA_CLI_DIR: &str = ".scala-build";

use crate::formats::sbt::build::{BUILD_PROPERTIES as SBT_BUILD_PROPERTIES, BUILD_SBT};

/// The basenames that make a directory a JVM project root wherever a
/// marker is matched by name alone (root detection on disk and in memory).
/// `project/build.properties` and `.scala-build` are no basename markers:
/// `build.properties` alone is too generic a name, and a directory is no
/// file a lock-less root is detected by.
pub const JVM_PROJECT_MARKERS: &[&str] = &[
    POM_FILE,
    GRADLE_ROOT_FILES[0],
    GRADLE_ROOT_FILES[1],
    GRADLE_ROOT_FILES[2],
    GRADLE_ROOT_FILES[3],
    BUILD_SBT,
    MILL_BUILD_FILES[0],
    MILL_BUILD_FILES[1],
    MILL_BUILD_FILES[2],
    SCALA_CLI_FILE,
];

/// A JVM build tool, by the files that mark its build root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BuildTool {
    Maven,
    Gradle,
    Sbt,
    Mill,
    ScalaCli,
}

impl BuildTool {
    pub const ALL: [BuildTool; 5] = [
        BuildTool::Maven,
        BuildTool::Gradle,
        BuildTool::Sbt,
        BuildTool::Mill,
        BuildTool::ScalaCli,
    ];

    /// The root-relative paths whose presence marks this tool's build.
    pub fn markers(self) -> &'static [&'static str] {
        match self {
            BuildTool::Maven => &[POM_FILE],
            BuildTool::Gradle => GRADLE_ROOT_FILES,
            BuildTool::Sbt => &[BUILD_SBT, SBT_BUILD_PROPERTIES],
            BuildTool::Mill => MILL_BUILD_FILES,
            BuildTool::ScalaCli => &[SCALA_CLI_FILE, SCALA_CLI_DIR],
        }
    }

    /// sbt, Mill and scala-cli resolve into the Coursier / Ivy caches.
    pub fn is_scala_tool(self) -> bool {
        matches!(self, BuildTool::Sbt | BuildTool::Mill | BuildTool::ScalaCli)
    }
}

/// The one stat rule every disk-side build-marker check applies: the path
/// exists, following symlinks (a file, or for `.scala-build` a directory).
/// So a directory named like a build file counts, and a dangling symlink
/// does not. (`scan`'s policy root markers keep `is_file`, the rule they
/// share with the non-JVM manifests they are listed beside.)
pub fn marker_present(dir: &Path, rel: &str) -> bool {
    std::fs::metadata(dir.join(rel)).is_ok()
}

/// Whether `dir` holds a `tool` build marker.
pub fn has_build(dir: &Path, tool: BuildTool) -> bool {
    tool.markers().iter().any(|m| marker_present(dir, m))
}

/// Whether `dir` holds any JVM build marker.
pub fn is_jvm_build(dir: &Path) -> bool {
    BuildTool::ALL.iter().any(|t| has_build(dir, *t))
}

/// Whether `dir` is an sbt, Mill or scala-cli build.
pub fn is_scala_tool_build(dir: &Path) -> bool {
    BuildTool::ALL
        .iter()
        .filter(|t| t.is_scala_tool())
        .any(|t| has_build(dir, *t))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maven2_paths() {
        assert_eq!(group_path("org.apache.commons"), "org/apache/commons");
        assert_eq!(group_path("single"), "single");
        assert_eq!(version_dir("org.example", "a", "1.0"), "org/example/a/1.0");
        assert_eq!(file_name("a", "1.0", None, "jar"), "a-1.0.jar");
        assert_eq!(
            file_name("a", "1.0", Some("sources"), "jar"),
            "a-1.0-sources.jar"
        );
        assert_eq!(
            artifact_path("org.example", "a", "1.0", Some("tests"), "jar"),
            "org/example/a/1.0/a-1.0-tests.jar"
        );
        assert_eq!(
            tree_dir(GRADLE_TREE, "org.example", "a", "1.0"),
            ".socket/vendor/gradle/org/example/a/1.0"
        );
        assert_eq!(
            version_dir_path(Path::new("/r"), "org.example", "a", "1.0"),
            Path::new("/r").join("org/example").join("a").join("1.0")
        );
    }

    #[test]
    fn path_safe_coordinates() {
        // Legit coordinates pass.
        assert!(is_path_safe(
            "org.apache.commons",
            "commons-lang3",
            "3.12.0"
        ));
        assert!(is_path_safe("com.google.guava", "guava", "32.1.3-jre"));
        // `..` in any single-segment coordinate is rejected.
        assert!(!is_path_safe("g", "..", "1.0.0"));
        assert!(!is_path_safe("g", "../../escaped", "1.0.0"));
        assert!(!is_path_safe("g", "a", ".."));
        // A `/` in the artifactId/version (never legitimate) is rejected.
        assert!(!is_path_safe("g", "a/b", "1.0.0"));
        assert!(!is_path_safe("g", "a", "1/0"));
        // groupId forms that convert to an absolute or empty-segment path
        // (`.` -> `/`, `.a` -> `/a`) are rejected.
        assert!(!is_path_safe(".", "a", "1.0.0"));
        assert!(!is_path_safe("..", "a", "1.0.0"));
        assert!(!is_path_safe(".org", "a", "1.0.0"));
        assert!(!is_path_safe("org.", "a", "1.0.0"));
        assert!(!is_path_safe("a..b", "a", "1.0.0"));
        // Backslash / NUL anywhere is rejected.
        assert!(!is_path_safe("g", "a\\b", "1.0.0"));
        assert!(!is_path_safe("g\0x", "a", "1.0.0"));
        // Empty coordinates are rejected.
        assert!(!is_path_safe("", "a", "1.0.0"));
        assert!(!is_path_safe("g", "", "1.0.0"));
        assert!(!is_path_safe("g", "a", ""));
        // Windows drive-relative escape: a `:` (e.g. `C:evil`) makes the
        // joined path absolute under `Path::join`; rejected in every
        // coordinate, including inside a dot-split groupId segment.
        assert!(!is_path_safe("C:evil.org", "a", "1.0.0"));
        assert!(!is_path_safe("g", "C:evil", "1.0.0"));
        assert!(!is_path_safe("g", "a", "C:1.0.0"));
        // A `/` smuggled inside a dot-split groupId segment never hits the
        // per-dot-segment checks (`/etc` has no dots at all) but converts to
        // an absolute or deeper path via `group_path`.
        assert!(!is_path_safe("/etc", "a", "1.0.0"));
        assert!(!is_path_safe("com/evil", "a", "1.0.0"));
    }

    #[test]
    fn strict_coordinates_are_path_safe() {
        for (g, a, v) in [
            ("org.example", "a", "1.0"),
            ("com.google.guava", "guava", "32.1.3-jre"),
            ("x", "y.z", "1+build"),
        ] {
            assert!(
                safe_coordinates(g, a, v) && is_path_safe(g, a, v),
                "{g}:{a}:{v}"
            );
        }
        for (g, a, v) in [
            ("org..x", "a", "1"),
            ("org", "..", "1"),
            ("org", "a", "C:x"),
        ] {
            assert!(
                !safe_coordinates(g, a, v) && !is_path_safe(g, a, v),
                "{g}:{a}:{v}"
            );
        }
        // Path-safe but not writable unescaped.
        assert!(is_path_safe("org", "a", "1--x") && !safe_coordinates("org", "a", "1--x"));
    }

    #[test]
    fn index_rows() {
        let sha = "a".repeat(64);
        let row = format!("org.example:a:1.0\torg/example/a/1.0/a-1.0.jar\t{sha}\tu");
        assert_eq!(
            index_row(&row),
            Some([
                "org.example:a:1.0",
                "org/example/a/1.0/a-1.0.jar",
                sha.as_str(),
                "u"
            ])
        );
        for bad in [
            format!("org.example:a:1.0\torg/example/a/2.0/a-1.0.jar\t{sha}\tu"),
            format!("org.example:a:1.0\torg/example/a/1.0/b-1.0.jar\t{sha}\tu"),
            format!("org.example:a:1.0\torg/example/a/1.0/x/a-1.0.jar\t{sha}\tu"),
            format!(
                "org.example:a:1.0\torg/example/a/1.0/a-1.0.jar\t{}\tu",
                "A".repeat(64)
            ),
            "org.example:a:1.0\torg/example/a/1.0/a-1.0.jar\tabc\tu".to_string(),
            format!("org.example:a\torg/example/a/1.0/a-1.0.jar\t{sha}\tu"),
            format!("org.example:a:1.0\torg/example/a/1.0/a-1.0.jar\t{sha}"),
        ] {
            assert_eq!(index_row(&bad), None, "{bad}");
        }
    }

    #[test]
    fn jvm_ledger_entries_are_maven_packages() {
        assert_eq!(ledger_ecosystem(LEDGER_ECOSYSTEM), "maven");
        assert_eq!(ledger_ecosystem("maven"), "maven");
        assert_eq!(ledger_ecosystem("npm"), "npm");
    }

    /// The basename list is exactly every tool marker that is a root file.
    #[test]
    fn project_markers_are_the_basename_markers_of_every_tool() {
        let mut basenames: Vec<&str> = BuildTool::ALL
            .iter()
            .flat_map(|t| t.markers().iter().copied())
            .filter(|m| !m.contains('/') && !m.starts_with('.'))
            .collect();
        let mut listed = JVM_PROJECT_MARKERS.to_vec();
        basenames.sort_unstable();
        listed.sort_unstable();
        assert_eq!(basenames, listed);
        assert_eq!(
            [GRADLE_SETTINGS_FILES, GRADLE_BUILD_FILES].concat(),
            GRADLE_ROOT_FILES
        );
        assert_eq!(&MILL_MARKERS[..3], MILL_BUILD_FILES);
    }

    #[test]
    fn every_marker_marks_its_tool() {
        for tool in BuildTool::ALL {
            for marker in tool.markers() {
                let dir = tempfile::tempdir().unwrap();
                assert!(!is_jvm_build(dir.path()));
                let path = dir.path().join(marker);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                if *marker == SCALA_CLI_DIR {
                    std::fs::create_dir(&path).unwrap();
                } else {
                    std::fs::write(&path, "").unwrap();
                }
                assert!(has_build(dir.path(), tool), "{marker}");
                assert!(is_jvm_build(dir.path()), "{marker}");
                assert_eq!(
                    is_scala_tool_build(dir.path()),
                    tool.is_scala_tool(),
                    "{marker}"
                );
            }
        }
    }

    #[test]
    fn gradle_settings_names() {
        assert_eq!(
            GRADLE_SETTINGS_FILES,
            &["settings.gradle", "settings.gradle.kts"]
        );
        assert!(is_gradle_settings("settings.gradle"));
        assert!(is_gradle_settings("sub/dir/settings.gradle.kts"));
        assert!(!is_gradle_settings("build.gradle"));
        assert!(!is_gradle_settings("settings.gradle/x"));
        assert!(!is_gradle_settings("my-settings.gradle"));
    }

    /// The tree-relative constants each backend spells as a literal must
    /// sit under the tree constant they belong to, so moving a tree root
    /// fails here rather than drifting.
    #[test]
    fn tree_relative_constants_sit_under_their_tree() {
        use super::super::{coursier_tree, gradle, maven_reactor, sbt, scala_cli};
        let under = |rel: &str, tree: &str| {
            assert!(
                rel.strip_prefix(tree).is_some_and(|r| r.starts_with('/')),
                "{rel} is not under {tree}"
            )
        };
        under(maven_reactor::GITATTRIBUTES_REL, MAVEN2_TREE);
        under(sbt::TREE_GITIGNORE_REL, MAVEN2_TREE);
        under(gradle::GITATTRIBUTES_REL, GRADLE_TREE);
        under(coursier_tree::GITIGNORE_REL, COURSIER_TREE);
        under(coursier_tree::GITATTRIBUTES_REL, COURSIER_TREE);
        under(scala_cli::GUARD_REL, COURSIER_TREE);
        assert!(scala_cli::ROOT_BYTES.contains(scala_cli::GUARD_REL));
        assert!(maven_reactor::TAIL_DIR.ends_with(&format!("/{MAVEN2_TREE}")));
        assert!(maven_reactor::REPO_URL.ends_with(&format!("/{MAVEN2_TREE}")));
        for index in [gradle::INDEX_REL, coursier_tree::INDEX_REL] {
            under(index, ".socket/vendor");
        }
        assert_eq!(
            gradle::VENDOR_GITATTRIBUTES_REL,
            ".socket/vendor/.gitattributes"
        );
    }

    /// Pins the edges of the one marker stat rule: a directory named like
    /// a build file counts, a dangling symlink does not.
    #[test]
    fn marker_present_edges() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        std::fs::create_dir(dir.join("build.gradle")).unwrap();
        assert!(marker_present(dir, "build.gradle"));
        assert!(has_build(dir, BuildTool::Gradle));
        std::fs::create_dir(dir.join(SCALA_CLI_DIR)).unwrap();
        assert!(has_build(dir, BuildTool::ScalaCli));
        assert!(!marker_present(dir, POM_FILE));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(dir.join("missing"), dir.join(POM_FILE)).unwrap();
            assert!(!marker_present(dir, POM_FILE));
            assert!(!has_build(dir, BuildTool::Maven));
        }
    }
}
