//! Shared seam for JVM build tools whose artifacts land in different
//! caches (Maven's `~/.m2/repository`, Gradle's `modules-2`, Coursier,
//! Ivy). Every Maven-PURL discovery path goes through here:
//!
//! - [`JVM_PROJECT_MARKERS`]: the files that make a directory a JVM
//!   project root (each build tool contributes its own).
//! - [`JvmCacheLayout`] / [`JvmCacheRoot`]: an installed-artifact cache
//!   and how its directories spell coordinates. [`MavenCrawler`] crawls
//!   and resolves PURLs per root, dispatching on the layout.
//! - [`project_dependency_set`]: the coordinates a project actually
//!   resolves, from one provider per build tool (Gradle lock state, an sbt
//!   lock, …). `None` means no provider could tell, so callers fall back to
//!   the whole-cache crawl.
//!
//! Each build tool keeps its implementation in its own module and only
//! adds a variant / list entry / match arm here.
//!
//! [`MavenCrawler`]: super::MavenCrawler

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Files whose presence makes a directory a JVM project root.
pub const JVM_PROJECT_MARKERS: &[&str] = &[
    // Maven
    "pom.xml",
    // Gradle
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
];

/// Whether `dir` holds any [`JVM_PROJECT_MARKERS`] file.
pub async fn is_jvm_project(dir: &Path) -> bool {
    for marker in JVM_PROJECT_MARKERS {
        if tokio::fs::metadata(dir.join(marker)).await.is_ok() {
            return true;
        }
    }
    false
}

/// How a cache root's directories spell an artifact's coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum JvmCacheLayout {
    /// `<group/path>/<artifact>/<version>/<artifact>-<version>.{pom,jar}`
    /// (Maven local repository).
    Maven2,
    /// `<group.id>/<artifact>/<version>/<sha1>/<file>` (Gradle's
    /// `caches/modules-2/files-2.1`).
    GradleModules2,
    /// Coursier's per-repository-URL cache.
    Coursier,
    /// Ivy's `~/.ivy2` cache.
    Ivy,
}

impl JvmCacheLayout {
    /// The layout of the cache rooted at `path`, from the root's own
    /// spelling (each cache's root directory has a distinctive name).
    /// Anything unrecognized is a Maven local repository.
    pub fn classify(path: &Path) -> Self {
        match path.file_name().and_then(|n| n.to_str()) {
            Some("files-2.1") => Self::GradleModules2,
            _ => Self::Maven2,
        }
    }
}

/// One installed-artifact cache to crawl.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct JvmCacheRoot {
    pub path: PathBuf,
    pub layout: JvmCacheLayout,
}

impl JvmCacheRoot {
    pub fn new(path: PathBuf, layout: JvmCacheLayout) -> Self {
        Self { path, layout }
    }
}

/// Maven coordinates `(group_id, artifact_id, version)`.
pub type Gav = (String, String, String);

/// What a project resolves, as far as one build tool's provider can tell.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectDependencySet {
    /// The provider that answered (`"gradle"`, `"sbt"`, …).
    pub provider: &'static str,
    pub gavs: BTreeSet<Gav>,
}

/// The coordinates the project rooted at `root` resolves, from the first
/// build-tool provider that recognizes it. `None` = no provider knows
/// (callers fall back to every cached artifact).
pub fn project_dependency_set(root: &Path) -> Option<ProjectDependencySet> {
    // One entry per build tool; each returns `None` for a root it does not
    // own or cannot read.
    let providers: &[fn(&Path) -> Option<ProjectDependencySet>] = &[];
    providers.iter().find_map(|provider| provider(root))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_recognizes_gradle_files_root_and_defaults_to_maven2() {
        let gradle = Path::new("/h/.gradle/caches/modules-2/files-2.1");
        assert_eq!(
            JvmCacheLayout::classify(gradle),
            JvmCacheLayout::GradleModules2
        );
        let m2 = Path::new("/h/.m2/repository");
        assert_eq!(JvmCacheLayout::classify(m2), JvmCacheLayout::Maven2);
        assert_eq!(
            JvmCacheLayout::classify(Path::new("")),
            JvmCacheLayout::Maven2
        );
    }

    #[test]
    fn no_provider_means_whole_cache_fallback() {
        assert_eq!(project_dependency_set(Path::new("/nonexistent")), None);
    }

    #[tokio::test]
    async fn every_marker_makes_a_jvm_project() {
        for marker in JVM_PROJECT_MARKERS {
            let dir = tempfile::tempdir().unwrap();
            assert!(!is_jvm_project(dir.path()).await);
            std::fs::write(dir.path().join(marker), "").unwrap();
            assert!(is_jvm_project(dir.path()).await, "{marker}");
        }
    }
}
