//! Shared seam for JVM build tools whose artifacts land in different
//! caches (Maven's `~/.m2/repository`, Gradle's `modules-2`, Coursier,
//! Ivy). Every Maven-PURL discovery path goes through here:
//!
//! - [`is_jvm_project`]: whether a directory is a JVM project root, by
//!   the build markers of [`layout::BuildTool`].
//! - [`JvmCacheLayout`] / [`JvmCacheRoot`]: an installed-artifact cache
//!   and how its directories spell coordinates. [`MavenCrawler`] crawls
//!   and resolves PURLs per root, dispatching on the layout.
//! - [`locate_artifact`] / [`all_local_roots`]: every installed copy of
//!   one artifact file across the local caches, for sourcing its bytes.
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

use crate::vendor::jvm::layout;

/// Whether `dir` is a JVM build root: any [`layout::BuildTool`] marker,
/// root-relative ones (`project/build.properties`, `.scala-build`)
/// included ([`layout::is_jvm_build`]).
pub async fn is_jvm_project(dir: &Path) -> bool {
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || layout::is_jvm_build(&dir))
        .await
        .unwrap_or(false)
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
    /// spelling (each cache's root directory has a distinctive name), in
    /// order:
    ///
    /// 1. `…/files-2.1` → [`Self::GradleModules2`];
    /// 2. `…/cache` under a directory whose name contains `ivy` (any case;
    ///    `~/.ivy2/cache`, `<sbt.ivy.home>/cache`) → [`Self::Ivy`];
    /// 3. `…/v1` under `coursier`, `Coursier`, `Cache` or `cache` (every OS
    ///    default and the legacy `~/.coursier/cache/v1`) → [`Self::Coursier`];
    /// 4. a path with an `https` / `http` component followed by at least two
    ///    more (a Coursier per-repository root,
    ///    `<cache>/https/<host>/<repo path…>`) → [`Self::Coursier`];
    /// 5. anything else is a Maven local repository.
    ///
    /// A Coursier false positive is harmless: the Coursier arms fall back
    /// to the Maven2 logic on a path that is not a Coursier cache directory.
    pub fn classify(path: &Path) -> Self {
        let name = |p: &Path| p.file_name().and_then(|n| n.to_str()).map(str::to_string);
        let parent = path.parent().and_then(name);
        match name(path).as_deref() {
            Some("files-2.1") => return Self::GradleModules2,
            Some("cache")
                if parent
                    .as_deref()
                    .is_some_and(|p| p.to_ascii_lowercase().contains("ivy")) =>
            {
                return Self::Ivy
            }
            Some("v1")
                if matches!(
                    parent.as_deref(),
                    Some("coursier" | "Coursier" | "Cache" | "cache")
                ) =>
            {
                return Self::Coursier
            }
            _ => {}
        }
        let parts: Vec<&std::ffi::OsStr> = path
            .components()
            .filter_map(|c| match c {
                std::path::Component::Normal(s) => Some(s),
                _ => None,
            })
            .collect();
        let scheme = parts.iter().position(|s| *s == "https" || *s == "http");
        if scheme.is_some_and(|at| parts.len() >= at + 3) {
            return Self::Coursier;
        }
        Self::Maven2
    }
}

/// Append `root` to `roots` when [`JvmCacheLayout::classify`] agrees with
/// its layout and the path is not there yet; `true` when appended. A
/// Coursier or Ivy root reached through an override whose path spells
/// another layout (an Ivy home at `/tmp/x`, so `/tmp/x/cache`) is skipped
/// with a debug line: [`MavenCrawler::find_by_purls`], which recovers the
/// layout from the path alone, would otherwise resolve it with the wrong
/// one.
///
/// [`MavenCrawler::find_by_purls`]: super::MavenCrawler::find_by_purls
pub fn push_classified(roots: &mut Vec<JvmCacheRoot>, root: JvmCacheRoot) -> bool {
    if JvmCacheLayout::classify(&root.path) != root.layout {
        debug_log(&format!(
            "skipping {:?} cache root {}: its path does not spell that layout",
            root.layout,
            root.path.display()
        ));
        return false;
    }
    // A root reached twice (the same path, or another spelling of it
    // through a symlink) is one cache: listing it twice would make the
    // every-copy fan-out patch the same files twice.
    let canonical = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let key = canonical(&root.path);
    if roots
        .iter()
        .any(|r| r.path == root.path || canonical(&r.path) == key)
    {
        return false;
    }
    roots.push(root);
    true
}

/// A `SOCKET_DEBUG` line from the JVM cache discovery.
pub(crate) fn debug_log(message: &str) {
    if crate::utils::env_compat::is_debug_enabled() {
        eprintln!("[socket-patch debug] {message}");
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

/// Every local JVM cache that exists on this machine (process environment),
/// whatever the build at `cwd` resolves from: for sourcing an artifact's
/// bytes ([`locate_artifact`]), never for discovery. See
/// [`all_local_roots_with`].
pub fn all_local_roots(cwd: &Path) -> Vec<JvmCacheRoot> {
    all_local_roots_with(cwd, &super::maven_crawler::JvmEnv::from_process())
}

/// [`all_local_roots`] under the caches `env` names: the Gradle user home's
/// `files-2.1`, the read-only Gradle cache and the Maven local repository,
/// each when it is a directory. A Gradle build at `cwd` lists the Gradle
/// caches first; anything else the Maven local repository first.
pub fn all_local_roots_with(cwd: &Path, env: &super::maven_crawler::JvmEnv) -> Vec<JvmCacheRoot> {
    let mut gradle = Vec::new();
    if let Some(home) = &env.gradle {
        for dir in std::iter::once(&home.files21).chain(&home.ro_files21) {
            if dir.is_dir() {
                gradle.push(JvmCacheRoot::new(
                    dir.clone(),
                    JvmCacheLayout::GradleModules2,
                ));
            }
        }
    }
    let m2 = env
        .m2_repo
        .as_ref()
        .filter(|repo| repo.is_dir())
        .map(|repo| JvmCacheRoot::new(repo.clone(), JvmCacheLayout::Maven2));
    if layout::has_build(cwd, layout::BuildTool::Gradle) {
        gradle.extend(m2);
        gradle
    } else {
        m2.into_iter().chain(gradle).collect()
    }
}

/// Every installed copy of one artifact file
/// (`<artifact>-<version>[-<classifier>].<ext>`) under `root`: the one
/// repository path for [`JvmCacheLayout::Maven2`], every hash directory's
/// copy for [`JvmCacheLayout::GradleModules2`] (sorted), the path in each
/// repository root of a [`JvmCacheLayout::Coursier`] cache, and each
/// artifact type directory's copy for [`JvmCacheLayout::Ivy`]. Only existing
/// regular files are returned; unsafe coordinates resolve to nothing.
pub fn locate_artifact(
    root: &JvmCacheRoot,
    gav: &Gav,
    classifier: Option<&str>,
    ext: &str,
) -> Vec<PathBuf> {
    let (group, artifact, version) = gav;
    let classifier_ok = classifier.is_none_or(crate::patch::path_safety::is_safe_single_segment);
    let ext_ok = crate::patch::path_safety::is_safe_single_segment(ext);
    if !layout::is_path_safe(group, artifact, version) || !classifier_ok || !ext_ok {
        return Vec::new();
    }
    let leaf = layout::file_name(artifact, version, classifier, ext);
    match root.layout {
        JvmCacheLayout::Maven2 => {
            let path = layout::version_dir_path(&root.path, group, artifact, version).join(&leaf);
            if path.is_file() {
                vec![path]
            } else {
                Vec::new()
            }
        }
        JvmCacheLayout::GradleModules2 => {
            let version_dir = root.path.join(group).join(artifact).join(version);
            let mut copies: Vec<PathBuf> = std::fs::read_dir(&version_dir)
                .into_iter()
                .flatten()
                .flatten()
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .is_some_and(super::gradle_cache::is_hash_dir_name)
                })
                .map(|e| e.path().join(&leaf))
                .filter(|p| p.is_file())
                .collect();
            copies.sort();
            copies
        }
        // A Coursier cache directory holds per-repository Maven2 roots; a
        // per-repository root is one itself.
        JvmCacheLayout::Coursier => {
            let repos = if super::coursier_cache::is_coursier_cache_dir(&root.path) {
                super::coursier_cache::repo_roots(&root.path)
            } else {
                vec![root.path.clone()]
            };
            repos
                .into_iter()
                .map(|repo| layout::version_dir_path(&repo, group, artifact, version).join(&leaf))
                .filter(|p| p.is_file())
                .collect()
        }
        // `<cache>/<org>/<module>/<type dir>/<leaf>`: the jar under
        // `jars/` (or `bundles/`, `orbits/`), a sources jar under `srcs/`.
        JvmCacheLayout::Ivy => {
            let module = root.path.join(group).join(artifact);
            super::ivy_cache::type_dirs(&module)
                .iter()
                .map(|dir| module.join(dir).join(&leaf))
                .filter(|p| p.is_file())
                .collect()
        }
    }
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
    fn classify_recognizes_ivy_and_coursier_roots_on_every_os() {
        use JvmCacheLayout::*;
        for (path, want) in [
            // Ivy: `<ivy home>/cache`.
            ("/home/u/.ivy2/cache", Ivy),
            ("/opt/sbt-IVY/cache", Ivy),
            ("/tmp/x/cache", Maven2),
            ("/home/u/.ivy2/local", Maven2),
            // Coursier cache dirs: Linux, macOS, Windows (both spellings),
            // legacy.
            ("/home/u/.cache/coursier/v1", Coursier),
            ("/Users/u/Library/Caches/Coursier/v1", Coursier),
            ("/c/Users/u/AppData/Local/Coursier/Cache/v1", Coursier),
            ("/c/Users/u/AppData/Local/Coursier/cache/v1", Coursier),
            ("/home/u/.coursier/cache/v1", Coursier),
            ("/srv/api/v1", Maven2),
            // Coursier per-repository roots.
            (
                "/home/u/.cache/coursier/v1/https/repo1.maven.org/maven2",
                Coursier,
            ),
            (
                "/tmp/cs/http/nexus.corp/content/repositories/releases",
                Coursier,
            ),
            ("/tmp/cs/https/host", Maven2),
            ("/tmp/cs", Maven2),
            ("/home/u/.m2/repository", Maven2),
        ] {
            assert_eq!(JvmCacheLayout::classify(Path::new(path)), want, "{path}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn classify_reads_windows_separators() {
        let path = Path::new(r"C:\Users\u\AppData\Local\Coursier\Cache\v1");
        assert_eq!(JvmCacheLayout::classify(path), JvmCacheLayout::Coursier);
        let repo = Path::new(r"C:\cs\https\repo1.maven.org\maven2");
        assert_eq!(JvmCacheLayout::classify(repo), JvmCacheLayout::Coursier);
    }

    #[test]
    fn push_classified_keeps_only_roots_whose_path_spells_their_layout() {
        let mut roots = Vec::new();
        let ivy = |p: &str| JvmCacheRoot::new(PathBuf::from(p), JvmCacheLayout::Ivy);
        assert!(push_classified(&mut roots, ivy("/h/.ivy2/cache")));
        assert!(
            !push_classified(&mut roots, ivy("/h/.ivy2/cache")),
            "duplicate"
        );
        assert!(
            !push_classified(&mut roots, ivy("/tmp/x/cache")),
            "override at /tmp/x"
        );
        let cs = JvmCacheRoot::new(PathBuf::from("/tmp/cs"), JvmCacheLayout::Coursier);
        assert!(
            !push_classified(&mut roots, cs),
            "a bare COURSIER_CACHE dir"
        );
        let repo = JvmCacheRoot::new(
            PathBuf::from("/tmp/cs/https/repo1.maven.org/maven2"),
            JvmCacheLayout::Coursier,
        );
        assert!(push_classified(&mut roots, repo));
        assert_eq!(roots.len(), 2);
    }

    /// A root reached again through a symlink is the same cache: listing
    /// it twice would patch its files twice.
    #[cfg(unix)]
    #[test]
    fn push_classified_drops_a_symlinked_spelling_of_a_listed_root() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("home/.ivy2/cache");
        std::fs::create_dir_all(&real).unwrap();
        let alias = tmp.path().join("alias-ivy");
        std::os::unix::fs::symlink(tmp.path().join("home/.ivy2"), &alias).unwrap();
        let mut roots = Vec::new();
        let ivy = |p: PathBuf| JvmCacheRoot::new(p, JvmCacheLayout::Ivy);
        assert!(push_classified(&mut roots, ivy(real.clone())));
        assert!(!push_classified(&mut roots, ivy(alias.join("cache"))));
        assert_eq!(roots, vec![ivy(real)]);
    }

    #[test]
    fn no_provider_means_whole_cache_fallback() {
        assert_eq!(project_dependency_set(Path::new("/nonexistent")), None);
    }

    /// Every build-tool marker, root-relative ones included, makes a JVM
    /// project: an sbt build may have only `project/build.properties`.
    #[tokio::test]
    async fn every_marker_makes_a_jvm_project() {
        for tool in layout::BuildTool::ALL {
            for marker in tool.markers() {
                let dir = tempfile::tempdir().unwrap();
                assert!(!is_jvm_project(dir.path()).await);
                let path = dir.path().join(marker);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, "").unwrap();
                assert!(is_jvm_project(dir.path()).await, "{marker}");
            }
        }
    }
}
