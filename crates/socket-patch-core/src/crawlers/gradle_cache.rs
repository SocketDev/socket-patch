//! Gradle's dependency cache on disk: the `files-2.1` layout and the
//! filesystem / process-environment adapters over the pure [`crate::gradle`]
//! model.
//!
//! Gradle caches every downloaded file at
//! `<user home>/caches/modules-2/files-2.1/<group>/<artifact>/<version>/<sha1>/<file>`:
//! the group keeps its dots, and each file sits in a directory named after
//! its own sha1 (some releases print the sha1 as a number and drop its
//! leading zeros, so a name may be shorter than 40 digits). A version's
//! jar, pom and `.module` therefore live in different hash directories, and
//! the same file name can appear in several (a re-download whose bytes
//! changed). The crawler reports the VERSION directory as the package path;
//! [`installed_copies`] expands it into the hash directories every join
//! site patches, verifies and rolls back.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::crawlers::jvm_cache::Gav;
use crate::crawlers::maven_crawler::is_safe_maven_coordinate;

/// The leaf directory name of a Gradle module cache.
pub const FILES21: &str = "files-2.1";

/// One cached file of a `files-2.1` tree.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    pub gav: Gav,
    /// The hash directory's name as spelled on disk.
    pub hash_dir: String,
    pub leaf: String,
}

impl Entry {
    /// The version directory of this entry under `root`.
    pub fn version_dir(&self, root: &Path) -> PathBuf {
        root.join(&self.gav.0).join(&self.gav.1).join(&self.gav.2)
    }

    /// The file itself under `root`.
    pub fn path(&self, root: &Path) -> PathBuf {
        self.version_dir(root).join(&self.hash_dir).join(&self.leaf)
    }
}

/// Whether `name` spells a `files-2.1` hash directory: 1-40 lowercase hex
/// digits.
pub fn is_hash_dir_name(name: &str) -> bool {
    (1..=40).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether the hash directory `dir_name` is the one Gradle names after
/// `sha1_hex`: both sides compared as 40-digit numbers (left-padded with
/// zeros), so a dropped leading zero still matches.
pub fn hash_eq(dir_name: &str, sha1_hex: &str) -> bool {
    let sha1 = sha1_hex.to_ascii_lowercase();
    if !is_hash_dir_name(dir_name) || !is_hash_dir_name(&sha1) {
        return false;
    }
    format!("{dir_name:0>40}") == format!("{sha1:0>40}")
}

/// Whether `bytes` are the pristine download Gradle stored in the hash
/// directory `dir_name` (their sha1 names it).
pub fn pristine(dir_name: &str, bytes: &[u8]) -> bool {
    use sha1::{Digest, Sha1};
    hash_eq(dir_name, &hex::encode(Sha1::digest(bytes)))
}

/// Whether `path` is a version directory of a `files-2.1` tree
/// (`…/files-2.1/<group>/<artifact>/<version>`), from its spelling alone.
pub fn is_gradle_version_dir(path: &Path) -> bool {
    let mut up = path.ancestors().skip(3);
    up.next()
        .and_then(Path::file_name)
        .is_some_and(|n| n == FILES21)
}

/// The UTF-8 names of `dir`'s children, sorted, with whether each is a
/// directory (symlinks are not followed). Unreadable = empty.
fn children(dir: &Path) -> Vec<(String, bool)> {
    let mut out: Vec<(String, bool)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let is_dir = e.file_type().ok()?.is_dir();
            Some((name, is_dir))
        })
        .collect();
    out.sort();
    out
}

/// Cache bookkeeping that can sit beside the module directories when a
/// caller hands over a `modules-2`-level tree: never a group.
fn is_bookkeeping(name: &str) -> bool {
    name.starts_with("metadata-")
        || name.starts_with("transforms")
        || name.starts_with("jars-")
        || name.ends_with(".lock")
}

/// Every cached file of the `files-2.1` tree at `root`: exactly three
/// literal directory levels (group, artifact, version), then a hash
/// directory ([`is_hash_dir_name`]) and its regular files. Bookkeeping
/// directories and lock files are skipped, as is any coordinate that
/// [`is_safe_maven_coordinate`] rejects. Sorted (walk order).
pub fn walk_files21(root: &Path) -> Vec<Entry> {
    let mut out = Vec::new();
    for (group, is_dir) in children(root) {
        if !is_dir || is_bookkeeping(&group) {
            continue;
        }
        let group_dir = root.join(&group);
        for (artifact, is_dir) in children(&group_dir) {
            if !is_dir {
                continue;
            }
            let artifact_dir = group_dir.join(&artifact);
            for (version, is_dir) in children(&artifact_dir) {
                if !is_dir || !is_safe_maven_coordinate(&group, &artifact, &version) {
                    continue;
                }
                let gav: Gav = (group.clone(), artifact.clone(), version.clone());
                out.extend(version_dir_entries(&artifact_dir.join(&version), &gav));
            }
        }
    }
    out
}

/// The cached files of one version directory.
fn version_dir_entries(version_dir: &Path, gav: &Gav) -> Vec<Entry> {
    let mut out = Vec::new();
    for (hash_dir, is_dir) in children(version_dir) {
        if !is_dir || !is_hash_dir_name(&hash_dir) {
            continue;
        }
        for (leaf, is_dir) in children(&version_dir.join(&hash_dir)) {
            if !is_dir {
                out.push(Entry {
                    gav: gav.clone(),
                    hash_dir: hash_dir.clone(),
                    leaf,
                });
            }
        }
    }
    out
}

/// Whether a version directory's files make it an installed module: some
/// hash directory holds `<artifact>-<version>.{jar,pom,module}`.
pub fn has_module_file<'a>(entries: impl IntoIterator<Item = &'a Entry>) -> bool {
    entries.into_iter().any(|e| {
        let stem = format!("{}-{}", e.gav.1, e.gav.2);
        e.leaf
            .strip_prefix(&stem)
            .is_some_and(|ext| matches!(ext, ".jar" | ".pom" | ".module"))
    })
}

/// [`has_module_file`] for the version directory `root/<g>/<a>/<v>`.
pub fn is_installed(root: &Path, gav: &Gav) -> bool {
    let (g, a, v) = gav;
    if !is_safe_maven_coordinate(g, a, v) {
        return false;
    }
    has_module_file(&version_dir_entries(&root.join(g).join(a).join(v), gav))
}

/// The cached files of the `files-2.1` tree at `root`, grouped by version
/// directory (in walk order).
pub fn walk_versions(root: &Path) -> BTreeMap<Gav, Vec<Entry>> {
    let mut out: BTreeMap<Gav, Vec<Entry>> = BTreeMap::new();
    for e in walk_files21(root) {
        out.entry(e.gav.clone()).or_default().push(e);
    }
    out
}
