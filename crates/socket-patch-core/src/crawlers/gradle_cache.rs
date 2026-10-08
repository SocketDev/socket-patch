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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use crate::crawlers::jvm_cache::Gav;
use crate::gradle::graph::{self, MavenLocal, ScriptGraph};
use crate::gradle::home::{is_init_script_name, GradleHome};
use crate::gradle::{Env, Os};
use crate::manifest::schema::PatchFileInfo;
use crate::vendor::jvm::layout::{self, is_path_safe, BuildTool};

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
    hash_eq(dir_name, &crate::utils::digest::sha1_hex_of(bytes))
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
/// [`is_path_safe`] rejects. Sorted (walk order).
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
                if !is_dir || !is_path_safe(&group, &artifact, &version) {
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
    if !is_path_safe(g, a, v) {
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

// ── installed copies ────────────────────────────────────────────────────

/// A version directory expanded into the hash directories that hold a
/// patch's files ([`installed_copies_detailed`]).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GradleTargets {
    /// `(hash dir, the files it holds, keyed by leaf)`, one per hash dir
    /// holding at least one of the files, sorted by directory.
    pub targets: Vec<(PathBuf, HashMap<String, PatchFileInfo>)>,
    /// The patch's keys no hash directory holds (also every key that is not
    /// a single file name: a jar member, say).
    pub missing: Vec<String>,
}

/// The directories a patch's `files` are joined onto for the package at
/// `pkg_path`, each with the keys it holds.
///
/// For a Gradle version directory ([`is_gradle_version_dir`]) each key's
/// file name (`package/` prefix dropped) is looked up in every hash
/// directory: a file present in two hash dirs (a re-download whose bytes
/// changed) yields two targets, and a jar and its pom in different hash
/// dirs yield one target each, keyed by the bare file name. An Ivy
/// artifact directory ([`ivy_cache::is_artifact_dir`]) expands the same
/// way over its module's artifact type directories (`jars/`, `bundles/`,
/// `orbits/`, `srcs/`, `docs/`): a sources jar sits in `srcs/`, beside the
/// `jars/` the crawler reports. Keys no directory holds stay joined onto
/// `pkg_path` itself, so verification reports them as not found instead
/// of dropping them. Any other path is returned as is:
/// `[(pkg_path, files)]`.
///
/// [`ivy_cache::is_artifact_dir`]: super::ivy_cache::is_artifact_dir
pub fn installed_copies(
    pkg_path: &Path,
    files: &HashMap<String, PatchFileInfo>,
) -> Vec<(PathBuf, HashMap<String, PatchFileInfo>)> {
    if !expands(pkg_path) {
        return vec![(pkg_path.to_path_buf(), files.clone())];
    }
    let GradleTargets {
        mut targets,
        missing,
    } = installed_copies_detailed(pkg_path, files);
    if !missing.is_empty() {
        let rest: HashMap<String, PatchFileInfo> = missing
            .into_iter()
            .filter_map(|k| files.get(&k).map(|info| (k, info.clone())))
            .collect();
        targets.push((pkg_path.to_path_buf(), rest));
    }
    targets
}

/// Whether [`installed_copies`] expands `pkg_path` (a Gradle version
/// directory or an Ivy artifact directory) instead of joining the keys
/// onto it as is.
pub fn expands(pkg_path: &Path) -> bool {
    is_gradle_version_dir(pkg_path) || super::ivy_cache::is_artifact_dir(pkg_path)
}

/// [`installed_copies`] with the keys no hash (or Ivy type) directory
/// holds reported apart. For any other path every key is in the one
/// identity target.
pub fn installed_copies_detailed(
    pkg_path: &Path,
    files: &HashMap<String, PatchFileInfo>,
) -> GradleTargets {
    if super::ivy_cache::is_artifact_dir(pkg_path) {
        // Directories are siblings of `pkg_path`, joined onto its parent.
        let Some(module_dir) = pkg_path.parent() else {
            return GradleTargets {
                targets: vec![(pkg_path.to_path_buf(), files.clone())],
                missing: Vec::new(),
            };
        };
        return expand_into(module_dir, &super::ivy_cache::type_dirs(module_dir), files);
    }
    if !is_gradle_version_dir(pkg_path) {
        return GradleTargets {
            targets: vec![(pkg_path.to_path_buf(), files.clone())],
            missing: Vec::new(),
        };
    }
    let hash_dirs: Vec<String> = children(pkg_path)
        .into_iter()
        .filter(|(name, is_dir)| *is_dir && is_hash_dir_name(name))
        .map(|(name, _)| name)
        .collect();
    expand_into(pkg_path, &hash_dirs, files)
}

/// Each of `files`' keys looked up by file name in every one of `dirs`
/// (children of `base`): one target per directory holding at least one of
/// them, keyed by the bare file name, sorted by directory; keys none holds
/// (and keys that are not a single file name) are `missing`.
fn expand_into(
    base: &Path,
    dirs: &[String],
    files: &HashMap<String, PatchFileInfo>,
) -> GradleTargets {
    let mut by_dir: BTreeMap<String, HashMap<String, PatchFileInfo>> = BTreeMap::new();
    let mut missing = Vec::new();
    let mut keys: Vec<&String> = files.keys().collect();
    keys.sort();
    for key in keys {
        let leaf = crate::patch::apply::normalize_file_path(key);
        let holders: Vec<&String> = if leaf.is_empty() || leaf.contains(['/', '\\']) {
            Vec::new()
        } else {
            dirs.iter()
                .filter(|dir| base.join(dir).join(leaf).is_file())
                .collect()
        };
        if holders.is_empty() {
            missing.push(key.clone());
            continue;
        }
        for dir in holders {
            by_dir
                .entry(dir.clone())
                .or_default()
                .insert(leaf.to_string(), files[key].clone());
        }
    }
    GradleTargets {
        targets: by_dir
            .into_iter()
            .map(|(dir, files)| (base.join(dir), files))
            .collect(),
        missing,
    }
}

// ── derived copies ──────────────────────────────────────────────────────

/// How deep below a derived-cache root [`stale_derived_copies`] looks.
const DERIVED_DEPTH: usize = 8;
/// A bound on the entries [`stale_derived_copies`] visits per root; a walk
/// cut short by it is reported [`DerivedCopies::incomplete`].
const DERIVED_ENTRIES: usize = 200_000;

/// What [`stale_derived_copies`] found of the copies Gradle derived from a
/// cached jar.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DerivedCopies {
    /// Copies proven derived from the pristine jar: byte-identical to it,
    /// or under a directory, or with a stem, that [`hash_eq`]s its sha1.
    /// Sorted.
    pub stale: Vec<PathBuf>,
    /// Files named after the jar (`jar_leaf`, `instrumented-<jar_leaf>`)
    /// whose bytes are not the pristine jar's: Gradle may have derived
    /// them from the pristine jar or from the patched one, and nothing in
    /// the file says which. Sorted.
    pub unknown: Vec<PathBuf>,
    /// The walk did not cover every derived-cache root (an unreadable
    /// directory or file, or more entries under one than the walk visits), so
    /// an empty `stale` does not prove there is no stale copy.
    pub incomplete: bool,
}

/// Copies of a cached jar that Gradle derived from it and keeps apart
/// (outside `files-2.1`), so patching the cached jar does not reach them:
/// files under `<user home>/caches/jars-*`, `caches/transforms-*` and
/// `caches/<version>/transforms` named `jar_leaf` (or
/// `instrumented-<jar_leaf>`), or under a directory, or with a stem, that
/// [`hash_eq`]s `pristine_sha1`. A name match counts as stale only when its
/// bytes are the pristine jar's; otherwise it is [`DerivedCopies::unknown`].
/// Symlinks are not followed. One query of a fresh [`DerivedIndex`]; a
/// caller checking several jars builds the index once instead.
pub fn stale_derived_copies(
    user_home: &Path,
    jar_leaf: &str,
    pristine_sha1: &str,
) -> DerivedCopies {
    DerivedIndex::build(user_home).query(jar_leaf, pristine_sha1)
}

/// [`stale_derived_copies`] visiting at most `max_entries` entries per root
/// (tests).
#[doc(hidden)]
pub fn stale_derived_copies_bounded(
    user_home: &Path,
    jar_leaf: &str,
    pristine_sha1: &str,
    max_entries: usize,
) -> DerivedCopies {
    DerivedIndex::build_bounded(user_home, max_entries).query(jar_leaf, pristine_sha1)
}

/// One walk of a Gradle user home's derived-cache roots, answering
/// [`stale_derived_copies`] for any number of jars. It keeps only the files
/// a query can match — `*.jar` files, and files whose stem or some
/// directory below the root looks like a sha1 (33–40 hex digits; Gradle's
/// own 32-digit workspace hashes do not) — so an Android home's extracted
/// resource trees cost the walk, not memory.
#[derive(Debug, Default)]
pub struct DerivedIndex {
    /// `(root, file)` of every candidate.
    files: Vec<(PathBuf, PathBuf)>,
    incomplete: bool,
}

impl DerivedIndex {
    /// Walk `user_home`'s derived-cache roots (bounded per root).
    pub fn build(user_home: &Path) -> Self {
        Self::build_bounded(user_home, DERIVED_ENTRIES)
    }

    /// [`DerivedIndex::build`] visiting at most `max_entries` per root.
    #[doc(hidden)]
    pub fn build_bounded(user_home: &Path, max_entries: usize) -> Self {
        let sha1_like = |name: &str| name.len() >= 33 && is_hash_dir_name(name);
        let caches = user_home.join("caches");
        let mut roots = Vec::new();
        for (name, is_dir) in children(&caches) {
            if !is_dir {
                continue;
            }
            if name.starts_with("jars-") || name.starts_with("transforms-") {
                roots.push(caches.join(&name));
            } else if name.starts_with(|c: char| c.is_ascii_digit()) {
                let transforms = caches.join(&name).join("transforms");
                if transforms.is_dir() {
                    roots.push(transforms);
                }
            }
        }
        let mut out = Self::default();
        for root in roots {
            let mut visited = 0usize;
            for entry in walkdir::WalkDir::new(&root)
                .follow_links(false)
                .max_depth(DERIVED_DEPTH)
                .sort_by_file_name()
            {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(_) => {
                        out.incomplete = true;
                        continue;
                    }
                };
                visited += 1;
                if visited > max_entries {
                    out.incomplete = true;
                    break;
                }
                if !entry.file_type().is_file() {
                    continue;
                }
                let Some(name) = entry.file_name().to_str() else {
                    continue;
                };
                let keep = name.ends_with(".jar")
                    || sha1_like(name.split('.').next().unwrap_or(name))
                    || entry
                        .path()
                        .strip_prefix(&root)
                        .ok()
                        .and_then(Path::parent)
                        .is_some_and(|rel| {
                            rel.components()
                                .any(|c| c.as_os_str().to_str().is_some_and(sha1_like))
                        });
                if keep {
                    out.files.push((root.clone(), entry.into_path()));
                }
            }
        }
        out
    }

    /// Whether the walk did not cover every derived-cache root.
    pub fn incomplete(&self) -> bool {
        self.incomplete
    }

    /// The [`DerivedCopies`] of the jar `jar_leaf` whose pristine bytes
    /// hash to `pristine_sha1`.
    pub fn query(&self, jar_leaf: &str, pristine_sha1: &str) -> DerivedCopies {
        let instrumented = format!("instrumented-{jar_leaf}");
        let mut out = DerivedCopies {
            incomplete: self.incomplete,
            ..DerivedCopies::default()
        };
        for (root, path) in &self.files {
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let stem = name.split('.').next().unwrap_or(name);
            let by_hash = hash_eq(stem, pristine_sha1)
                || path
                    .strip_prefix(root)
                    .ok()
                    .and_then(Path::parent)
                    .is_some_and(|rel| {
                        rel.components().any(|c| {
                            c.as_os_str()
                                .to_str()
                                .is_some_and(|c| hash_eq(c, pristine_sha1))
                        })
                    });
            if by_hash {
                out.stale.push(path.clone());
            } else if name == jar_leaf || name == instrumented {
                match crate::utils::fs::read_regular_to_bytes_sync(path) {
                    Ok(bytes)
                        if hash_eq(&crate::utils::digest::sha1_hex_of(&bytes), pristine_sha1) =>
                    {
                        out.stale.push(path.clone())
                    }
                    Ok(_) => out.unknown.push(path.clone()),
                    Err(_) => {
                        out.incomplete = true;
                        out.unknown.push(path.clone());
                    }
                }
            }
        }
        out.stale.sort();
        out.unknown.sort();
        out
    }
}

// ── process environment ─────────────────────────────────────────────────

/// The process environment behind [`Env`].
pub struct ProcessEnv;

impl Env for ProcessEnv {
    fn var(&self, k: &str) -> Option<String> {
        std::env::var(k).ok()
    }
}

/// The account's home directory from the passwd database
/// (`getpwuid_r(getuid())->pw_dir`): what the JVM reports as `user.home`
/// on Linux and macOS, whatever `$HOME` says. `None` on Windows, and when
/// there is no entry or it names no directory.
#[cfg(unix)]
pub fn passwd_home() -> Option<PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;

    let uid = unsafe { libc::getuid() };
    let mut buf: Vec<libc::c_char> = vec![0; 4096];
    // SAFETY: an all-zero `passwd` is a valid out-parameter; it is only
    // read when `getpwuid_r` reports a result, and its strings point into
    // `buf`, which outlives every read below.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    loop {
        // SAFETY: `buf` is writable for `buf.len()` bytes.
        let rc =
            unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
        if rc == libc::ERANGE && buf.len() < (1 << 20) {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        break;
    }
    if result.is_null() || pwd.pw_dir.is_null() {
        return None;
    }
    // SAFETY: a non-null `pw_dir` is a NUL-terminated string inside `buf`.
    let dir = unsafe { CStr::from_ptr(pwd.pw_dir) }.to_bytes();
    (!dir.is_empty()).then(|| PathBuf::from(std::ffi::OsStr::from_bytes(dir)))
}

#[cfg(not(unix))]
pub fn passwd_home() -> Option<PathBuf> {
    None
}

/// The Gradle user home this process's Gradle would use
/// ([`GradleHome::resolve`] over the process environment and, on Unix,
/// [`passwd_home`]).
pub fn home_from_process_env() -> Option<GradleHome> {
    GradleHome::resolve(&ProcessEnv, Os::current(), passwd_home().as_deref())
}

/// `($HOME, passwd home)` when the Gradle user home came from the account's
/// home directory (no `gradle.user.home`, no `GRADLE_USER_HOME`) and `$HOME`
/// names another directory: Gradle follows the passwd entry, so its cache
/// is not under `$HOME/.gradle`. `None` on Windows and when they agree.
pub fn home_mismatch() -> Option<(PathBuf, PathBuf)> {
    home_mismatch_with(&ProcessEnv, Os::current(), passwd_home().as_deref())
}

/// [`home_mismatch`] over an explicit environment.
pub fn home_mismatch_with(
    env: &dyn Env,
    os: Os,
    passwd: Option<&Path>,
) -> Option<(PathBuf, PathBuf)> {
    if os != Os::Unix {
        return None;
    }
    let set = |k: &str| env.var(k).filter(|v| !v.is_empty());
    let explicit = set("GRADLE_USER_HOME").is_some()
        || ["GRADLE_OPTS", "JAVA_OPTS"].iter().any(|k| {
            set(k).is_some_and(|opts| {
                crate::gradle::home::system_property(&opts, "gradle.user.home", os)
                    .is_some_and(|v| !v.is_empty())
            })
        });
    let home = PathBuf::from(set("HOME")?);
    let passwd = passwd?.to_path_buf();
    let same = home == passwd
        || home
            .canonicalize()
            .ok()
            .is_some_and(|h| passwd.canonicalize().ok() == Some(h));
    (!explicit && !same).then_some((home, passwd))
}

// ── filesystem adapters ─────────────────────────────────────────────────

/// A [`crate::gradle::TextReadFn`] over the directory `root`: reads the
/// forward-slash path relative to it as strict UTF-8 with a leading BOM
/// dropped. Missing, non-regular, unreadable and non-UTF-8 files are
/// `None`. A file larger than [`graph::MAX_FILE_BYTES`] is not read: it
/// comes back as that many spaces plus one, so the graph records it as too
/// large rather than missing.
pub fn fs_text_read(root: &Path) -> impl Fn(&str) -> Option<String> + '_ {
    move |rel: &str| {
        let path = root.join(rel);
        let meta = std::fs::metadata(&path).ok()?;
        if !meta.is_file() {
            return None;
        }
        if meta.len() > graph::MAX_FILE_BYTES as u64 {
            return Some(" ".repeat(graph::MAX_FILE_BYTES + 1));
        }
        crate::gradle::dsl::decode(&crate::utils::fs::read_regular_to_bytes_sync(&path).ok()?)
    }
}

/// A [`crate::gradle::ListFn`] over the directory `root`: the UTF-8 child
/// names of the forward-slash directory relative to it, directories
/// (symlinks followed) ending in `/`, sorted. Missing = empty.
pub fn fs_list(root: &Path) -> impl Fn(&str) -> Vec<String> + '_ {
    move |rel: &str| list_dir(&root.join(rel))
}

/// [`fs_list`] for an absolute directory (the shape `GradleHome`'s
/// listing callbacks take).
pub fn list_dir(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let is_dir = std::fs::metadata(e.path()).is_ok_and(|m| m.is_dir());
            Some(if is_dir { format!("{name}/") } else { name })
        })
        .collect();
    out.sort();
    out
}

// ── init scripts ────────────────────────────────────────────────────────

/// The Gradle init scripts that apply to a build, read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InitScripts {
    /// `(path, text)` of each readable script, BOM dropped.
    pub scripts: Vec<(String, String)>,
    /// Scripts (or whole init-script sources) that exist or may exist but
    /// could not be read: not UTF-8, unreadable, or a wrapper distribution
    /// that is not unpacked yet.
    pub unreadable: Vec<String>,
}

impl InitScripts {
    fn read(&mut self, path: &Path) {
        let Ok(meta) = std::fs::metadata(path) else {
            return;
        };
        if !meta.is_file() {
            return;
        }
        let tag = path.to_string_lossy().into_owned();
        match crate::utils::fs::read_regular_to_bytes_sync(path)
            .ok()
            .and_then(|b| crate::gradle::dsl::decode(&b))
        {
            Some(text) => self.scripts.push((tag, text)),
            None => self.unreadable.push(tag),
        }
    }
}

/// Every init script of the user home, `$GRADLE_HOME` and every unpacked
/// wrapper distribution ([`GradleHome::init_scripts_with`]), read.
pub fn read_init_scripts(home: &GradleHome) -> InitScripts {
    let mut out = InitScripts::default();
    for path in home.init_scripts_with(&list_dir) {
        out.read(&path);
    }
    out
}

/// Where a build keeps its wrapper's properties, relative to its root.
const WRAPPER_PROPERTIES: &str = "gradle/wrapper/gradle-wrapper.properties";

/// The key/value pairs of a `.properties` file, read the way
/// `java.util.Properties.load(InputStream)` reads it: bytes are ISO-8859-1
/// (a leading UTF-8 BOM is dropped), `#`/`!` lines are comments, a line
/// ending in an odd number of backslashes continues on the next, the key
/// ends at the first unescaped `=`, `:` or whitespace, and `\t`, `\n`,
/// `\r`, `\f`, `\uXXXX` and `\<char>` escapes are resolved. A later key
/// wins.
fn parse_properties(bytes: &[u8]) -> HashMap<String, String> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let text: String = bytes.iter().map(|&b| b as char).collect();
    let text = text.replace("\r\n", "\n");
    let is_ws = |c: char| matches!(c, ' ' | '\t' | '\x0c');
    let mut out = HashMap::new();
    let mut lines = text.split(['\n', '\r']);
    while let Some(first) = lines.next() {
        let first = first.trim_start_matches(is_ws);
        if first.is_empty() || first.starts_with(['#', '!']) {
            continue;
        }
        // Join continuation lines (an odd run of trailing backslashes).
        let mut logical = String::new();
        let mut line = first.to_string();
        loop {
            let trailing = line.chars().rev().take_while(|&c| c == '\\').count();
            if trailing % 2 == 0 {
                logical.push_str(&line);
                break;
            }
            logical.push_str(&line[..line.len() - 1]);
            match lines.next() {
                Some(next) => line = next.trim_start_matches(is_ws).to_string(),
                None => break,
            }
        }
        let mut chars = logical.chars().peekable();
        let mut key = String::new();
        let mut value = String::new();
        let mut in_key = true;
        while let Some(c) = chars.next() {
            if in_key && (c == '=' || c == ':' || is_ws(c)) {
                in_key = false;
                while chars.peek().is_some_and(|&c| is_ws(c)) {
                    chars.next();
                }
                // Whitespace then `=`/`:` is one separator.
                if is_ws(c) && chars.peek().is_some_and(|&c| c == '=' || c == ':') {
                    chars.next();
                    while chars.peek().is_some_and(|&c| is_ws(c)) {
                        chars.next();
                    }
                }
                continue;
            }
            let c = if c == '\\' {
                match chars.next() {
                    Some('t') => '\t',
                    Some('n') => '\n',
                    Some('r') => '\r',
                    Some('f') => '\x0c',
                    Some('u') => {
                        let hex: String = (0..4).filter_map(|_| chars.next()).collect();
                        u32::from_str_radix(&hex, 16)
                            .ok()
                            .and_then(char::from_u32)
                            .unwrap_or('\u{fffd}')
                    }
                    Some(other) => other,
                    None => continue,
                }
            } else {
                c
            };
            if in_key {
                key.push(c);
            } else {
                value.push(c);
            }
        }
        out.insert(key, value);
    }
    out
}

/// What `gradle/wrapper/gradle-wrapper.properties` says about where the
/// wrapper's distribution unpacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapperProps {
    /// `distributionUrl`, property escapes removed.
    pub url: String,
    /// `distributionBase=PROJECT`: relative to the build root instead of
    /// the Gradle user home.
    pub project_base: bool,
    /// `distributionPath` (default `wrapper/dists`).
    pub path: String,
}

impl WrapperProps {
    /// The properties of the wrapper of the build at `root`: `None` when it
    /// has no `gradle/wrapper/gradle-wrapper.properties`, an error naming
    /// the file when it exists but names no distribution (unreadable, too
    /// large, or no `distributionUrl`). Read as `java.util.Properties`
    /// does: ISO-8859-1, `=`, `:` or whitespace between key and value,
    /// backslash escapes and continuation lines.
    pub fn of(root: &Path) -> Option<Result<Self, String>> {
        let path = root.join(WRAPPER_PROPERTIES);
        let meta = std::fs::metadata(&path).ok()?;
        let unusable = |why: &str| Some(Err(format!("{} ({why})", path.display())));
        if !meta.is_file() {
            return unusable("not a file");
        }
        if meta.len() > graph::MAX_FILE_BYTES as u64 {
            return unusable("too large");
        }
        let Ok(bytes) = crate::utils::fs::read_regular_to_bytes_sync(&path) else {
            return unusable("unreadable");
        };
        let mut props = parse_properties(&bytes);
        let Some(url) = props
            .remove("distributionUrl")
            .filter(|u| !u.trim().is_empty())
        else {
            return unusable("no distributionUrl");
        };
        Some(Ok(Self {
            url: url.trim().to_string(),
            project_base: props
                .get("distributionBase")
                .is_some_and(|b| b.trim() == "PROJECT"),
            path: props
                .remove("distributionPath")
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .unwrap_or_else(|| "wrapper/dists".to_string()),
        }))
    }

    /// The distribution's directory name: the URL's file name without
    /// `.zip`.
    pub fn name(&self) -> &str {
        let file = self.url.rsplit('/').next().unwrap_or(&self.url);
        file.strip_suffix(".zip").unwrap_or(file)
    }

    /// A stock Gradle distribution (which ships no init scripts).
    pub fn is_stock(&self) -> bool {
        let url = self.url.trim();
        [
            "https://services.gradle.org/distributions/",
            "https://services.gradle.org/distributions-snapshots/",
        ]
        .iter()
        .any(|p| url.starts_with(p))
    }
}

/// The `init.d` directories of one wrapper distribution unpacked under
/// `dists` (`<dists>/<name>/<url hash>/<dir>/init.d`). `None` when it is not
/// unpacked at all.
fn dist_init_dirs(dists: &Path, name: &str) -> Option<Vec<PathBuf>> {
    let subdirs = |d: &Path| -> Vec<PathBuf> {
        list_dir(d)
            .into_iter()
            .filter_map(|n| n.strip_suffix('/').map(|n| d.join(n)))
            .collect()
    };
    let mut unpacked = false;
    let mut out = Vec::new();
    for hash in subdirs(&dists.join(name)) {
        for top in subdirs(&hash) {
            unpacked = true;
            let init = top.join("init.d");
            if init.is_dir() {
                out.push(init);
            }
        }
    }
    unpacked.then_some(out)
}

/// The init scripts that apply to the build rooted at `build_root`: the user
/// home's fixed scripts and `init.d`, `$GRADLE_HOME/init.d`, and the
/// `init.d` of the distribution its wrapper names (wherever
/// `distributionBase` / `distributionPath` unpack it). Without a wrapper,
/// every unpacked wrapper distribution's `init.d` counts (the build may run
/// any of them). A wrapper whose distribution is not a stock Gradle one and
/// is not unpacked yet cannot be read: it is reported unreadable, so
/// `mavenLocal()` stays undetermined.
pub fn init_scripts_for_build(home: &GradleHome, build_root: &Path) -> InitScripts {
    let wrapper = match WrapperProps::of(build_root) {
        None => return read_init_scripts(home),
        Some(Ok(wrapper)) => wrapper,
        Some(Err(why)) => {
            // A wrapper names a distribution this run cannot identify: its
            // init.d may declare anything.
            let mut out = read_init_scripts(home);
            out.unreadable.push(format!("wrapper properties {why}"));
            return out;
        }
    };
    let mut out = InitScripts::default();
    for path in home.init_script_paths() {
        out.read(&path);
    }
    let base = if wrapper.project_base {
        build_root
    } else {
        home.user_home.as_path()
    };
    let dists = base.join(&wrapper.path);
    let mut dirs = vec![home.user_home.join("init.d")];
    match dist_init_dirs(&dists, wrapper.name()) {
        Some(found) => dirs.extend(found),
        None if !wrapper.is_stock() => out.unreadable.push(format!(
            "wrapper distribution {} (not unpacked under {})",
            wrapper.url,
            dists.display()
        )),
        None => {}
    }
    dirs.extend(home.gradle_home.as_ref().map(|g| g.join("init.d")));
    for dir in dirs {
        for name in list_dir(&dir) {
            if is_init_script_name(&name) {
                out.read(&dir.join(name));
            }
        }
    }
    out
}

// ── the build and mavenLocal() ──────────────────────────────────────────

/// Whether `dir` holds a Gradle settings script.
fn has_settings(dir: &Path) -> bool {
    layout::GRADLE_SETTINGS_FILES
        .iter()
        .any(|s| layout::marker_present(dir, s))
}

/// The Gradle build roots to analyse for a cwd that is a Gradle project:
/// the cwd itself and, when it has no settings script, the nearest ancestor
/// that has one (Gradle searches upwards for the settings of a
/// subproject). Empty when the cwd has no Gradle marker.
pub fn build_roots(cwd: &Path) -> Vec<PathBuf> {
    if !layout::has_build(cwd, BuildTool::Gradle) {
        return Vec::new();
    }
    let mut roots = vec![cwd.to_path_buf()];
    if !has_settings(cwd) {
        if let Some(up) = cwd.ancestors().skip(1).find(|d| has_settings(d)) {
            roots.push(up.to_path_buf());
        }
    }
    roots
}

/// The script graph of the build at `root`, with the init scripts that
/// apply to it (unreadable ones noted).
pub fn script_graph(root: &Path, init: &InitScripts) -> ScriptGraph {
    let read = fs_text_read(root);
    let list = fs_list(root);
    let mut graph = ScriptGraph::collect(&read, &list, "", &init.scripts);
    for tag in &init.unreadable {
        graph.note_unreadable_init_script(tag);
    }
    graph
}

/// Whether the Gradle build at `cwd` reads the Maven local repository
/// (`mavenLocal()`), across every build root ([`build_roots`]) and the init
/// scripts that apply. `home` is the Gradle user home (`None` = unknown,
/// so the init scripts are too). Declared wins over undetermined, which
/// wins over not declared.
pub fn maven_local(cwd: &Path, home: Option<&GradleHome>) -> MavenLocal {
    let mut verdict = MavenLocal::NotDeclared;
    for root in build_roots(cwd) {
        let init = match home {
            Some(home) => init_scripts_for_build(home, &root),
            None => InitScripts {
                unreadable: vec!["(no Gradle user home could be resolved)".to_string()],
                ..InitScripts::default()
            },
        };
        match script_graph(&root, &init).maven_local() {
            declared @ MavenLocal::Declared(_) => return declared,
            undetermined @ MavenLocal::Undetermined(_) => {
                if verdict == MavenLocal::NotDeclared {
                    verdict = undetermined;
                }
            }
            MavenLocal::NotDeclared => {}
        }
    }
    verdict
}

/// The modules locked by the lock files of the Gradle build at `cwd`
/// (every build root's graph-scoped lock files,
/// `ScriptGraph::lockfile_paths`). An annotation only: locks never narrow
/// discovery.
pub fn locked_gavs(cwd: &Path) -> BTreeSet<Gav> {
    let mut out = BTreeSet::new();
    for root in build_roots(cwd) {
        let graph = script_graph(&root, &InitScripts::default());
        let read = fs_text_read(&root);
        for rel in graph.lockfile_paths(&fs_list(&root)) {
            let Some(text) = read(&rel) else {
                continue;
            };
            for e in crate::gradle::locks::parse(&text).entries {
                out.insert((e.group, e.artifact, e.version));
            }
        }
    }
    out
}
