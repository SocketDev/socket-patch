//! The IO side of sbt resolution evidence: walk a build root for the
//! records `formats::sbt::evidence` parses, read them FIFO-safely within
//! caps, and judge their freshness against the build sources.
//!
//! The walk locates `target/` directories to depth [`MAX_TARGET_DEPTH`]
//! (skipping [`SKIP_DIRS`] and a top-level Mill `out/`; never following
//! symlinks), then descends below each `target/` only along the evidence
//! patterns (`formats::sbt::evidence`'s table), however deep they go. The
//! build sources (`formats::sbt::build::source_kind`) are collected on the
//! same walk. Caps: [`MAX_FILES`] files, [`MAX_TOTAL_BYTES`] in all,
//! [`MAX_FILE_BYTES`] per file, for the evidence and the sources each, and
//! [`MAX_ENTRIES`] directory entries visited; over a cap there is no
//! evidence at all (never a partial resolution, which could hide a
//! project's conflicting version).
//!
//! Staleness ([`SbtEvidence::stale`]): a build source (root `*.sbt`,
//! `project/*.{scala,sbt}`, `project/build.properties`, `<P>/*.sbt`) is
//! newer than some project's evidence, each project dated by its newest
//! library evidence file or sibling `inputs`. Probe (every version): `sbt
//! update` rewrites each resolved project's `output` even when its `inputs`
//! hash is unchanged, so after any `update` the evidence is newer than the
//! sources it read; a project the run did not resolve (`sbt core/test`
//! leaves `api` alone, as does another Scala version of a cross build)
//! keeps its old files, so one project's fresh record never vouches for
//! another's. The meta-build's records never date the evidence: every sbt
//! load (`sbt projects`, an IDE import) rewrites the meta-build's `output`
//! without resolving any library (probe, 1.9.9 and 2.0.9).

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::jvm_cache::{JvmCacheLayout, JvmCacheRoot};
use crate::formats::sbt::build::{
    declared_projects, source_kind, SourceKind, BUILD_PROPERTIES, BUILD_SBT,
};
use crate::formats::sbt::evidence::{classify_path, is_meta_record, ResolutionDoc};
use crate::formats::sbt::owned_file::{HOSTED_FILE, VENDORED_FILE};
use crate::formats::sbt::JvmResolution;
use crate::utils::fs::read_regular_to_bytes_sync;

/// How deep (in path segments below the root) a `target/` directory is
/// looked for.
pub const MAX_TARGET_DEPTH: usize = 6;
/// The most evidence files (and, separately, build sources) read.
pub const MAX_FILES: usize = 512;
/// The most bytes read in all, per kind.
pub const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
/// The largest single file read.
pub const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
/// The most directory entries the walk visits.
pub const MAX_ENTRIES: usize = 200_000;
/// Directories never descended into above a `target/`.
pub const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    ".socket",
    ".bsp",
    ".idea",
    ".metals",
    ".bloop",
    ".scala-build",
];

/// The evidence files and build sources of one build root.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SbtEvidence {
    /// `(root-relative path, bytes)` of every evidence file.
    pub files: Vec<(String, Vec<u8>)>,
    /// `(root-relative path, text)` of every build source
    /// (`formats::sbt::build::source_kind`).
    pub build_sources: Vec<(String, String)>,
    /// A build source is newer than some project's newest evidence
    /// `output` / `inputs` (the least recently resolved project's).
    pub stale: bool,
    /// The build root's directory name (canonical), which names sbt 2's
    /// meta-build and implicit root project.
    pub root_name: String,
    /// The newest library (not meta-build) evidence file (or sibling
    /// `inputs`) modification time.
    pub newest_evidence: Option<SystemTime>,
    /// A generated file ([`HOSTED_FILE`] / [`VENDORED_FILE`]) is newer than
    /// the newest evidence: sbt has not resolved since the last wiring.
    pub wiring_newer: bool,
}

/// The evidence under `root`, `None` when there is none (or a cap was hit,
/// or a file could not be read).
pub fn discover(root: &Path) -> Option<SbtEvidence> {
    scan(root).ok().filter(|e| !e.files.is_empty())
}

/// Everything the walk found under `root` (the evidence possibly empty: the
/// build sources still name the projects and the dependency digest), or why
/// nothing can be trusted (a cap, an unreadable file).
pub fn scan(root: &Path) -> Result<SbtEvidence, String> {
    let mut walk = Walk {
        root,
        entries: 0,
        evidence: Budget::default(),
        sources: Budget::default(),
        out: SbtEvidence::default(),
        newest_source: None,
        generated: None,
        dated: Vec::new(),
    };
    walk.dir(&mut Vec::new())?;
    let mut out = walk.out;
    out.files.sort();
    out.build_sources.sort();
    out.root_name = std::fs::canonicalize(root)
        .ok()
        .as_deref()
        .unwrap_or(root)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string();
    // Date the evidence by its library records only, per project (see the
    // module doc).
    let declared = declared_projects(&out.build_sources);
    let mut per_project: std::collections::BTreeMap<(String, bool), Option<SystemTime>> =
        std::collections::BTreeMap::new();
    for (rel, modified) in &walk.dated {
        let output = rel
            .strip_suffix("/inputs")
            .map(|dir| format!("{dir}/output"));
        let Some(record) = classify_path(output.as_deref().unwrap_or(rel), &out.root_name) else {
            continue;
        };
        if is_meta_record(&record, declared.as_ref(), &out.root_name) {
            continue;
        }
        newer(&mut out.newest_evidence, *modified);
        newer(
            per_project
                .entry((record.project, record.project_is_id))
                .or_default(),
            *modified,
        );
    }
    if let Some(newest) = out.newest_evidence {
        // The least recently resolved project dates the build: a source
        // edited after it may change what that project resolves.
        let oldest_project = per_project.values().flatten().min().copied();
        out.stale = walk
            .newest_source
            .is_some_and(|s| oldest_project.is_some_and(|o| s > o));
        out.wiring_newer = walk.generated.is_some_and(|g| g > newest);
    }
    Ok(out)
}

/// The [`ResolutionDoc`] of the sbt build at `root`, what the hosted
/// rewriter (`hosted::sbt_reads`) and the vendored gate
/// (`vendor::jvm::sbt_gate`) decide on: the resolution, the declared
/// projects, staleness and the dependency digest, or why the evidence could
/// not be read (then no resolution and, for a walk cap, no build facts).
pub fn distill(root: &Path) -> ResolutionDoc {
    let canonical = std::fs::canonicalize(root)
        .map(|c| strip_verbatim(&c))
        .unwrap_or_else(|_| root.to_path_buf());
    let evidence = match scan(root) {
        Ok(evidence) => evidence,
        Err(reason) => {
            return ResolutionDoc {
                root: canonical,
                read_error: Some(reason),
                ..Default::default()
            }
        }
    };
    let res = resolution(&evidence);
    let read_error = (res.is_none() && !evidence.files.is_empty())
        .then(|| "an sbt resolution record under target/ is malformed".to_string());
    let artifact_sha256 = res.as_ref().map(pinned_artifact_hashes).unwrap_or_default();
    ResolutionDoc {
        read_error,
        artifact_sha256,
        ..ResolutionDoc::from_parts(
            canonical,
            res,
            &evidence.build_sources,
            evidence.stale,
            evidence.wiring_newer,
        )
    }
}

/// Most pinned artifact files [`pinned_artifact_hashes`] hashes per run.
pub const MAX_HASHED_ARTIFACTS: usize = 64;
/// Largest artifact file it hashes (bigger: left unhashed, so a copy
/// outside the pin repository still reads as resolved elsewhere).
pub const MAX_HASHED_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

/// sha256 hex of every artifact file `res` resolves at a Socket-suffixed
/// version (a pin's), for the content-based re-check of existing pins
/// (`formats::sbt::gate::check_existing`). Bounded by
/// [`MAX_HASHED_ARTIFACTS`] / [`MAX_HASHED_ARTIFACT_BYTES`]; FIFO-safe, a
/// symlink or non-regular file is never hashed.
pub fn pinned_artifact_hashes(res: &JvmResolution) -> std::collections::BTreeMap<PathBuf, String> {
    use sha2::{Digest, Sha256};
    use std::io::Read as _;
    let mut out = std::collections::BTreeMap::new();
    let pinned = res
        .artifacts
        .iter()
        .filter(|((_, _, v), _)| crate::formats::maven::split_socket_version(v).is_some())
        .flat_map(|(_, paths)| paths.iter());
    for path in pinned.take(MAX_HASHED_ARTIFACTS) {
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            continue;
        };
        if !meta.is_file() || meta.len() > MAX_HASHED_ARTIFACT_BYTES {
            continue;
        }
        let Ok((mut file, meta)) = crate::utils::fs::open_regular_file_sync(path) else {
            continue;
        };
        if meta.len() > MAX_HASHED_ARTIFACT_BYTES {
            continue;
        }
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        let complete = loop {
            match file.read(&mut buf) {
                Ok(0) => break true,
                Ok(n) => hasher.update(&buf[..n]),
                Err(_) => break false,
            }
        };
        if complete {
            out.insert(path.clone(), hex::encode(hasher.finalize()));
        }
    }
    out
}

/// `path` without Windows' verbatim prefix (`\\?\C:\x` → `C:\x`,
/// `\\?\UNC\srv\share` → `\\srv\share`), which `canonicalize` adds and
/// sbt's `file:` URIs never carry: a verbatim root starts no artifact path,
/// so every pinned jar would read as resolved elsewhere.
pub(crate) fn strip_verbatim(path: &Path) -> std::path::PathBuf {
    let Some(text) = path.to_str() else {
        return path.to_path_buf();
    };
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}").into()
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        rest.into()
    } else {
        path.to_path_buf()
    }
}

/// The resolution `e` records (`None` when no file parses as evidence).
pub fn resolution(e: &SbtEvidence) -> Option<JvmResolution> {
    let declared = crate::formats::sbt::build::declared_projects(&e.build_sources);
    crate::formats::sbt::evidence::resolution(&e.files, declared.as_ref(), &e.root_name)
}

/// Extra JVM cache roots the local evidence names: the Coursier / Ivy /
/// Maven directories its artifact paths point into (a cache relocated by a
/// build option the environment does not show). Only for an sbt build;
/// never a root under a `.socket/` directory (socket-patch's own pin
/// repositories, here or in another checkout).
pub fn cache_roots(root: &Path) -> Vec<JvmCacheRoot> {
    let marker = |rel: &str| {
        std::fs::symlink_metadata(root.join(rel)).is_ok_and(|m| m.file_type().is_file())
    };
    if !marker(BUILD_SBT) && !marker(BUILD_PROPERTIES) {
        return Vec::new();
    }
    let Some(res) = discover(root).as_ref().and_then(resolution) else {
        return Vec::new();
    };
    let mut roots: Vec<JvmCacheRoot> = res
        .artifacts
        .iter()
        .flat_map(|((g, a, v), paths)| paths.iter().filter_map(move |p| cache_root_of(g, a, v, p)))
        .filter(|r| !r.path.components().any(|c| c.as_os_str() == ".socket") && r.path.is_dir())
        .collect();
    roots.sort();
    roots.dedup();
    roots
}

/// The cache root holding `path`, the artifact of `g:a:v`: a Maven2
/// (Coursier per-repository, `~/.m2`) `<root>/<g/…>/<a>/<v>/<file>`, or an
/// Ivy `<root>/<g>/<a>/<type>s/<file>`, accepted only when
/// [`JvmCacheLayout::classify`] reads the root as that layout.
fn cache_root_of(g: &str, a: &str, v: &str, path: &Path) -> Option<JvmCacheRoot> {
    fn name(p: Option<&Path>) -> Option<&str> {
        p.and_then(Path::file_name).and_then(|n| n.to_str())
    }
    let parent = path.parent()?;
    if name(Some(parent)) == Some(v) && name(parent.parent()) == Some(a) {
        let mut dir = parent.parent()?.parent()?;
        let mut ok = true;
        for seg in g.split('.').rev() {
            if name(Some(dir)) != Some(seg) {
                ok = false;
                break;
            }
            dir = dir.parent()?;
        }
        if ok {
            let layout = JvmCacheLayout::classify(dir);
            if matches!(layout, JvmCacheLayout::Coursier | JvmCacheLayout::Maven2) {
                return Some(JvmCacheRoot::new(dir.to_path_buf(), layout));
            }
        }
    }
    let module = parent.parent()?;
    if name(Some(module)) == Some(a) && name(module.parent()) == Some(g) {
        let dir = module.parent()?.parent()?;
        if JvmCacheLayout::classify(dir) == JvmCacheLayout::Ivy {
            return Some(JvmCacheRoot::new(dir.to_path_buf(), JvmCacheLayout::Ivy));
        }
    }
    None
}

#[derive(Default)]
struct Budget {
    files: usize,
    bytes: u64,
}

impl Budget {
    fn charge(&mut self, what: &str, rel: &str, len: u64) -> Result<(), String> {
        self.files += 1;
        self.bytes += len;
        if len > MAX_FILE_BYTES {
            return Err(format!(
                "{rel} is over the {MAX_FILE_BYTES}-byte {what} cap"
            ));
        }
        if self.files > MAX_FILES || self.bytes > MAX_TOTAL_BYTES {
            return Err(format!(
                "over the {what} cap ({MAX_FILES} files / {MAX_TOTAL_BYTES} bytes)"
            ));
        }
        Ok(())
    }
}

struct Walk<'a> {
    root: &'a Path,
    entries: usize,
    evidence: Budget,
    sources: Budget,
    out: SbtEvidence,
    newest_source: Option<SystemTime>,
    generated: Option<SystemTime>,
    /// `(rel, mtime)` of every evidence file and sibling `inputs`, dated
    /// once the walk knows the root name and the declared projects.
    dated: Vec<(String, Option<SystemTime>)>,
}

/// One segment of an evidence pattern below `target/`.
#[derive(Clone, Copy)]
enum Seg {
    Lit(&'static str),
    Any,
    /// `scala-*`.
    Scala,
    /// `sbt-*` (the meta-build's sbt binary version).
    Sbt,
    /// `update_cache` or `update_cache_*`.
    Cache,
    /// `$global` / `_global`.
    Global,
    /// `*.xml`.
    Xml,
    /// The leaf: `output`, or its sibling `inputs` (dating only).
    Output,
}

use Seg::*;

/// `formats::sbt::evidence`'s table, as descent patterns.
const PATTERNS: &[&[Seg]] = &[
    &[Lit("out"), Any, Any, Any, Lit("update"), Cache, Output],
    &[Scala, Lit("update"), Cache, Output],
    &[Scala, Sbt, Lit("update"), Cache, Output],
    &[Lit("update"), Lit("update_cache"), Output],
    &[
        Lit("streams"),
        Global,
        Lit("update"),
        Global,
        Lit("streams"),
        Cache,
        Output,
    ],
    &[Lit("resolution-cache"), Lit("reports"), Xml],
    &[Scala, Lit("resolution-cache"), Lit("reports"), Xml],
    &[Scala, Sbt, Lit("resolution-cache"), Lit("reports"), Xml],
];

impl Seg {
    fn matches(self, s: &str) -> bool {
        match self {
            Lit(l) => s == l,
            Any => true,
            Scala => s.starts_with("scala-"),
            Sbt => s.starts_with("sbt-"),
            Cache => s == "update_cache" || s.starts_with("update_cache_"),
            Global => s == "$global" || s == "_global",
            Xml => s.ends_with(".xml"),
            Output => s == "output" || s == "inputs",
        }
    }
}

/// Whether `tail` (below `target/`) can still grow into a pattern
/// (`leaf == false`) or is a whole one (`leaf == true`).
fn tail_matches(tail: &[&str], leaf: bool) -> bool {
    PATTERNS.iter().any(|p| {
        (if leaf {
            p.len() == tail.len()
        } else {
            p.len() > tail.len()
        }) && p.iter().zip(tail).all(|(seg, s)| seg.matches(s))
    })
}

fn newer(slot: &mut Option<SystemTime>, t: Option<SystemTime>) {
    if let Some(t) = t {
        if slot.is_none_or(|s| t > s) {
            *slot = Some(t);
        }
    }
}

impl Walk<'_> {
    /// The entries of `rel` (root-relative segments), sorted, symlinks
    /// included (the callers skip them).
    fn list(&mut self, rel: &[String]) -> Result<Vec<(String, std::fs::Metadata)>, String> {
        let dir = rel.iter().fold(self.root.to_path_buf(), |p, s| p.join(s));
        let iter = match std::fs::read_dir(&dir) {
            Ok(iter) => iter,
            // Vanished or unlistable mid-walk: nothing below it.
            Err(_) => return Ok(Vec::new()),
        };
        let mut out = Vec::new();
        for entry in iter.flatten() {
            self.entries += 1;
            if self.entries > MAX_ENTRIES {
                return Err(format!("over the {MAX_ENTRIES}-entry walk cap"));
            }
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            // `symlink_metadata`: a symlink is reported as one.
            if let Ok(meta) = std::fs::symlink_metadata(entry.path()) {
                out.push((name, meta));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    /// Read `rel` FIFO-safely within `budget`; `Ok(None)` when it vanished.
    fn read(
        &mut self,
        rel: &str,
        meta: &std::fs::Metadata,
        evidence: bool,
    ) -> Result<Option<Vec<u8>>, String> {
        let (what, budget) = if evidence {
            ("evidence", &mut self.evidence)
        } else {
            ("build source", &mut self.sources)
        };
        budget.charge(what, rel, meta.len())?;
        match read_regular_to_bytes_sync(&self.root.join(rel)) {
            Ok(bytes) if bytes.len() as u64 > MAX_FILE_BYTES => Err(format!(
                "{rel} is over the {MAX_FILE_BYTES}-byte {what} cap"
            )),
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{rel}: {e}")),
        }
    }

    fn dir(&mut self, rel: &mut Vec<String>) -> Result<(), String> {
        for (name, meta) in self.list(rel)? {
            let ft = meta.file_type();
            if ft.is_symlink() {
                continue;
            }
            rel.push(name);
            let result = if ft.is_dir() {
                let name = rel.last().expect("pushed").as_str();
                if name == "target" {
                    self.target(rel, &mut Vec::new())
                } else if SKIP_DIRS.contains(&name)
                    || (rel.len() == 1 && name == "out")
                    || rel.len() >= MAX_TARGET_DEPTH
                {
                    Ok(())
                } else {
                    self.dir(rel)
                }
            } else {
                self.file(&rel.join("/"), &meta)
            };
            rel.pop();
            result?;
        }
        Ok(())
    }

    /// A non-evidence file above any `target/`: a build source, or a
    /// generated file (dated only).
    fn file(&mut self, rel: &str, meta: &std::fs::Metadata) -> Result<(), String> {
        if rel == HOSTED_FILE || rel == VENDORED_FILE {
            newer(&mut self.generated, meta.modified().ok());
            return Ok(());
        }
        let Some(kind) = source_kind(rel) else {
            return Ok(());
        };
        let Some(bytes) = self.read(rel, meta, false)? else {
            return Ok(());
        };
        if matches!(
            kind,
            SourceKind::Definition
                | SourceKind::Subproject
                | SourceKind::Meta
                | SourceKind::Properties
        ) {
            newer(&mut self.newest_source, meta.modified().ok());
        }
        self.out.build_sources.push((
            rel.to_string(),
            String::from_utf8_lossy(&bytes).into_owned(),
        ));
        Ok(())
    }

    /// Below the `target/` at `base`: only along [`PATTERNS`].
    fn target(&mut self, base: &[String], tail: &mut Vec<String>) -> Result<(), String> {
        let here: Vec<String> = base.iter().chain(tail.iter()).cloned().collect();
        for (name, meta) in self.list(&here)? {
            let ft = meta.file_type();
            if ft.is_symlink() {
                continue;
            }
            tail.push(name);
            let segs: Vec<&str> = tail.iter().map(String::as_str).collect();
            let result = if ft.is_dir() {
                if tail_matches(&segs, false) {
                    self.target(base, tail)
                } else {
                    Ok(())
                }
            } else if tail_matches(&segs, true) {
                // A non-regular file (a FIFO) at an evidence path fails the
                // FIFO-safe read: no evidence, never a wedge.
                let rel = here
                    .iter()
                    .chain(tail.last())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("/");
                self.evidence_file(&rel, &meta)
            } else {
                Ok(())
            };
            tail.pop();
            result?;
        }
        Ok(())
    }

    fn evidence_file(&mut self, rel: &str, meta: &std::fs::Metadata) -> Result<(), String> {
        if rel.ends_with("/inputs") {
            self.dated.push((rel.to_string(), meta.modified().ok()));
            return Ok(());
        }
        // The descent patterns and the parser's classifier agree; the
        // classifier has the last word (sbt 2's shape only at the root).
        if classify_path(rel, "").is_none() {
            return Ok(());
        }
        if let Some(bytes) = self.read(rel, meta, true)? {
            self.dated.push((rel.to_string(), meta.modified().ok()));
            self.out.files.push((rel.to_string(), bytes));
        }
        Ok(())
    }
}

/// Copy a committed evidence fixture to `to`, dated as sbt leaves it: the
/// build sources an hour ago, every record under `target/` a minute later.
/// (`std::fs::copy` stamps each copy "now" on Linux, in `read_dir` order,
/// which would make a fixture's freshness depend on directory hashing.)
#[cfg(test)]
pub(crate) fn stage_fixture(from: &Path, to: &Path) {
    fn copy(from: &Path, to: &Path, rel: &Path, out: &mut Vec<(std::path::PathBuf, bool)>) {
        std::fs::create_dir_all(to.join(rel)).unwrap();
        for entry in std::fs::read_dir(from.join(rel)).unwrap() {
            let entry = entry.unwrap();
            let child = rel.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy(from, to, &child, out);
            } else {
                std::fs::copy(entry.path(), to.join(&child)).unwrap();
                let record = child.components().any(|c| c.as_os_str() == "target");
                out.push((to.join(&child), record));
            }
        }
    }
    let mut files = Vec::new();
    copy(from, to, Path::new(""), &mut files);
    let sources = SystemTime::now() - std::time::Duration::from_secs(3600);
    for (path, record) in files {
        let at = if record {
            sources + std::time::Duration::from_secs(60)
        } else {
            sources
        };
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(at)
            .unwrap();
    }
}

#[cfg(test)]
mod tests;
