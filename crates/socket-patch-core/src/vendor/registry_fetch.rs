//! Bounded archive readers, integrity verification and registry metadata transport.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::api::retry::ApiTimeouts;
use crate::constants::USER_AGENT;
use crate::patch::apply::is_safe_relative_subpath;

use super::lock_inventory::LockIntegrity;

/// The default npm registry; override with `SOCKET_NPM_REGISTRY` (the
/// enterprise-mirror / test escape hatch — `.npmrc` parsing is out of
/// scope, but lock-recorded `resolved` URLs already carry custom hosts).
pub const DEFAULT_NPM_REGISTRY: &str = "https://registry.npmjs.org";

/// Whole-package caps — wider than `patch/package.rs`'s patch-archive caps
/// because these are full upstream packages, but still bounded so a
/// poisoned lockfile cannot turn the fetch into a disk/memory bomb.
pub(crate) const MAX_DOWNLOAD_BYTES: u64 = 128 * 1024 * 1024;
// `pub(crate)`: `common::read_zip_members` is the in-memory twin of
// [`extract_zip`] and must refuse exactly the same archives, so it reads the
// one set of caps rather than carrying a copy that can drift.
pub(crate) const MAX_TOTAL_DECOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const MAX_ENTRY_BYTES: u64 = 128 * 1024 * 1024;
pub(crate) const MAX_ENTRIES: usize = 60_000;

#[derive(Debug)]
pub enum FetchError {
    /// The entry cannot be verified against the lockfile (no integrity
    /// recorded, or no fetcher for its ecosystem) — decided BEFORE any
    /// network I/O; the caller keeps its `package_not_installed` outcome.
    Unverifiable(String),
    /// The fetch was attempted and failed (HTTP error, size cap, integrity
    /// mismatch, extraction failure). User-facing message.
    Failed(String),
}

/// Shared registry HTTP client for metadata and verified artifact downloads.
pub type RegistryClient = reqwest::Client;

pub fn build_registry_client() -> RegistryClient {
    registry_client_builder(USER_AGENT)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// The one builder behind every registry client (npm-family, PyPI, Go,
/// NuGet, Maven), sending `user_agent`. It applies the shared
/// [`ApiTimeouts`] transport policy: a connect bound plus an idle read
/// bound that restarts on every chunk, and no total deadline, so a large
/// artifact that keeps streaming is never cut off while a stalled host
/// still fails the fetch.
pub(crate) fn registry_client_builder(user_agent: &str) -> reqwest::ClientBuilder {
    registry_timeouts().apply(reqwest::Client::builder().user_agent(user_agent))
}

fn registry_timeouts() -> ApiTimeouts {
    #[cfg(test)]
    if let Some(t) = test_timeouts::get() {
        return t;
    }
    ApiTimeouts::default()
}

/// Test-only override of [`registry_timeouts`] for the current thread, so a
/// test can prove the idle bound and the absence of a total deadline in
/// seconds rather than minutes. `#[tokio::test]` runs on one thread.
#[cfg(test)]
pub(crate) mod test_timeouts {
    use std::cell::Cell;

    use crate::api::retry::ApiTimeouts;

    thread_local! {
        static OVERRIDE: Cell<Option<ApiTimeouts>> = const { Cell::new(None) };
    }

    pub(crate) fn get() -> Option<ApiTimeouts> {
        OVERRIDE.with(Cell::get)
    }

    /// Shortens the bounds until the returned guard drops.
    pub(crate) fn set(t: ApiTimeouts) -> Guard {
        OVERRIDE.with(|c| c.set(Some(t)));
        Guard
    }

    pub(crate) struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            OVERRIDE.with(|c| c.set(None));
        }
    }
}

/// The npm registry base after the env override.
pub fn npm_registry_base() -> String {
    std::env::var("SOCKET_NPM_REGISTRY")
        .ok()
        .map(|v| v.trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_NPM_REGISTRY.to_string())
}

/// Conventional npm tarball URL: the scope stays in the package path, the
/// tarball leaf uses the bare name —
/// `{base}/@scope/name/-/name-1.0.0.tgz` / `{base}/name/-/name-1.0.0.tgz`.
pub fn npm_tarball_url(base: &str, name: &str, version: &str) -> String {
    let leaf = name.rsplit('/').next().unwrap_or(name);
    format!("{base}/{name}/-/{leaf}-{version}.tgz")
}

/// Whether `url` is the tarball URL a package manager derives on its own
/// for `name@version` under the registry `base` — and so leaves out of its
/// lock. pnpm drops `tarball:` and yarn berry drops the
/// `::__archiveUrl=` binding only for such a URL (pnpm's
/// `toLockfileResolution`, yarn's `isConventionalTarballUrl`); every other
/// `dist.tarball` is recorded. Both spell a scope as `@scope/name` or
/// `@scope%2fname`, and pnpm ignores the scheme. Yarn treats
/// registry.npmjs.org and registry.yarnpkg.com as one registry.
pub fn npm_tarball_is_conventional(base: &str, name: &str, version: &str, url: &str) -> bool {
    fn canonical(url: &str) -> String {
        let rest = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);
        let rest = match rest.strip_prefix("registry.yarnpkg.com") {
            Some(tail) if tail.is_empty() || tail.starts_with('/') => {
                format!("registry.npmjs.org{tail}")
            }
            _ => rest.to_string(),
        };
        rest.replace("%2f", "/").replace("%2F", "/")
    }
    canonical(url) == canonical(&npm_tarball_url(base.trim_end_matches('/'), name, version))
}

/// Run one of the extractors on the blocking pool.
///
/// A service archive is written out in full — tens of thousands of small
/// files for a big package — and doing that inline pinned a runtime worker
/// for the whole write, next to the downloads A6 runs concurrently. The
/// bytes move into the task, so callers hand over the archive they have
/// finished verifying.
pub(crate) async fn extract_on_blocking_pool<F>(
    bytes: Vec<u8>,
    dest: &Path,
    extract: F,
) -> Result<(), String>
where
    F: FnOnce(&[u8], &Path) -> Result<(), String> + Send + 'static,
{
    let dest = dest.to_path_buf();
    match tokio::task::spawn_blocking(move || extract(&bytes, &dest)).await {
        Ok(outcome) => outcome,
        Err(e) => Err(format!("extraction task failed: {e}")),
    }
}

/// What an archive walk does with each entry's decompressed bytes.
///
/// The two modes run the SAME walk in the same order over the same
/// constants: every archive-shaped refusal (entry count, the declared and
/// actual size caps, the traversal guard, the declared-vs-actual mismatch)
/// fires at the same entry with the same message in both. [`Sink::Validate`]
/// only sends the bytes to `io::sink()` instead of a file and creates
/// nothing, so a source whose extraction is deferred
/// ([`FetchedPackage::dir`]) can still be refused where the eager extraction
/// refused it.
///
/// The `cannot create …` errors are the ones a pass that opens nothing
/// cannot raise. Most are environment-shaped — a full or unwritable
/// destination — and belong to whoever writes. The exception is a name the
/// archive itself uses as both a file and a directory: the write walk
/// refuses every such archive, so [`Sink::Validate`] models the
/// destinations, and when one shows up it hands the archive to the write
/// walk rather than answering for it (see [`DestShape::file_dir_conflict`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Sink {
    Write,
    Validate,
}

/// The destination side of an archive walk: opens each entry's file and
/// creates each parent directory ONCE per walk (archives list a directory's
/// files consecutively, so the per-entry `create_dir_all` re-walked the same
/// parents for every member). In [`Sink::Validate`] it opens nothing.
struct EntrySink<'a> {
    dest: &'a Path,
    sink: Sink,
    /// Entries whose final path component is this are not written — the
    /// `fresh_copy` skip the vendor stage asks for (cargo's
    /// `.cargo-checksum.json`, which must never reach a path-dep copy).
    skip_file_name: Option<&'a str>,
    made: std::collections::HashSet<PathBuf>,
}

impl<'a> EntrySink<'a> {
    fn new(dest: &'a Path, sink: Sink) -> Self {
        Self {
            dest,
            sink,
            skip_file_name: None,
            made: std::collections::HashSet::new(),
        }
    }

    fn skipping(mut self, skip_file_name: Option<&'a str>) -> Self {
        self.skip_file_name = skip_file_name;
        self
    }

    /// Whether `rel` is one of the entries the caller asked to drop.
    fn skipped(&self, rel: &Path) -> bool {
        self.skip_file_name
            .is_some_and(|skip| rel.file_name().is_some_and(|n| n == skip))
    }

    /// Create `target`'s parent directory, once per walk.
    fn ensure_parent(&mut self, target: &Path) -> Result<(), String> {
        let Some(parent) = target.parent() else {
            return Ok(());
        };
        if !self.made.contains(parent) {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
            self.made.insert(parent.to_path_buf());
        }
        Ok(())
    }

    /// The open destination file for `rel`, or `None` when the entry is not
    /// written. The tar walk stays one pass: a tar entry is only reachable
    /// by reading the one before it.
    fn open(&mut self, rel: &Path) -> Result<Option<std::fs::File>, String> {
        if self.sink == Sink::Validate {
            return Ok(None);
        }
        let target = self.dest.join(rel);
        // The parent is created even for a skipped entry: what this stands
        // in for extracted the WHOLE archive and copied the tree out again,
        // and that copy walked directories, so a directory whose only member
        // was skipped still reached the stage.
        self.ensure_parent(&target)?;
        if self.skipped(rel) {
            return Ok(None);
        }
        std::fs::File::create(&target)
            .map(Some)
            .map_err(|e| format!("cannot create {}: {e}", target.display()))
    }
}

/// The destination `dest.join(rel)` names, with any `./` collapsed the way
/// the join collapses it — the key a repeated name and an aliasing spelling
/// are both recognised by. `Path::components` keeps a LEADING `CurDir`
/// ([`is_safe_relative_subpath`] allows one), so `./a` and `a` are two
/// `PathBuf`s for one file.
fn dest_rel(rel: &Path) -> PathBuf {
    if rel
        .components()
        .any(|c| matches!(c, std::path::Component::CurDir))
    {
        rel.components()
            .filter(|c| !matches!(c, std::path::Component::CurDir))
            .collect()
    } else {
        rel.to_path_buf()
    }
}

/// A destination under the ASCII case fold a case-insensitive filesystem
/// (APFS, NTFS) applies before it decides two names are one file.
fn fold_key(p: &Path) -> String {
    p.to_string_lossy().to_ascii_lowercase()
}

/// What the entries a zip plans to write look like to a FILESYSTEM, as
/// opposed to a set of `PathBuf`s.
#[derive(Default)]
struct DestShape {
    /// Two planned entries may land on ONE file, or a name is used as both
    /// a file and a directory. Either way the entries are not independent:
    /// the pool must not spread them and each parent must be created right
    /// before its own file, as a sequential in-order extraction does.
    ///
    /// Besides the exact repeats the plan already resolves, two spellings
    /// meet on a case-insensitive volume (`LICENSE` / `license`) or a
    /// normalization-insensitive one (`café` in NFC / NFD). ASCII case is
    /// checked; for anything non-ASCII the walk gives up on deciding and
    /// takes the one-at-a-time path.
    in_order: bool,
    /// A name is used as both a file and a directory — a refusal the write
    /// walk raises for every such archive, decided by its entries alone.
    file_dir_conflict: bool,
}

/// What a sequential walk has put under the destination so far, by the key a
/// case-insensitive filesystem compares on — enough to answer the one
/// refusal a write-free pass cannot: a name used as both a file and a
/// directory ([`DestShape::file_dir_conflict`]), which a sequential archive
/// only reveals as it is read.
#[derive(Default)]
struct DestModel {
    files: std::collections::HashSet<String>,
    dirs: std::collections::HashSet<String>,
}

impl DestModel {
    /// Record `rel` and report whether writing it clashes with what an
    /// earlier entry put there.
    fn clashes(&mut self, rel: &Path) -> bool {
        let rel = dest_rel(rel);
        for ancestor in rel.ancestors().skip(1) {
            if ancestor.as_os_str().is_empty() {
                break;
            }
            let key = fold_key(ancestor);
            if self.files.contains(&key) {
                return true;
            }
            self.dirs.insert(key);
        }
        let key = fold_key(&rel);
        if self.dirs.contains(&key) {
            return true;
        }
        self.files.insert(key);
        false
    }
}

/// Read the shape off the planned destinations (relative, `./`-collapsed).
fn dest_shape(rels: &[PathBuf]) -> DestShape {
    let mut shape = DestShape::default();
    let mut files: std::collections::HashMap<String, &Path> = std::collections::HashMap::new();
    let mut dirs: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut walked: Option<&Path> = None;
    for rel in rels {
        shape.in_order |= !rel.as_os_str().as_encoded_bytes().is_ascii();
        // An archive lists a directory's files consecutively, so the parent
        // chain is nearly always the one the entry before it walked.
        let parent = rel.parent();
        if parent != walked {
            walked = parent;
            for ancestor in rel.ancestors().skip(1) {
                if ancestor.as_os_str().is_empty() {
                    break;
                }
                dirs.insert(fold_key(ancestor));
            }
        }
        match files.insert(fold_key(rel), rel.as_path()) {
            // Two spellings of one file the exact-path rule cannot see.
            Some(earlier) if earlier != rel.as_path() => shape.in_order = true,
            _ => {}
        }
    }
    shape.file_dir_conflict = files.keys().any(|key| dirs.contains(key));
    shape.in_order |= shape.file_dir_conflict;
    shape
}

/// Copy one entry's bytes into the opened file, or count them when
/// validating.
fn drain_entry<R: std::io::Read>(
    reader: &mut R,
    out: Option<&mut std::fs::File>,
) -> std::io::Result<u64> {
    match out {
        Some(file) => std::io::copy(reader, file),
        None => std::io::copy(reader, &mut std::io::sink()),
    }
}

/// Give an extracted entry the exec-aware mode through its OWN open handle
/// (`fchmod`), so the walk never re-resolves the path it just wrote. The
/// chmod stays explicit: the mode must be exact regardless of umask.
#[cfg_attr(not(unix), allow(unused_variables))]
fn set_entry_mode(file: Option<&std::fs::File>, exec: bool) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some(file) = file {
            let perms = if exec { 0o755 } else { 0o644 };
            let _ = file.set_permissions(std::fs::Permissions::from_mode(perms));
        }
    }
}

/// Traversal-guarded zip extraction. `strip_first` mirrors the tar
/// behavior (composer dist zips carry a variable top dir; wheels carry
/// content at the root).
///
/// `pub(crate)` so the composer service-download path can extract a downloaded
/// dist zip into the vendor copy dir (`strip_first` = drop the top-level dir).
pub(crate) fn extract_zip(bytes: &[u8], dest: &Path, strip_first: bool) -> Result<(), String> {
    extract_zip_skipping(bytes, dest, strip_first, None)
}

/// [`extract_zip`], dropping any entry whose final path component is
/// `skip_file_name` (the `fresh_copy` skip a vendor stage asks for).
pub(crate) fn extract_zip_skipping(
    bytes: &[u8],
    dest: &Path,
    strip_first: bool,
    skip_file_name: Option<&str>,
) -> Result<(), String> {
    walk_zip(bytes, dest, strip_first, Sink::Write, None, skip_file_name).map(|_| ())
}

/// [`extract_zip`]'s write-free twin: every refusal, nothing created.
/// Reports whether the extraction would put `watch` at the root (see
/// [`lands_at_root`]) so the fetchers' post-extraction presence probe can
/// run without a tree.
///
/// `dest` is where the tree WOULD go. Nothing is written there — it names
/// the destinations the refusals name, and it is where the write walk takes
/// over for the one refusal this pass cannot decide on its own (see
/// [`DestShape::file_dir_conflict`]).
#[cfg(test)]
pub(crate) fn validate_zip(
    bytes: &[u8],
    dest: &Path,
    strip_first: bool,
    watch: Option<&str>,
) -> Result<bool, String> {
    walk_zip(bytes, dest, strip_first, Sink::Validate, watch, None)
}

/// The zip walk, in two passes.
///
/// Pass one reads the central directory alone — no entry is inflated — and
/// decides everything that comes from headers, in entry order over one
/// running total: the traversal guard, the per-entry and total DECLARED
/// caps, and each entry's destination (every parent directory created
/// once). It stops at the first refusal.
///
/// Pass two inflates the planned entries on a bounded pool of threads, each
/// with its own reader over the shared bytes. Inflating is the whole cost of
/// a big dist zip and it is per-entry independent, so the only thing the
/// pass has to serialise is the ANSWER: a repeated name is written by its
/// last spelling, as an in-order extraction left it, and the refusal
/// reported is the one at the lowest entry index — which, against pass one's
/// own index, reproduces a sequential walk's verdict entry for entry.
fn walk_zip(
    bytes: &[u8],
    dest: &Path,
    strip_first: bool,
    sink: Sink,
    watch: Option<&str>,
    skip_file_name: Option<&str>,
) -> Result<bool, String> {
    let plan = plan_zip(bytes, dest, strip_first, sink, watch, skip_file_name)?;
    // A name used as both a file and a directory is refused by every write
    // walk, but only the filesystem can say with which errno, at which
    // entry — and this pass opens nothing. Hand the archive to the write
    // walk, into the destination the tree would have gone to, so the fetch
    // reports exactly the refusal the eager extraction reported.
    if sink == Sink::Validate && plan.file_dir_conflict {
        return walk_zip(bytes, dest, strip_first, Sink::Write, watch, skip_file_name);
    }
    let body_refusal =
        inflate_planned_entries(bytes, &plan.entries, plan.declared_total, plan.in_order);
    match (body_refusal, plan.header_refusal) {
        // Both passes refused: the walk stopped at whichever entry came
        // first, and within one entry the header checks ran first.
        (Some((body_at, body)), Some((header_at, header))) => {
            Err(if body_at < header_at { body } else { header })
        }
        (Some((_, body)), None) => Err(body),
        (None, Some((_, header))) => Err(header),
        (None, None) => Ok(plan.seen_watched),
    }
}

/// One entry pass one decided to read.
struct PlannedEntry {
    index: usize,
    /// The extraction-relative name, for the refusal messages.
    rel_str: String,
    declared: u64,
    exec: bool,
    /// Where the bytes go — `None` when the entry is read but not written:
    /// validating, skipped by name, or an earlier spelling of a repeated
    /// name that a later entry overwrites.
    target: Option<PathBuf>,
    /// The directory to create before writing, when the plan left that to
    /// the inflate pass (see [`DestShape::in_order`]). `None` when the plan
    /// created every parent itself.
    parent: Option<PathBuf>,
}

struct ZipPlan {
    entries: Vec<PlannedEntry>,
    /// The first header-shaped refusal and the entry index it fired at.
    header_refusal: Option<(usize, String)>,
    /// What the planned entries declare they decompress to — the pool's
    /// work estimate.
    declared_total: u64,
    seen_watched: bool,
    /// [`DestShape::in_order`]: the entries are not independent, so one
    /// thread writes them in plan order, creating each parent as it goes.
    in_order: bool,
    /// [`DestShape::file_dir_conflict`].
    file_dir_conflict: bool,
}

fn plan_zip(
    bytes: &[u8],
    dest: &Path,
    strip_first: bool,
    sink: Sink,
    watch: Option<&str>,
    skip_file_name: Option<&str>,
) -> Result<ZipPlan, String> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| format!("unreadable zip: {e}"))?;
    if archive.len() > MAX_ENTRIES {
        return Err(format!("zip exceeds {MAX_ENTRIES} entries"));
    }
    let mut plan = ZipPlan {
        entries: Vec::new(),
        header_refusal: None,
        declared_total: 0,
        seen_watched: false,
        in_order: false,
        file_dir_conflict: false,
    };
    // Each planned entry's destination relative to `dest`, which is what
    // the repeated-name rule and the aliasing check are decided on.
    let mut rels: Vec<PathBuf> = Vec::new();
    let mut total: u64 = 0;
    for i in 0..archive.len() {
        // `by_index`, not the raw reader: an entry the decompressor refuses
        // (an unsupported method, an encrypted member) must be refused HERE,
        // at its index and with the sequential walk's words, rather than
        // falling through to a later check.
        let file = match archive.by_index(i) {
            Ok(file) => file,
            Err(e) => {
                plan.header_refusal = Some((i, format!("unreadable zip entry: {e}")));
                break;
            }
        };
        if file.is_dir() {
            continue;
        }
        let raw = PathBuf::from(file.name());
        let rel = if strip_first {
            match strip_first_component(&raw) {
                Some(rel) => rel,
                None => continue,
            }
        } else {
            raw.clone()
        };
        let rel_str = rel.to_string_lossy().into_owned();
        if !is_safe_relative_subpath(&rel_str) {
            plan.header_refusal = Some((
                i,
                format!(
                    "zip entry `{}` escapes the extraction dir — refusing the artifact",
                    raw.display()
                ),
            ));
            break;
        }
        let declared = file.size();
        if declared > MAX_ENTRY_BYTES {
            plan.header_refusal = Some((
                i,
                format!("zip entry `{rel_str}` is {declared} bytes (cap {MAX_ENTRY_BYTES})"),
            ));
            break;
        }
        total += declared;
        if total > MAX_TOTAL_DECOMPRESSED_BYTES {
            plan.header_refusal = Some((
                i,
                format!("zip decompresses past the {MAX_TOTAL_DECOMPRESSED_BYTES}-byte cap"),
            ));
            break;
        }
        plan.seen_watched |= watch.is_some_and(|name| lands_at_root(&rel, name));
        plan.declared_total += declared;
        rels.push(dest_rel(&rel));
        plan.entries.push(PlannedEntry {
            index: i,
            rel_str,
            declared,
            exec: file.unix_mode().is_some_and(|m| m & 0o111 != 0),
            target: (sink == Sink::Write).then(|| dest.join(&rel)),
            parent: None,
        });
    }
    let shape = dest_shape(&rels);
    plan.in_order = shape.in_order;
    plan.file_dir_conflict = shape.file_dir_conflict;
    if sink == Sink::Validate {
        return Ok(plan);
    }

    // The destination pass, in entry order.
    let mut out = EntrySink::new(dest, sink).skipping(skip_file_name);
    if plan.in_order {
        // Aliasing destinations: leave the directories to the inflate pass,
        // which creates each one right before its own file, so a name used
        // as both a file and a directory fails from the same syscall at the
        // same entry as a sequential extraction.
        for entry in &mut plan.entries {
            entry.parent = entry
                .target
                .as_deref()
                .and_then(Path::parent)
                .map(Path::to_path_buf);
        }
    } else {
        for at in 0..plan.entries.len() {
            let Some(target) = plan.entries[at].target.clone() else {
                continue;
            };
            if let Err(detail) = out.ensure_parent(&target) {
                // Refuse at this entry: everything before it is written,
                // nothing after it.
                let index = plan.entries[at].index;
                plan.entries.truncate(at);
                plan.header_refusal = Some((index, detail));
                break;
            }
        }
    }
    // What is NOT written: an entry dropped by name, and every spelling of
    // a repeated destination but the last — which is what an in-order
    // extraction that overwrote it left behind.
    let mut written_at: std::collections::HashMap<&Path, usize> = std::collections::HashMap::new();
    for (at, rel) in rels.iter().enumerate().take(plan.entries.len()) {
        if out.skipped(rel) {
            plan.entries[at].target = None;
            continue;
        }
        if let Some(earlier) = written_at.insert(rel.as_path(), at) {
            plan.entries[earlier].target = None;
        }
    }
    Ok(plan)
}

/// Most entries one thread takes at a time, and the pool's ceiling. Small
/// files dominate a package archive, so handing them out in runs keeps the
/// cursor off the hot path without letting one thread hold a long tail.
const ZIP_CHUNK: usize = 16;
const ZIP_THREADS: usize = 8;

/// The pool only pays for itself on an archive with real inflating to do.
/// Measured on a 60-package composer vendor, where every dist zip is small:
/// spreading them cost 0.8 s of system time and 4x the involuntary context
/// switches for an instruction count that moved 3%, because each archive
/// was spawning and tearing down its own thread stacks. Below these, one
/// thread does the pass.
const ZIP_PARALLEL_MIN_ENTRIES: usize = 64;
const ZIP_PARALLEL_MIN_BYTES: u64 = 8 * 1024 * 1024;

/// Inflate the planned entries, writing each one that has a destination.
/// Returns the refusal at the LOWEST entry index, which is where the
/// one-at-a-time walk would have stopped.
fn inflate_planned_entries(
    bytes: &[u8],
    entries: &[PlannedEntry],
    declared_total: u64,
    in_order: bool,
) -> Option<(usize, String)> {
    let worth_spreading = !in_order
        && entries.len() >= ZIP_PARALLEL_MIN_ENTRIES
        && declared_total >= ZIP_PARALLEL_MIN_BYTES;
    let threads = if worth_spreading {
        (entries.len() / ZIP_CHUNK).clamp(1, ZIP_THREADS)
    } else {
        1
    };
    if threads == 1 {
        let mut archive = match zip::ZipArchive::new(std::io::Cursor::new(bytes)) {
            Ok(archive) => archive,
            // Pass one already opened it; an archive that fails here would
            // have failed there.
            Err(e) => return Some((0, format!("unreadable zip: {e}"))),
        };
        let mut refusal: Option<(usize, String)> = None;
        for entry in entries {
            if let Some(hit) = inflate_one(&mut archive, entry) {
                refusal.get_or_insert(hit);
                break;
            }
        }
        return refusal;
    }
    let cursor = std::sync::atomic::AtomicUsize::new(0);
    let refusal = std::sync::Mutex::new(None::<(usize, String)>);
    let refused = std::sync::atomic::AtomicBool::new(false);
    let worker = || {
        let mut archive = match zip::ZipArchive::new(std::io::Cursor::new(bytes)) {
            Ok(archive) => archive,
            Err(e) => {
                keep_lowest(&refusal, (0, format!("unreadable zip: {e}")));
                refused.store(true, std::sync::atomic::Ordering::Relaxed);
                return;
            }
        };
        loop {
            // The verdict is decided; a sequential walk would have stopped
            // writing by now, so stop taking work.
            if refused.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            let at = cursor.fetch_add(ZIP_CHUNK, std::sync::atomic::Ordering::Relaxed);
            if at >= entries.len() {
                return;
            }
            let upto = (at + ZIP_CHUNK).min(entries.len());
            for entry in &entries[at..upto] {
                if let Some(hit) = inflate_one(&mut archive, entry) {
                    keep_lowest(&refusal, hit);
                    refused.store(true, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
            }
        }
    };
    std::thread::scope(|scope| {
        // `Scope::spawn` PANICS when the OS refuses a thread (EAGAIN under
        // RLIMIT_NPROC, ENOMEM), and this runs inline on a runtime worker
        // for the fetchers that validate in their async body. Take what the
        // OS gives and let the caller's own thread drain the rest — one
        // thread is a plain sequential walk.
        for _ in 1..threads {
            if std::thread::Builder::new()
                .spawn_scoped(scope, worker)
                .is_err()
            {
                break;
            }
        }
        worker();
    });
    refusal
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn keep_lowest(slot: &std::sync::Mutex<Option<(usize, String)>>, hit: (usize, String)) {
    let mut slot = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if slot.as_ref().is_none_or(|(at, _)| hit.0 < *at) {
        *slot = Some(hit);
    }
}

/// Read one planned entry, writing it when it has a destination.
fn inflate_one<R: std::io::Read + std::io::Seek>(
    archive: &mut zip::ZipArchive<R>,
    entry: &PlannedEntry,
) -> Option<(usize, String)> {
    use std::io::Read as _;
    let PlannedEntry {
        index,
        rel_str,
        declared,
        exec,
        target,
        parent,
    } = entry;
    // Only when the plan left the directories to this pass (aliasing
    // destinations); it creates them itself otherwise, once each.
    if let Some(parent) = parent {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return Some((*index, format!("cannot create {}: {e}", parent.display())));
        }
    }
    let mut out = match target {
        None => None,
        Some(path) => match std::fs::File::create(path) {
            Ok(file) => Some(file),
            Err(e) => {
                return Some((*index, format!("cannot create {}: {e}", path.display())));
            }
        },
    };
    let mut file = match archive.by_index(*index) {
        Ok(file) => file,
        Err(e) => return Some((*index, format!("unreadable zip entry: {e}"))),
    };
    // The declared size is header data a crafted zip can understate (the zip
    // crate does not bound an entry's read by it), so hold the caps against
    // the ACTUAL decompressed bytes too: read at most declared+1 and refuse
    // on any mismatch.
    let copied = match drain_entry(&mut (&mut file).take(declared + 1), out.as_mut()) {
        Ok(copied) => copied,
        Err(e) => return Some((*index, format!("cannot extract `{rel_str}`: {e}"))),
    };
    if copied != *declared {
        return Some((
            *index,
            format!(
                "zip entry `{rel_str}` decompresses to {copied} bytes but declares {declared} \
                 — refusing the artifact"
            ),
        ));
    }
    set_entry_mode(out.as_ref(), *exec);
    None
}

/// Whether extracting `rel` puts `name` at the root of the destination —
/// either as the entry itself or as a directory the walk creates for it.
/// This is exactly what a `metadata(dest.join(name))` probe would answer
/// after a full extraction.
fn lands_at_root(rel: &Path, name: &str) -> bool {
    // A leading `./` survives `Path::components` but not `dest.join(rel)`,
    // which is what the probe this replaces ran against.
    rel.components()
        .find(|c| !matches!(c, std::path::Component::CurDir))
        .is_some_and(|c| c.as_os_str() == name)
}

/// PyPI's JSON API base; override with `SOCKET_PYPI_JSON_API` (tests point it
/// at a mock). Used only to turn a lock's file hash into a download URL for
/// locks that record hashes without URLs (poetry.lock, which records one wheel
/// hash, and Pipfile.lock, which records every release file's hash).
pub const DEFAULT_PYPI_JSON_API: &str = "https://pypi.org/pypi";

pub(crate) fn pypi_json_api_base() -> String {
    std::env::var("SOCKET_PYPI_JSON_API")
        .ok()
        .map(|v| v.trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_PYPI_JSON_API.to_string())
}

/// go's default module proxy (the first element of go's default
/// `GOPROXY=https://proxy.golang.org,direct`).
pub const DEFAULT_GOPROXY: &str = "https://proxy.golang.org";

/// The module proxy go itself would ask for `module`, or `Err` when go would
/// not use a proxy for it: GOPROXY's first element is `off` or `direct`, or
/// the module matches GONOPROXY (defaulting to GOPRIVATE). Falling back to a
/// public proxy there would send a private module path off the machine.
/// A non-empty `SOCKET_GOPROXY` is an explicit choice and always wins.
pub(crate) fn goproxy_base(module: &str) -> Result<String, String> {
    if let Ok(v) = std::env::var("SOCKET_GOPROXY") {
        let v = v.trim_end_matches('/').to_string();
        if !v.is_empty() {
            return Ok(v);
        }
    }
    let nonempty = |key: &str| std::env::var(key).ok().filter(|v| !v.trim().is_empty());
    if let Some((key, patterns)) = nonempty("GONOPROXY")
        .map(|v| ("GONOPROXY", v))
        .or_else(|| nonempty("GOPRIVATE").map(|v| ("GOPRIVATE", v)))
    {
        if go_match_prefix_patterns(&patterns, module) {
            return Err(format!(
                "{module} matches {key}, so go fetches it directly, never through a \
                 module proxy; not fetching it (set SOCKET_GOPROXY to name a proxy \
                 that serves it)"
            ));
        }
    }
    let goproxy = nonempty("GOPROXY").unwrap_or_else(|| format!("{DEFAULT_GOPROXY},direct"));
    // A comma- OR pipe-separated list (go help goproxy); go tries the first
    // element first, and `off` / `direct` there mean no proxy is consulted.
    let first = goproxy
        .split([',', '|'])
        .map(|part| part.trim().trim_end_matches('/'))
        .find(|part| !part.is_empty())
        .unwrap_or(DEFAULT_GOPROXY);
    match first {
        "off" => Err("GOPROXY=off disables module downloads; not fetching".to_string()),
        "direct" => Err(
            "GOPROXY=direct fetches modules from their version control origin, which \
             socket-patch does not do; not fetching (set SOCKET_GOPROXY to name a proxy)"
                .to_string(),
        ),
        proxy => Ok(proxy.to_string()),
    }
}

/// `golang.org/x/mod/module.MatchPrefixPatterns`: does any comma-separated
/// glob match a leading path-element prefix of `target`? A glob with
/// syntax this matcher does not implement (`[...]`, `\`) counts as a
/// match, so an unrecognized private pattern never leaks a module path.
pub(crate) fn go_match_prefix_patterns(globs: &str, target: &str) -> bool {
    globs
        .split(',')
        .map(str::trim)
        .filter(|g| !g.is_empty())
        .any(|glob| {
            let elements = glob.matches('/').count() + 1;
            let prefix: Vec<&str> = target.splitn(elements + 1, '/').take(elements).collect();
            prefix.len() == elements
                && (glob.contains(['[', '\\'])
                    || go_glob_match(glob.as_bytes(), prefix.join("/").as_bytes()))
        })
}

/// `path.Match` for `*` and `?` (neither crosses a `/`) and literals.
fn go_glob_match(pattern: &[u8], name: &[u8]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some((b'*', rest)) => (0..=name.len())
            .take_while(|&i| i == 0 || name[i - 1] != b'/')
            .any(|i| go_glob_match(rest, &name[i..])),
        Some((b'?', rest)) => {
            name.first().is_some_and(|&c| c != b'/') && go_glob_match(rest, &name[1..])
        }
        Some((&c, rest)) => name.first() == Some(&c) && go_glob_match(rest, &name[1..]),
    }
}

/// go.sum's `h1:` dirhash over a module zip: sha256 of the sorted
/// `"{sha256hex(content)}  {entry name}\n"` lines, base64-encoded
/// (golang.org/x/mod/sumdb/dirhash Hash1/HashZip). Computed in memory
/// BEFORE extraction.
///
/// Runs in the ecosystem-agnostic service-download path whenever the
/// service reports a `dirhashH1`.
pub(crate) fn go_h1_of_zip(bytes: &[u8]) -> Result<String, String> {
    Ok(walk_module_zip(bytes, None)?.h1)
}

/// What one walk over a module zip learned.
#[cfg_attr(not(test), allow(dead_code))]
struct ModuleZipWalk {
    /// The `h1:` dirhash of the entries.
    h1: String,
    /// The refusal [`extract_zip_with_prefix`] would have raised over the
    /// same entries, held back — `None` when it would have extracted
    /// cleanly, and always `None` when no prefix was given.
    extract_refusal: Option<String>,
    /// An entry name used as both a file and a directory: the extraction
    /// refuses it, but with an errno only the filesystem knows, so the
    /// caller hands the archive back to the extraction (see
    /// [`DestShape::file_dir_conflict`]). Always `false` without a prefix.
    dest_clash: bool,
}

/// The dirhash walk, optionally also answering what the extraction walk
/// would have said about the same entries.
///
/// One inflate serves both the dirhash and the extraction checks: both
/// derive everything from the entry's name, its declared size and how many
/// bytes it actually decompresses to.
///
/// Refusal ORDER matches a dirhash-then-extract sequence: a dirhash refusal
/// wins outright and returns here; the extraction refusal is recorded at
/// the lowest entry index and handed back for the caller to raise only
/// after the dirhash has been compared.
fn walk_module_zip(bytes: &[u8], validate_prefix: Option<&str>) -> Result<ModuleZipWalk, String> {
    use std::io::Read as _;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| format!("unreadable module zip: {e}"))?;
    if archive.len() > MAX_ENTRIES {
        return Err(format!("module zip exceeds {MAX_ENTRIES} entries"));
    }
    let mut files: Vec<(String, String)> = Vec::new();
    let mut total: u64 = 0;
    // The extraction walk's own running total — DECLARED sizes, where the
    // dirhash walk counts actual ones.
    let mut declared_total: u64 = 0;
    let mut extract_refusal: Option<String> = None;
    // See [`walk_tar_gz`]: the one refusal that needs a real filesystem.
    let mut shape = DestModel::default();
    let mut dest_clash = false;
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| format!("unreadable module zip entry: {e}"))?;
        if file.is_dir() {
            continue; // go module zips carry files only
        }
        let name = file.name().to_string();
        if name.contains('\n') {
            return Err("module zip entry name contains a newline".to_string());
        }
        let declared = file.size();
        if declared > MAX_ENTRY_BYTES {
            return Err(format!(
                "module zip entry `{name}` is {declared} bytes (cap {MAX_ENTRY_BYTES})"
            ));
        }
        // The caps count ACTUAL decompressed bytes — the declared size is
        // header data a crafted zip can understate (the zip crate does not
        // bound an entry's read by it), and this hash runs on lockfile-fetch
        // bytes before any other verifier.
        let mut hasher = Sha256::new();
        let mut entry_bytes: u64 = 0;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| format!("cannot read module zip entry `{name}`: {e}"))?;
            if n == 0 {
                break;
            }
            entry_bytes += n as u64;
            if entry_bytes > MAX_ENTRY_BYTES {
                return Err(format!(
                    "module zip entry `{name}` decompresses past the {MAX_ENTRY_BYTES}-byte cap"
                ));
            }
            hasher.update(&buf[..n]);
        }
        total += entry_bytes;
        if total > MAX_TOTAL_DECOMPRESSED_BYTES {
            return Err(format!(
                "module zip decompresses past the {MAX_TOTAL_DECOMPRESSED_BYTES}-byte cap"
            ));
        }
        // What `extract_zip_with_prefix` would have made of this entry, in
        // its own order. Only up to the first refusal: past that the
        // extraction would already have stopped, totals included.
        if let (Some(prefix), None) = (validate_prefix, extract_refusal.as_ref()) {
            extract_refusal =
                module_entry_refusal(&name, prefix, declared, entry_bytes, &mut declared_total);
            if let Some(rel) = name.strip_prefix(prefix) {
                dest_clash |= shape.clashes(Path::new(rel));
            }
        }
        files.push((name, hex::encode(hasher.finalize())));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h = Sha256::new();
    for (name, content_hex) in &files {
        h.update(format!("{content_hex}  {name}\n").as_bytes());
    }
    Ok(ModuleZipWalk {
        h1: format!(
            "h1:{}",
            base64::engine::general_purpose::STANDARD.encode(h.finalize())
        ),
        extract_refusal,
        dest_clash,
    })
}

/// [`walk_zip_with_prefix`]'s per-entry refusals, checked in its order over
/// the one inflate [`walk_module_zip`] already did. `actual` is how many
/// bytes the entry really decompressed to, which is what the extraction's
/// `take(declared + 1)` copy would have counted (capped there).
fn module_entry_refusal(
    name: &str,
    prefix: &str,
    declared: u64,
    actual: u64,
    declared_total: &mut u64,
) -> Option<String> {
    let Some(rel) = name.strip_prefix(prefix) else {
        return Some(format!(
            "module zip entry `{name}` lies outside `{prefix}` — refusing the artifact"
        ));
    };
    if !is_safe_relative_subpath(rel) {
        return Some(format!(
            "module zip entry `{name}` escapes the extraction dir — refusing the artifact"
        ));
    }
    if declared > MAX_ENTRY_BYTES {
        return Some(format!(
            "module zip entry `{name}` is {declared} bytes (cap {MAX_ENTRY_BYTES})"
        ));
    }
    *declared_total += declared;
    if *declared_total > MAX_TOTAL_DECOMPRESSED_BYTES {
        return Some(format!(
            "module zip decompresses past the {MAX_TOTAL_DECOMPRESSED_BYTES}-byte cap"
        ));
    }
    let copied = actual.min(declared + 1);
    if copied != declared {
        return Some(format!(
            "module zip entry `{name}` decompresses to {copied} bytes but declares \
             {declared} — refusing the artifact"
        ));
    }
    None
}

/// Verify a golang module zip's `h1:` dirhash against an expected value.
///
/// The vendoring service reports `dirhashH1` for golang artifacts (what
/// `go mod verify` checks); the service-download path uses this to confirm the
/// downloaded zip's CONTENTS — not just its bytes — match.
pub(crate) fn verify_go_h1(bytes: &[u8], expected_h1: &str) -> Result<(), String> {
    let actual = go_h1_of_zip(bytes)?;
    if actual == expected_h1 {
        Ok(())
    } else {
        Err(format!(
            "go module dirhash mismatch: service reports {expected_h1}, the downloaded zip \
             hashes to {actual}"
        ))
    }
}

/// Traversal-guarded zip extraction with an EXPLICIT required prefix
/// (`<module>@<version>/` — go module paths contain slashes, so a
/// first-component strip would be wrong). Same guard family as
/// [`extract_tgz`]; an entry outside the prefix fails the whole artifact.
/// `pub(crate)` so the golang service-download path can extract a downloaded
/// module zip (entries prefixed `{module}@{version}/`) into the vendor copy dir.
pub(crate) fn extract_zip_with_prefix(
    bytes: &[u8],
    dest: &Path,
    prefix: &str,
) -> Result<(), String> {
    extract_zip_with_prefix_skipping(bytes, dest, prefix, None)
}

/// [`extract_zip_with_prefix`], dropping any entry whose final path
/// component is `skip_file_name`.
pub(crate) fn extract_zip_with_prefix_skipping(
    bytes: &[u8],
    dest: &Path,
    prefix: &str,
    skip_file_name: Option<&str>,
) -> Result<(), String> {
    walk_zip_with_prefix(bytes, dest, prefix, Sink::Write, skip_file_name)
}

/// [`extract_zip_with_prefix`]'s write-free twin: every refusal, nothing
/// created. The golang fetch gets the same answer out of its dirhash walk
/// ([`walk_module_zip`]); this is the oracle that pins the two together.
#[cfg(test)]
pub(crate) fn validate_zip_with_prefix(
    bytes: &[u8],
    dest: &Path,
    prefix: &str,
) -> Result<(), String> {
    walk_zip_with_prefix(bytes, dest, prefix, Sink::Validate, None)
}

fn walk_zip_with_prefix(
    bytes: &[u8],
    dest: &Path,
    prefix: &str,
    sink: Sink,
    skip_file_name: Option<&str>,
) -> Result<(), String> {
    use std::io::Read as _;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| format!("unreadable module zip: {e}"))?;
    if archive.len() > MAX_ENTRIES {
        return Err(format!("module zip exceeds {MAX_ENTRIES} entries"));
    }
    let mut out = EntrySink::new(dest, sink).skipping(skip_file_name);
    let mut total: u64 = 0;
    // See [`walk_tar_gz`]: the one refusal a write-free pass cannot open a
    // file to find out about.
    let mut shape = DestModel::default();
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| format!("unreadable module zip entry: {e}"))?;
        if file.is_dir() {
            continue;
        }
        let name = file.name().to_string();
        let Some(rel) = name.strip_prefix(prefix) else {
            return Err(format!(
                "module zip entry `{name}` lies outside `{prefix}` — refusing the artifact"
            ));
        };
        if !is_safe_relative_subpath(rel) {
            return Err(format!(
                "module zip entry `{name}` escapes the extraction dir — refusing the artifact"
            ));
        }
        // Bomb caps, same family as [`extract_zip`]: this path is reachable
        // WITHOUT the cap-enforcing dirhash pre-pass (the service-download
        // path when the service reports no `dirhashH1`), so it must bound
        // itself.
        let declared = file.size();
        if declared > MAX_ENTRY_BYTES {
            return Err(format!(
                "module zip entry `{name}` is {declared} bytes (cap {MAX_ENTRY_BYTES})"
            ));
        }
        total += declared;
        if total > MAX_TOTAL_DECOMPRESSED_BYTES {
            return Err(format!(
                "module zip decompresses past the {MAX_TOTAL_DECOMPRESSED_BYTES}-byte cap"
            ));
        }
        if sink == Sink::Validate && shape.clashes(Path::new(rel)) {
            return walk_zip_with_prefix(bytes, dest, prefix, Sink::Write, skip_file_name);
        }
        let mut target = out.open(Path::new(rel))?;
        // Hold the caps against the ACTUAL decompressed bytes too — the
        // declared size is header data a crafted zip can understate.
        let copied = drain_entry(&mut (&mut file).take(declared + 1), target.as_mut())
            .map_err(|e| format!("cannot extract `{rel}`: {e}"))?;
        if copied != declared {
            return Err(format!(
                "module zip entry `{name}` decompresses to {copied} bytes but declares \
                 {declared} — refusing the artifact"
            ));
        }
        set_entry_mode(
            target.as_ref(),
            file.unix_mode().is_some_and(|m| m & 0o111 != 0),
        );
    }
    Ok(())
}

/// Capped download. http(s) only; [`crate::utils::http::read_capped`]
/// enforces [`MAX_DOWNLOAD_BYTES`] on the declared Content-Length AND the
/// actual stream (a lying server cannot blow past it). Every error quotes
/// the URL redacted (userinfo from a GOPROXY or `.npmrc` registry, a grant
/// token, a signed query), reqwest's own error text included.
pub(crate) async fn download(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    download_unredacted(client, url)
        .await
        .map_err(|e| crate::utils::redact::redact_urls_in(&e).into_owned())
}

async fn download_unredacted(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(format!("refusing non-http(s) artifact URL `{url}`"));
    }
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("GET {url}: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("GET {url}: HTTP {status}"));
    }
    crate::utils::http::read_capped(resp, MAX_DOWNLOAD_BYTES, "registry artifact")
        .await
        .map_err(|e| format!("{url}: {e}"))
}

/// Verify archive bytes against lock-recorded integrity. Berry cache checksums
/// require server metadata because they identify a different archive format.
pub fn artifact_matches_integrity(
    bytes: &[u8],
    _name: &str,
    integrity: &LockIntegrity,
) -> Result<(), String> {
    match integrity {
        LockIntegrity::BerryChecksum(_) => Err("a Yarn Berry cache checksum cannot verify tarball bytes; use the archive integrity supplied by the patch service".into()),
        other => verify_integrity(bytes, other).map_err(|e| match e {
            FetchError::Failed(d) | FetchError::Unverifiable(d) => d,
        }),
    }
}

/// Verify downloaded bytes against the lock-recorded verifier. Runs BEFORE
/// any disk write. Berry cache-zip checksums and go.sum dirhashes have
/// dedicated verifiers in their ecosystems' fetchers.
fn verify_integrity(bytes: &[u8], integrity: &LockIntegrity) -> Result<(), FetchError> {
    match integrity {
        LockIntegrity::Sri(sri) => verify_sri(bytes, sri).map_err(FetchError::Failed),
        LockIntegrity::Sha1Hex(expect) => {
            let actual = crate::utils::digest::sha1_hex_of(bytes);
            if &actual == expect {
                Ok(())
            } else {
                Err(FetchError::Failed(format!(
                    "sha1 mismatch: lockfile records {expect}, downloaded bytes hash to {actual}"
                )))
            }
        }
        LockIntegrity::Sha256Hex(expect) => {
            let actual = crate::utils::digest::sha256_hex_of(bytes);
            if actual.eq_ignore_ascii_case(expect) {
                Ok(())
            } else {
                Err(FetchError::Failed(format!(
                    "sha256 mismatch: lockfile records {expect}, downloaded bytes hash to {actual}"
                )))
            }
        }
        LockIntegrity::Sha256AnyOf(expected) => {
            let actual = crate::utils::digest::sha256_hex_of(bytes);
            if expected.iter().any(|e| actual.eq_ignore_ascii_case(e)) {
                Ok(())
            } else {
                Err(FetchError::Failed(format!(
                    "sha256 mismatch: downloaded bytes hash to {actual}, which is none of the {} digests the lockfile records",
                    expected.len()
                )))
            }
        }
        LockIntegrity::BerryChecksum(_) | LockIntegrity::GoH1(_) => Err(FetchError::Unverifiable(
            "verifier handled by a dedicated ecosystem fetcher".to_string(),
        )),
        LockIntegrity::None => Err(FetchError::Unverifiable(
            "no integrity recorded".to_string(),
        )),
    }
}

/// SRI verification: pick the strongest hash of a (possibly multi-hash,
/// whitespace-separated) SRI string and compare base64 digests.
///
/// `sha1` is accepted as a LAST resort (never preferred over sha256+): it is
/// the only integrity npm-era lockfile entries carry (yarn classic writes
/// `integrity sha1-…` for them), and it is the exact guarantee the package
/// manager itself enforces for those entries — refusing it would make every
/// legacy package unvendorable whenever the prebuilt-artifact service misses.
/// The bare-hex twin of this trust
/// decision already lives in the `LockIntegrity::Sha1Hex` arm above.
pub(crate) fn verify_sri(bytes: &[u8], sri: &str) -> Result<(), String> {
    let mut best: Option<(u8, &str, &str)> = None;
    for token in sri.split_whitespace() {
        let Some((algo, b64)) = token.split_once('-') else {
            continue;
        };
        let rank = match algo {
            "sha512" => 3,
            "sha384" => 2,
            "sha256" => 1,
            "sha1" => 0,
            _ => continue,
        };
        if best.map(|(r, _, _)| rank > r).unwrap_or(true) {
            best = Some((rank, algo, b64));
        }
    }
    let Some((_, algo, expect)) = best else {
        return Err(format!("no usable hash in SRI `{sri}`"));
    };
    let b64 = base64::engine::general_purpose::STANDARD;
    let actual = match algo {
        "sha512" => b64.encode(Sha512::digest(bytes)),
        "sha384" => b64.encode(Sha384::digest(bytes)),
        "sha1" => b64.encode(Sha1::digest(bytes)),
        _ => b64.encode(Sha256::digest(bytes)),
    };
    if actual == expect {
        Ok(())
    } else {
        Err(format!(
            "{algo} integrity mismatch: lockfile records {expect}, downloaded bytes hash to \
             {actual}"
        ))
    }
}

/// Strip the FIRST path component (npm's tarball semantics — usually
/// `package/`, but registry tarballs may use any prefix dir).
fn strip_first_component(path: &Path) -> Option<PathBuf> {
    let mut components = path.components();
    components.next()?;
    let rest = components.as_path();
    (!rest.as_os_str().is_empty()).then(|| rest.to_path_buf())
}

/// Traversal-guarded, mode-preserving tgz extraction (the same guard
/// family as `patch/package.rs::read_archive_to_map`, plus exec-bit
/// preservation: the deterministic re-pack reads modes from disk, so a
/// bytes-only extraction would silently strip bin scripts' exec bits).
/// Fails CLOSED on any traversal-shaped entry — a malicious tarball must
/// not half-extract.
///
/// `pub(crate)` so the cargo service-download path can extract a downloaded
/// `.crate` (tar.gz, single top-level `{name}-{version}/` prefix) into the
/// vendor copy dir — the same content the local `fresh_copy` produces.
pub(crate) fn extract_tgz(bytes: &[u8], dest: &Path) -> Result<(), String> {
    extract_tgz_skipping(bytes, dest, None)
}

/// [`extract_tgz`], dropping any entry whose final path component is
/// `skip_file_name` (the `fresh_copy` skip a vendor stage asks for).
pub(crate) fn extract_tgz_skipping(
    bytes: &[u8],
    dest: &Path,
    skip_file_name: Option<&str>,
) -> Result<(), String> {
    walk_tar_gz(
        bytes,
        dest,
        /*strip_first=*/ true,
        Sink::Write,
        None,
        skip_file_name,
        /*strict=*/ false,
    )
    .map(|_| ())
}

/// [`extract_tgz`] that refuses the archive instead of skipping a symlink,
/// hardlink, device or FIFO entry (a directory artifact is committed as
/// extracted, so nothing the archive carries may be silently dropped).
pub(crate) fn extract_tgz_strict(bytes: &[u8], dest: &Path) -> Result<(), String> {
    walk_tar_gz(
        bytes,
        dest,
        /*strip_first=*/ true,
        Sink::Write,
        None,
        None,
        /*strict=*/ true,
    )
    .map(|_| ())
}

/// [`extract_tgz`]'s write-free twin: every refusal, nothing created.
/// Reports whether `watch` would land at the root (see [`lands_at_root`]).
/// `dest` is where the tree WOULD go; see [`validate_zip`].
#[cfg(test)]
pub(crate) fn validate_tgz(bytes: &[u8], dest: &Path, watch: Option<&str>) -> Result<bool, String> {
    walk_tar_gz(
        bytes,
        dest,
        /*strip_first=*/ true,
        Sink::Validate,
        watch,
        None,
        /*strict=*/ false,
    )
}

/// Extract a `.gem`'s package content into `dest`. A `.gem` is a plain
/// (uncompressed) outer tar holding `data.tar.gz` (the lib files, at the ROOT
/// — no prefix dir), `metadata.gz`, and `checksums.yaml.gz`; only
/// `data.tar.gz` carries content a path source loads, so it is the only member
/// extracted (verbatim paths, no strip). Fails closed when the member is
/// missing or exceeds the size cap.
///
/// `pub(crate)` so the gem service-download path can extract a downloaded,
/// integrity-verified `.gem` into the vendor copy dir — the same content the
/// local `fresh_copy(installed_dir)` produces.
pub(crate) fn extract_gem_data(gem_bytes: &[u8], dest: &Path) -> Result<(), String> {
    extract_gem_data_skipping(gem_bytes, dest, None)
}

/// [`extract_gem_data`], dropping any entry whose final path component is
/// `skip_file_name`.
pub(crate) fn extract_gem_data_skipping(
    gem_bytes: &[u8],
    dest: &Path,
    skip_file_name: Option<&str>,
) -> Result<(), String> {
    walk_gem_data(gem_bytes, dest, Sink::Write, skip_file_name)
}

/// [`extract_gem_data`]'s write-free twin: every refusal, nothing created.
/// `dest` is where the tree WOULD go; see [`validate_zip`].
#[cfg(test)]
pub(crate) fn validate_gem_data(gem_bytes: &[u8], dest: &Path) -> Result<(), String> {
    walk_gem_data(gem_bytes, dest, Sink::Validate, None)
}

fn walk_gem_data(
    gem_bytes: &[u8],
    dest: &Path,
    sink: Sink,
    skip_file_name: Option<&str>,
) -> Result<(), String> {
    use std::io::Read as _;
    let mut archive = tar::Archive::new(gem_bytes);
    for e in archive
        .entries()
        .map_err(|e| format!("unreadable .gem: {e}"))?
    {
        let mut e = e.map_err(|err| format!("unreadable .gem entry: {err}"))?;
        let is_data = e
            .path()
            .ok()
            .is_some_and(|p| p.as_os_str() == "data.tar.gz");
        if !is_data {
            continue;
        }
        if e.header().size().unwrap_or(u64::MAX) > MAX_DOWNLOAD_BYTES {
            return Err("data.tar.gz exceeds the size cap".into());
        }
        let mut buf = Vec::new();
        e.read_to_end(&mut buf)
            .map_err(|err| format!("cannot read data.tar.gz: {err}"))?;
        return walk_tar_gz(
            &buf,
            dest,
            /*strip_first=*/ false,
            sink,
            None,
            skip_file_name,
            /*strict=*/ false,
        )
        .map(|_| ());
    }
    Err("the .gem carries no data.tar.gz".to_string())
}

fn walk_tar_gz(
    bytes: &[u8],
    dest: &Path,
    strip_first: bool,
    sink: Sink,
    watch: Option<&str>,
    skip_file_name: Option<&str>,
    strict: bool,
) -> Result<bool, String> {
    use std::io::Read as _;
    let gz = flate2::read::GzDecoder::new(bytes).take(MAX_TOTAL_DECOMPRESSED_BYTES);
    let mut archive = tar::Archive::new(gz);
    let mut out = EntrySink::new(dest, sink).skipping(skip_file_name);
    let mut seen_watched = false;
    let mut count = 0usize;
    // Validating opens nothing, so a destination the filesystem refuses
    // cannot surface here. A name used as both a file and a directory is
    // decidable from the entries alone, though, and the write walk always
    // refuses it — so model what the entries put on disk and, when one
    // shows up, let the write walk answer into the destination the tree
    // would have gone to.
    let mut shape = DestModel::default();
    for entry in archive
        .entries()
        .map_err(|e| format!("unreadable tarball: {e}"))?
    {
        let mut entry = entry.map_err(|e| format!("unreadable tarball entry: {e}"))?;
        count += 1;
        if count > MAX_ENTRIES {
            return Err(format!("tarball exceeds {MAX_ENTRIES} entries"));
        }
        // Regular files only: symlinks/hardlinks/devices never extract
        // (a symlink could redirect later entries out of the stage).
        let kind = entry.header().entry_type();
        if !kind.is_file() {
            if strict
                && !(kind.is_dir()
                    || kind.is_pax_global_extensions()
                    || kind.is_pax_local_extensions())
            {
                return Err(format!(
                    "tarball entry `{}` is not a regular file or directory — refusing the artifact",
                    entry
                        .path()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default()
                ));
            }
            continue;
        }
        let raw = entry
            .path()
            .map_err(|e| format!("tarball entry has an undecodable path: {e}"))?
            .into_owned();
        let rel = if strip_first {
            match strip_first_component(&raw) {
                Some(rel) => rel,
                None => continue, // a bare prefix-level file — not package content
            }
        } else {
            raw.clone()
        };
        let rel_str = rel.to_string_lossy();
        if !is_safe_relative_subpath(&rel_str) {
            return Err(format!(
                "tarball entry `{}` escapes the extraction dir — refusing the artifact",
                raw.display()
            ));
        }
        let size = entry.header().size().unwrap_or(u64::MAX);
        if size > MAX_ENTRY_BYTES {
            return Err(format!(
                "tarball entry `{rel_str}` is {size} bytes (cap {MAX_ENTRY_BYTES})"
            ));
        }
        if sink == Sink::Validate && shape.clashes(&rel) {
            return walk_tar_gz(
                bytes,
                dest,
                strip_first,
                Sink::Write,
                watch,
                skip_file_name,
                strict,
            );
        }
        let mut target = out.open(&rel)?;
        let mode = entry.header().mode().unwrap_or(0o644);
        drain_entry(&mut entry, target.as_mut())
            .map_err(|e| format!("cannot extract `{rel_str}`: {e}"))?;
        set_entry_mode(target.as_ref(), mode & 0o111 != 0);
        seen_watched |= watch.is_some_and(|name| lands_at_root(&rel, name));
    }
    Ok(seen_watched)
}

#[cfg(test)]
mod tests {
    use super::npm_tarball_is_conventional as conventional;

    #[test]
    fn conventional_tarball_url_matches_what_pms_derive() {
        let base = "https://registry.npmjs.org";
        assert!(conventional(
            base,
            "left-pad",
            "1.3.0",
            "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
        ));
        // pnpm ignores the scheme; yarn equates npmjs and yarnpkg.
        assert!(conventional(
            base,
            "left-pad",
            "1.3.0",
            "http://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
        ));
        assert!(conventional(
            base,
            "left-pad",
            "1.3.0",
            "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz"
        ));
        // Scoped names: `/` or `%2f` between scope and name.
        assert!(conventional(
            base,
            "@s/p",
            "1.0.0",
            "https://registry.npmjs.org/@s/p/-/p-1.0.0.tgz"
        ));
        assert!(conventional(
            base,
            "@s/p",
            "1.0.0",
            "https://registry.npmjs.org/@s%2fp/-/p-1.0.0.tgz"
        ));
        // A trailing slash on the base changes nothing.
        assert!(conventional(
            "https://r.example/npm/",
            "a",
            "1.0.0",
            "https://r.example/npm/a/-/a-1.0.0.tgz"
        ));
    }

    #[test]
    fn unconventional_tarball_urls_are_recorded() {
        let base = "https://r.example";
        // Another host, another path, another leaf, another version.
        assert!(!conventional(
            base,
            "a",
            "1.0.0",
            "https://cdn.example/a/-/a-1.0.0.tgz"
        ));
        assert!(!conventional(
            base,
            "a",
            "1.0.0",
            "https://r.example/files/a/1.0.0.tgz"
        ));
        assert!(!conventional(
            base,
            "@s/p",
            "1.0.0",
            "https://r.example/download/@s/p/1.0.0/abc"
        ));
        assert!(!conventional(
            base,
            "a",
            "1.0.0",
            "https://r.example/a/-/a-1.0.1.tgz"
        ));
        // yarnpkg is only npmjs's alias, not a prefix match.
        assert!(!conventional(
            "https://registry.npmjs.org",
            "a",
            "1.0.0",
            "https://registry.yarnpkg.com.evil/a/-/a-1.0.0.tgz"
        ));
    }

    use super::*;
    use crate::crawlers::go_crawler::encode_module_path;

    /// Build a gzipped tarball with the given `(path, bytes, exec)` entries.
    fn make_tgz(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (path, bytes, exec) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(if *exec { 0o755 } else { 0o644 });
            header.set_cksum();
            builder.append_data(&mut header, path, *bytes).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn sri_of(bytes: &[u8]) -> String {
        format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
        )
    }

    #[test]
    fn tarball_url_forms() {
        assert_eq!(
            npm_tarball_url(DEFAULT_NPM_REGISTRY, "left-pad", "1.3.0"),
            "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
        );
        assert_eq!(
            npm_tarball_url(DEFAULT_NPM_REGISTRY, "@scope/pkg", "2.0.0"),
            "https://registry.npmjs.org/@scope/pkg/-/pkg-2.0.0.tgz",
            "the scope stays in the path; the leaf uses the bare name"
        );
    }

    #[test]
    fn sri_picks_strongest_hash_and_compares() {
        let bytes = b"hello";
        let good = sri_of(bytes);
        assert!(verify_sri(bytes, &good).is_ok());
        // Multi-hash: a wrong sha256 alongside the right sha512 still passes
        // (strongest wins), and vice versa fails.
        let multi = format!("sha256-WRONG= {good}");
        assert!(verify_sri(bytes, &multi).is_ok());
        let bad = sri_of(b"other");
        assert!(verify_sri(bytes, &bad).is_err());
        assert!(
            verify_sri(bytes, "md5-abc=").is_err(),
            "unknown algos refuse"
        );
    }

    #[test]
    fn sri_sha1_is_accepted_as_last_resort() {
        use base64::Engine as _;
        let bytes = b"hello";
        let sha1_b64 = base64::engine::general_purpose::STANDARD.encode(Sha1::digest(bytes));
        // npm-era lockfile entries carry ONLY `sha1-…`; it must verify…
        assert!(
            verify_sri(bytes, &format!("sha1-{sha1_b64}")).is_ok(),
            "sha1-only SRI must be usable"
        );
        // …and still be a REAL check, not a fail-open.
        let wrong = base64::engine::general_purpose::STANDARD.encode(Sha1::digest(b"other"));
        assert!(
            verify_sri(bytes, &format!("sha1-{wrong}")).is_err(),
            "sha1 mismatch must refuse"
        );
        // sha1 never outranks a stronger hash: a correct sha1 alongside a
        // wrong sha512 fails (strongest wins), the reverse passes.
        let sha512_good = sri_of(bytes);
        assert!(verify_sri(bytes, &format!("sha1-{sha1_b64} sha512-WRONG=")).is_err());
        assert!(verify_sri(bytes, &format!("sha1-{wrong} {sha512_good}")).is_ok());
    }

    #[test]
    fn extraction_strips_first_component_whatever_its_name() {
        let tgz = make_tgz(&[("weird-prefix/package.json", b"{}", false)]);
        let tmp = tempfile::tempdir().unwrap();
        extract_tgz(&tgz, tmp.path()).unwrap();
        assert!(tmp.path().join("package.json").is_file());
    }

    #[test]
    fn traversal_entries_fail_closed() {
        // The tar crate refuses to WRITE `..` paths, so craft the header
        // name bytes directly — exactly what a hostile tarball would carry.
        for evil in ["package/../../escape.js", "package/x/../../../up.js"] {
            let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::default(),
            ));
            let mut header = tar::Header::new_gnu();
            {
                let name = &mut header.as_gnu_mut().unwrap().name;
                name[..evil.len()].copy_from_slice(evil.as_bytes());
            }
            header.set_size(4);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, &b"evil"[..]).unwrap();
            let tgz = builder.into_inner().unwrap().finish().unwrap();

            let tmp = tempfile::tempdir().unwrap();
            let err = extract_tgz(&tgz, tmp.path()).unwrap_err();
            assert!(err.contains("escapes"), "{evil}: {err}");
            assert!(
                std::fs::read_dir(tmp.path()).unwrap().next().is_none(),
                "nothing may extract from a traversal-bearing tarball"
            );
        }
    }

    /// Build a go module zip in memory (files only, `module@version/`
    /// prefix — the go zip layout).
    fn make_module_zip(prefix: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write as _;
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, bytes) in files {
            writer
                .start_file(
                    format!("{prefix}{name}"),
                    zip::write::SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Deflated),
                )
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    /// Independent spec-mirror of dirhash Hash1/HashZip, structured
    /// differently from the production fn to catch encoding slips.
    fn spec_h1(files: &[(&str, &[u8])], prefix: &str) -> String {
        // dirhash.Hash1 sorts the FILE NAMES, then emits one line per file.
        let mut named: Vec<(String, &[u8])> = files
            .iter()
            .map(|(name, bytes)| (format!("{prefix}{name}"), *bytes))
            .collect();
        named.sort_by(|a, b| a.0.cmp(&b.0));
        let lines: Vec<String> = named
            .iter()
            .map(|(name, bytes)| format!("{}  {name}\n", hex::encode(Sha256::digest(bytes))))
            .collect();
        let digest = Sha256::digest(lines.concat().as_bytes());
        format!(
            "h1:{}",
            base64::engine::general_purpose::STANDARD.encode(digest)
        )
    }

    #[test]
    fn go_escape_uppercase_and_zip_prefix_guards() {
        assert_eq!(
            encode_module_path("github.com/Azure/azure-sdk"),
            "github.com/!azure/azure-sdk"
        );
        assert_eq!(encode_module_path("v1.0.0-RC1"), "v1.0.0-!r!c1");

        // An entry outside the module prefix fails the whole artifact.
        let zip_bytes = make_module_zip("github.com/x/y@v1.0.0/", &[("go.mod", b"m\n")]);
        let tmp = tempfile::tempdir().unwrap();
        let err =
            extract_zip_with_prefix(&zip_bytes, tmp.path(), "github.com/OTHER@v1/").unwrap_err();
        assert!(err.contains("outside"), "{err}");
    }

    /// Build a zip with the given `(path, bytes)` entries.
    fn make_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write as _;
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, bytes) in files {
            writer
                .start_file(
                    name.to_string(),
                    zip::write::SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Deflated),
                )
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    #[serial_test::serial]
    fn goproxy_base_splits_on_pipe_separator() {
        const MODULE: &str = "example.com/m";
        // GOPROXY is a comma- OR pipe-separated list (go help goproxy); a
        // pipe-separated value must yield the first usable proxy, not a
        // `https://a|b`-shaped base that builds an unparseable URL.
        let saved_socket = std::env::var("SOCKET_GOPROXY").ok();
        let saved = std::env::var("GOPROXY").ok();
        std::env::remove_var("SOCKET_GOPROXY");
        std::env::set_var(
            "GOPROXY",
            "https://athens.example|https://proxy.golang.org|direct",
        );
        let piped = goproxy_base(MODULE);
        std::env::set_var("GOPROXY", "https://mirror.example/,direct");
        let mixed = goproxy_base(MODULE);
        match saved {
            Some(v) => std::env::set_var("GOPROXY", v),
            None => std::env::remove_var("GOPROXY"),
        }
        match saved_socket {
            Some(v) => std::env::set_var("SOCKET_GOPROXY", v),
            None => std::env::remove_var("SOCKET_GOPROXY"),
        }
        assert_eq!(piped.as_deref(), Ok("https://athens.example"));
        assert_eq!(mixed.as_deref(), Ok("https://mirror.example"));
    }

    /// Binary-patch a single-entry zip's DECLARED uncompressed size (local
    /// header + central directory) — the exact lie a crafted artifact can
    /// carry, since the crc and the deflate stream stay honest and zip 8.x
    /// does not cross-check the declared size on read.
    fn patch_declared_uncompressed_size(zip_bytes: &mut [u8], lie: u32) {
        assert_eq!(&zip_bytes[0..4], b"PK\x03\x04", "local file header");
        zip_bytes[22..26].copy_from_slice(&lie.to_le_bytes());
        let cd = (0..zip_bytes.len() - 4)
            .rev()
            .find(|&i| &zip_bytes[i..i + 4] == b"PK\x01\x02")
            .expect("central directory header");
        zip_bytes[cd + 24..cd + 28].copy_from_slice(&lie.to_le_bytes());
    }

    #[test]
    fn zip_entry_lying_declared_size_fails_closed() {
        // The size caps must hold against the ACTUAL decompressed bytes: an
        // entry declaring 1 byte while its deflate stream inflates to 4096
        // must refuse, not extract the full content past the caps.
        let content = vec![0x42u8; 4096];
        let mut zip_bytes = make_zip(&[("a.bin", &content)]);
        patch_declared_uncompressed_size(&mut zip_bytes, 1);
        let tmp = tempfile::tempdir().unwrap();
        let err = extract_zip(&zip_bytes, tmp.path(), false).unwrap_err();
        assert!(err.contains("declares"), "{err}");
    }

    #[test]
    fn module_zip_extraction_enforces_size_caps() {
        // extract_zip_with_prefix is reachable without the cap-enforcing
        // dirhash pre-pass (the service-download path when the service
        // reports no `dirhashH1`), so it must carry the bomb caps itself.
        let prefix = "github.com/x/y@v1.0.0/";
        let mut zip_bytes = make_module_zip(prefix, &[("big.bin", &[0u8; 16])]);
        patch_declared_uncompressed_size(&mut zip_bytes, (MAX_ENTRY_BYTES + 1) as u32);
        let tmp = tempfile::tempdir().unwrap();
        let err = extract_zip_with_prefix(&zip_bytes, tmp.path(), prefix).unwrap_err();
        assert!(err.contains("cap"), "{err}");

        // And the actual-bytes guard: declared-small, inflates bigger.
        let content = vec![0x42u8; 4096];
        let mut zip_bytes = make_module_zip(prefix, &[("lie.bin", &content)]);
        patch_declared_uncompressed_size(&mut zip_bytes, 1);
        let tmp = tempfile::tempdir().unwrap();
        let err = extract_zip_with_prefix(&zip_bytes, tmp.path(), prefix).unwrap_err();
        assert!(err.contains("declares"), "{err}");
    }

    #[test]
    fn go_h1_caps_actual_decompressed_bytes() {
        // A module zip whose entry DECLARES a tiny size while its deflate
        // stream inflates past the per-entry cap must refuse instead of
        // hashing unbounded decompressed bytes (a capped download can still
        // inflate ~1000×; the declared-size checks alone are bypassable).
        let big = vec![0u8; (MAX_ENTRY_BYTES + 64 * 1024) as usize];
        let mut zip_bytes = make_module_zip("m@v1/", &[("big.bin", &big)]);
        drop(big);
        patch_declared_uncompressed_size(&mut zip_bytes, 4096);
        let err = go_h1_of_zip(&zip_bytes).unwrap_err();
        assert!(err.contains("cap"), "{err}");
    }

    #[test]
    fn oversized_entry_header_fails_closed() {
        // A header CLAIMING more than the per-entry cap fails before any
        // attempt to read that much data.
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_path("package/huge.bin").unwrap();
        header.set_size(MAX_ENTRY_BYTES + 1);
        header.set_mode(0o644);
        header.set_cksum();
        // Intentionally append no data: the size check fires first.
        let inner = {
            use std::io::Write as _;
            builder.get_mut().write_all(&header.as_bytes()[..]).unwrap();
            builder.into_inner().unwrap().finish().unwrap()
        };
        let tmp = tempfile::tempdir().unwrap();
        let err = extract_tgz(&inner, tmp.path()).unwrap_err();
        assert!(
            err.contains("cap") || err.contains("unreadable"),
            "oversize header fails closed: {err}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn goproxy_base_env_precedence() {
        const MODULE: &str = "example.com/m";
        let saved_socket = std::env::var("SOCKET_GOPROXY").ok();
        let saved = std::env::var("GOPROXY").ok();

        // SOCKET_GOPROXY wins over GOPROXY (trailing slash trimmed).
        std::env::set_var("SOCKET_GOPROXY", "https://socket.example/");
        std::env::set_var("GOPROXY", "https://ignored.example");
        let socket_wins = goproxy_base(MODULE);
        // An EMPTY SOCKET_GOPROXY falls through to GOPROXY.
        std::env::set_var("SOCKET_GOPROXY", "");
        std::env::set_var("GOPROXY", "https://fallback.example");
        let empty_falls_through = goproxy_base(MODULE);
        // Neither set → the default proxy.
        std::env::remove_var("SOCKET_GOPROXY");
        std::env::remove_var("GOPROXY");
        let neither = goproxy_base(MODULE);
        // A GOPROXY led by direct/off consults no proxy: refused, never the
        // default proxy.
        std::env::set_var("GOPROXY", "direct,off");
        let no_proxy = goproxy_base(MODULE);

        match saved_socket {
            Some(v) => std::env::set_var("SOCKET_GOPROXY", v),
            None => std::env::remove_var("SOCKET_GOPROXY"),
        }
        match saved {
            Some(v) => std::env::set_var("GOPROXY", v),
            None => std::env::remove_var("GOPROXY"),
        }
        assert_eq!(socket_wins.as_deref(), Ok("https://socket.example"));
        assert_eq!(
            empty_falls_through.as_deref(),
            Ok("https://fallback.example")
        );
        assert_eq!(neither.as_deref(), Ok(DEFAULT_GOPROXY));
        assert!(no_proxy.is_err(), "{no_proxy:?}");
    }

    #[test]
    fn zip_traversal_entries_fail_closed() {
        // ZipWriter::start_file accepts raw names — exactly what a hostile
        // artifact carries. Nothing may extract from a traversal-bearing zip.
        let evil = make_zip(&[("../evil.txt", b"evil")]);
        let tmp = tempfile::tempdir().unwrap();
        let err = extract_zip(&evil, tmp.path(), /*strip_first=*/ false).unwrap_err();
        assert!(err.contains("escapes"), "{err}");
        assert!(
            std::fs::read_dir(tmp.path()).unwrap().next().is_none(),
            "nothing may extract from a traversal-bearing zip"
        );

        // With strip_first, the REMAINDER after the strip is what must hold.
        let evil = make_zip(&[("pfx/../../up.txt", b"evil")]);
        let tmp = tempfile::tempdir().unwrap();
        let err = extract_zip(&evil, tmp.path(), /*strip_first=*/ true).unwrap_err();
        assert!(err.contains("escapes"), "{err}");
        assert!(std::fs::read_dir(tmp.path()).unwrap().next().is_none());
    }

    #[test]
    fn zip_dir_entries_skip_across_extractors() {
        // One zip with an explicit directory entry drives all three zip
        // consumers: a dir entry neither errors nor materializes anywhere.
        use std::io::Write as _;
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        writer
            .add_directory("m@v1/d", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer
            .start_file(
                "m@v1/go.mod",
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
        writer.write_all(b"module m\n").unwrap();
        let bytes = writer.finish().unwrap().into_inner();

        let tmp = tempfile::tempdir().unwrap();
        extract_zip(&bytes, tmp.path(), /*strip_first=*/ false).unwrap();
        assert!(tmp.path().join("m@v1/go.mod").is_file());
        assert!(
            !tmp.path().join("m@v1/d").exists(),
            "dir entry must not materialize"
        );

        // The dirhash covers FILES only — the dir entry must not add a line.
        assert_eq!(
            go_h1_of_zip(&bytes).unwrap(),
            spec_h1(&[("go.mod", b"module m\n")], "m@v1/"),
            "dir entries must not contribute dirhash lines"
        );

        let tmp = tempfile::tempdir().unwrap();
        extract_zip_with_prefix(&bytes, tmp.path(), "m@v1/").unwrap();
        assert!(tmp.path().join("go.mod").is_file());
        assert!(!tmp.path().join("d").exists());
    }

    #[test]
    fn strip_first_drops_bare_top_level_entries() {
        // A single-component entry alongside prefixed content is silently
        // dropped — not extracted, not fatal — in both archive flavors.
        let zip_bytes = make_zip(&[("TOPFILE", b"loose"), ("pfx/composer.json", b"{}")]);
        let tmp = tempfile::tempdir().unwrap();
        extract_zip(&zip_bytes, tmp.path(), /*strip_first=*/ true).unwrap();
        assert!(tmp.path().join("composer.json").is_file());
        assert_eq!(
            std::fs::read_dir(tmp.path()).unwrap().count(),
            1,
            "the bare top-level zip entry must not extract anywhere"
        );

        let tgz = make_tgz(&[
            ("toplevel", b"loose", false),
            ("package/package.json", b"{}", false),
        ]);
        let tmp = tempfile::tempdir().unwrap();
        extract_tgz(&tgz, tmp.path()).unwrap();
        assert!(tmp.path().join("package.json").is_file());
        assert_eq!(
            std::fs::read_dir(tmp.path()).unwrap().count(),
            1,
            "the bare top-level tar entry must not extract anywhere"
        );
    }

    #[test]
    fn module_zip_prefix_interior_traversal_fails_closed() {
        // An entry INSIDE the prefix whose remainder escapes — distinct from
        // the outside-prefix refusal — must fail the whole artifact.
        let zip_bytes = make_module_zip("github.com/x/y@v1.0.0/", &[("../evil", b"evil")]);
        let tmp = tempfile::tempdir().unwrap();
        let err =
            extract_zip_with_prefix(&zip_bytes, tmp.path(), "github.com/x/y@v1.0.0/").unwrap_err();
        assert!(err.contains("escapes"), "{err}");
        assert!(
            std::fs::read_dir(tmp.path()).unwrap().next().is_none(),
            "nothing may extract from a traversal-bearing module zip"
        );
    }

    #[test]
    fn module_zip_newline_in_name_fails_closed() {
        // dirhash is line-oriented: a newline inside an entry name could
        // forge another file's hash line, so it must refuse outright.
        let zip_bytes = make_module_zip("m@v1/", &[("a\nb", b"x")]);
        let err = go_h1_of_zip(&zip_bytes).unwrap_err();
        assert!(err.contains("newline"), "{err}");
    }

    #[test]
    fn zip_declared_entry_size_over_cap_fails_closed() {
        // A DECLARED size past the per-entry cap refuses before any read —
        // in the plain extractor and in the dirhash pre-pass (the prefix
        // extractor's twin is covered by module_zip_extraction_enforces_size_caps).
        let mut zip_bytes = make_zip(&[("a.bin", &[0u8; 16])]);
        patch_declared_uncompressed_size(&mut zip_bytes, (MAX_ENTRY_BYTES + 1) as u32);
        let tmp = tempfile::tempdir().unwrap();
        let err = extract_zip(&zip_bytes, tmp.path(), false).unwrap_err();
        assert!(err.contains("cap"), "{err}");
        assert!(std::fs::read_dir(tmp.path()).unwrap().next().is_none());

        let mut zip_bytes = make_module_zip("m@v1/", &[("big.bin", &[0u8; 16])]);
        patch_declared_uncompressed_size(&mut zip_bytes, (MAX_ENTRY_BYTES + 1) as u32);
        let err = go_h1_of_zip(&zip_bytes).unwrap_err();
        assert!(err.contains("cap"), "{err}");
    }

    #[test]
    fn entry_count_caps_fail_closed() {
        // 60,001 empty entries: the zip caps refuse up front (archive.len()
        // is header data), the tar cap refuses during iteration. Entries are
        // empty/dir-typed so the fixtures stay small and nothing extracts.
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for i in 0..=MAX_ENTRIES {
            writer
                .start_file(
                    format!("m@v1/f{i}"),
                    zip::write::SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Stored),
                )
                .unwrap();
        }
        let zip_bytes = writer.finish().unwrap().into_inner();
        let tmp = tempfile::tempdir().unwrap();
        let err = extract_zip(&zip_bytes, tmp.path(), false).unwrap_err();
        assert!(err.contains("entries"), "{err}");
        assert!(std::fs::read_dir(tmp.path()).unwrap().next().is_none());
        let err = go_h1_of_zip(&zip_bytes).unwrap_err();
        assert!(err.contains("entries"), "{err}");
        let tmp = tempfile::tempdir().unwrap();
        let err = extract_zip_with_prefix(&zip_bytes, tmp.path(), "m@v1/").unwrap_err();
        assert!(err.contains("entries"), "{err}");

        // Tar twin: dir-typed entries count toward the cap without any
        // extraction work (the file-type skip runs after the count check).
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for i in 0..=MAX_ENTRIES {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("package/d{i}"), std::io::empty())
                .unwrap();
        }
        let tgz = builder.into_inner().unwrap().finish().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = extract_tgz(&tgz, tmp.path()).unwrap_err();
        assert!(err.contains("entries"), "{err}");
    }

    #[test]
    fn tar_link_entries_never_materialize() {
        // Symlinks and hardlinks are silently skipped: a link could redirect
        // later entries out of the stage, so neither may land on disk while
        // regular siblings still extract.
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        let mut lh = tar::Header::new_gnu();
        lh.set_path("package/link").unwrap();
        lh.set_link_name("../../etc/passwd").unwrap();
        lh.set_entry_type(tar::EntryType::Symlink);
        lh.set_size(0);
        lh.set_mode(0o777);
        lh.set_cksum();
        builder.append(&lh, std::io::empty()).unwrap();
        let mut hh = tar::Header::new_gnu();
        hh.set_path("package/hard").unwrap();
        hh.set_link_name("package/package.json").unwrap();
        hh.set_entry_type(tar::EntryType::Link);
        hh.set_size(0);
        hh.set_mode(0o644);
        hh.set_cksum();
        builder.append(&hh, std::io::empty()).unwrap();
        let mut fh = tar::Header::new_gnu();
        fh.set_size(2);
        fh.set_mode(0o644);
        fh.set_cksum();
        builder
            .append_data(&mut fh, "package/package.json", &b"{}"[..])
            .unwrap();
        let tgz = builder.into_inner().unwrap().finish().unwrap();

        let tmp = tempfile::tempdir().unwrap();
        extract_tgz(&tgz, tmp.path()).unwrap();
        assert!(tmp.path().join("package.json").is_file());
        assert!(
            std::fs::symlink_metadata(tmp.path().join("link")).is_err(),
            "a symlink entry must not materialize"
        );
        assert!(
            std::fs::symlink_metadata(tmp.path().join("hard")).is_err(),
            "a hardlink entry must not materialize"
        );
    }

    #[test]
    fn gem_without_data_tar_gz_refuses() {
        let mut outer = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o644);
        header.set_cksum();
        outer
            .append_data(&mut header, "metadata.gz", &b"meta"[..])
            .unwrap();
        let gem_bytes = outer.into_inner().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = extract_gem_data(&gem_bytes, tmp.path()).unwrap_err();
        assert_eq!(err, "the .gem carries no data.tar.gz");
    }

    #[test]
    fn gem_data_member_declaring_over_cap_refuses() {
        // A data.tar.gz header DECLARING more than the download cap refuses
        // before any attempt to read that much data (header-only craft — no
        // data follows, so a read attempt would error differently).
        let mut header = tar::Header::new_gnu();
        header.set_path("data.tar.gz").unwrap();
        header.set_size(MAX_DOWNLOAD_BYTES + 1);
        header.set_mode(0o644);
        header.set_cksum();
        let gem_bytes = header.as_bytes().to_vec();
        let tmp = tempfile::tempdir().unwrap();
        let err = extract_gem_data(&gem_bytes, tmp.path()).unwrap_err();
        assert!(err.contains("size cap"), "{err}");
    }

    /// A gzipped tarball carrying one entry whose RAW header name is
    /// `evil` — the tar crate refuses to write a `..` path, so a hostile
    /// tarball's bytes have to be crafted.
    fn make_traversing_tgz(evil: &str) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        let mut header = tar::Header::new_gnu();
        {
            let name = &mut header.as_gnu_mut().unwrap().name;
            name[..evil.len()].copy_from_slice(evil.as_bytes());
        }
        header.set_size(4);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, &b"evil"[..]).unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    }

    /// A `.gem` wrapping `data`, as `fetch_gem` receives it.
    fn wrap_gem(data_tgz: &[u8]) -> Vec<u8> {
        let mut outer = tar::Builder::new(Vec::new());
        for (name, bytes) in [
            ("metadata.gz", b"meta".as_slice()),
            ("data.tar.gz", data_tgz),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            outer.append_data(&mut header, name, bytes).unwrap();
        }
        outer.into_inner().unwrap()
    }

    /// The archives the extractors refuse, each paired with the walk that
    /// reads it. Deferring the WRITE is only safe while the fetch still
    /// decides everything the write decided, so the validation pass has to
    /// refuse the same bytes at the same entry with the same words.
    #[test]
    fn validation_pass_refuses_exactly_what_the_extractor_refuses() {
        let big_content = vec![0x42u8; 4096];

        // ── tar.gz ──────────────────────────────────────────────────────
        let mut over_cap = tar::Header::new_gnu();
        over_cap.set_path("package/huge.bin").unwrap();
        over_cap.set_size(MAX_ENTRY_BYTES + 1);
        over_cap.set_mode(0o644);
        over_cap.set_cksum();
        let oversized_tgz = {
            use std::io::Write as _;
            let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::default(),
            ));
            builder
                .get_mut()
                .write_all(&over_cap.as_bytes()[..])
                .unwrap();
            builder.into_inner().unwrap().finish().unwrap()
        };
        let truncated_tgz = {
            let mut bytes = make_tgz(&[("package/a.txt", b"hello", false)]);
            bytes.truncate(bytes.len() / 2);
            bytes
        };
        for (label, bytes) in [
            (
                "tar traversal",
                make_traversing_tgz("package/../../evil.js"),
            ),
            ("tar oversized header", oversized_tgz),
            ("tar truncated", truncated_tgz),
        ] {
            let stage = tempfile::tempdir().unwrap();
            let eager = extract_tgz(&bytes, stage.path()).unwrap_err();
            let lazy = validate_tgz(&bytes, stage.path(), Some("package.json")).unwrap_err();
            assert_eq!(lazy, eager, "{label}");
        }

        // ── zip ─────────────────────────────────────────────────────────
        let mut lying_zip = make_zip(&[("a.bin", &big_content)]);
        patch_declared_uncompressed_size(&mut lying_zip, 1);
        let mut over_cap_zip = make_zip(&[("a.bin", &[0u8; 16])]);
        patch_declared_uncompressed_size(&mut over_cap_zip, (MAX_ENTRY_BYTES + 1) as u32);
        let truncated_zip = {
            let mut bytes = make_zip(&[("a.txt", b"hello")]);
            bytes.truncate(bytes.len() / 2);
            bytes
        };
        for (label, bytes, strip) in [
            ("zip traversal", make_zip(&[("../evil.txt", b"x")]), false),
            (
                "zip traversal after strip",
                make_zip(&[("pfx/../../up.txt", b"x")]),
                true,
            ),
            ("zip lying declared size", lying_zip, false),
            ("zip declared over cap", over_cap_zip, false),
            ("zip truncated", truncated_zip, false),
        ] {
            let stage = tempfile::tempdir().unwrap();
            let eager = extract_zip(&bytes, stage.path(), strip).unwrap_err();
            let lazy =
                validate_zip(&bytes, stage.path(), strip, Some("composer.json")).unwrap_err();
            assert_eq!(lazy, eager, "{label}");
        }

        // ── module zip (prefix) ─────────────────────────────────────────
        let prefix = "github.com/x/y@v1.0.0/";
        let mut module_over_cap = make_module_zip(prefix, &[("big.bin", &[0u8; 16])]);
        patch_declared_uncompressed_size(&mut module_over_cap, (MAX_ENTRY_BYTES + 1) as u32);
        let mut module_lying = make_module_zip(prefix, &[("lie.bin", &big_content)]);
        patch_declared_uncompressed_size(&mut module_lying, 1);
        for (label, bytes) in [
            (
                "module zip outside prefix",
                make_zip(&[("other@v1/go.mod", b"module m\n")]),
            ),
            (
                "module zip interior traversal",
                make_module_zip(prefix, &[("../evil", b"x")]),
            ),
            ("module zip declared over cap", module_over_cap),
            ("module zip lying declared size", module_lying),
        ] {
            let stage = tempfile::tempdir().unwrap();
            let eager = extract_zip_with_prefix(&bytes, stage.path(), prefix).unwrap_err();
            let lazy = validate_zip_with_prefix(&bytes, stage.path(), prefix).unwrap_err();
            assert_eq!(lazy, eager, "{label}");
            // And the golang fetch's fused walk, which answers the same
            // question off the dirhash pass's single inflate.
            match walk_module_zip(&bytes, Some(prefix)) {
                // The dirhash pass guards the caps too and refuses first.
                Err(dirhash_refusal) => assert!(
                    dirhash_refusal.contains("cap"),
                    "{label}: {dirhash_refusal}"
                ),
                Ok(walk) => assert_eq!(
                    walk.extract_refusal.as_deref(),
                    Some(eager.as_str()),
                    "{label}: the fused walk must hold the extraction refusal verbatim"
                ),
            }
        }

        // A healthy module zip: the fused walk agrees with both walks.
        let healthy = make_module_zip(prefix, &[("go.mod", b"module m"), ("a/b.go", b"package b")]);
        let walk = walk_module_zip(&healthy, Some(prefix)).unwrap();
        assert_eq!(walk.h1, go_h1_of_zip(&healthy).unwrap());
        assert_eq!(walk.extract_refusal, None);

        // ── .gem ────────────────────────────────────────────────────────
        let no_data = {
            let mut outer = tar::Builder::new(Vec::new());
            let mut header = tar::Header::new_gnu();
            header.set_size(4);
            header.set_mode(0o644);
            header.set_cksum();
            outer
                .append_data(&mut header, "metadata.gz", &b"meta"[..])
                .unwrap();
            outer.into_inner().unwrap()
        };
        let traversing = wrap_gem(&make_traversing_tgz("../evil.rb"));
        for (label, bytes) in [("gem without data", no_data), ("gem traversal", traversing)] {
            let stage = tempfile::tempdir().unwrap();
            let eager = extract_gem_data(&bytes, stage.path()).unwrap_err();
            let lazy = validate_gem_data(&bytes, stage.path()).unwrap_err();
            assert_eq!(lazy, eager, "{label}");
        }
    }

    /// The refusal a write-free pass cannot reach on its own: an archive
    /// that names one path as both a file and a directory. It is decided by
    /// the archive's own entries — no environment involved — so the fetch
    /// has to refuse it where the eager extraction refused it, with the
    /// errno the filesystem gave, at the entry it gave it for.
    #[test]
    fn validation_pass_refuses_a_file_that_is_also_a_directory() {
        let tgz_file_first = make_tgz(&[
            ("package/package.json", b"{}", false),
            ("package/a", b"i am a file", false),
            ("package/a/b", b"i am under it", false),
        ]);
        let tgz_dir_first = make_tgz(&[
            ("package/package.json", b"{}", false),
            ("package/a/b", b"i am under it", false),
            ("package/a", b"i am a file", false),
        ]);
        let zip_file_first = make_zip(&[("a", b"i am a file"), ("a/b", b"i am under it")]);
        let zip_dir_first = make_zip(&[("a/b", b"i am under it"), ("a", b"i am a file")]);

        // The message names the destination, so eager and lazy each get a
        // fresh one and the two are compared with it masked out.
        let masked = |dest: &Path, detail: &str| {
            detail.replace(&dest.to_string_lossy().into_owned(), "<dest>")
        };
        for (label, bytes) in [
            ("tgz file first", &tgz_file_first),
            ("tgz dir first", &tgz_dir_first),
        ] {
            let eager_at = tempfile::tempdir().unwrap();
            let eager = extract_tgz(bytes, eager_at.path()).unwrap_err();
            let lazy_at = tempfile::tempdir().unwrap();
            let lazy = validate_tgz(bytes, lazy_at.path(), Some("package.json")).unwrap_err();
            assert_eq!(
                masked(lazy_at.path(), &lazy),
                masked(eager_at.path(), &eager),
                "{label}"
            );
            assert!(eager.contains("cannot create"), "{label}: {eager}");
        }
        for (label, bytes) in [
            ("zip file first", &zip_file_first),
            ("zip dir first", &zip_dir_first),
        ] {
            let eager_at = tempfile::tempdir().unwrap();
            let eager = extract_zip(bytes, eager_at.path(), /*strip_first=*/ false).unwrap_err();
            let lazy_at = tempfile::tempdir().unwrap();
            let lazy =
                validate_zip(bytes, lazy_at.path(), false, Some("composer.json")).unwrap_err();
            assert_eq!(
                masked(lazy_at.path(), &lazy),
                masked(eager_at.path(), &eager),
                "{label}"
            );
            assert!(eager.contains("cannot create"), "{label}: {eager}");
        }

        // And the .gem and module-zip walks, which reach the same code.
        let gem = wrap_gem(&make_tgz(&[
            ("lib/a", b"i am a file", false),
            ("lib/a/b", b"i am under it", false),
        ]));
        let eager_at = tempfile::tempdir().unwrap();
        let eager = extract_gem_data(&gem, eager_at.path()).unwrap_err();
        let lazy_at = tempfile::tempdir().unwrap();
        let lazy = validate_gem_data(&gem, lazy_at.path()).unwrap_err();
        assert_eq!(
            masked(lazy_at.path(), &lazy),
            masked(eager_at.path(), &eager)
        );

        let prefix = "github.com/x/y@v1.0.0/";
        let module = make_module_zip(prefix, &[("a", b"file"), ("a/b", b"under")]);
        let eager_at = tempfile::tempdir().unwrap();
        let eager = extract_zip_with_prefix(&module, eager_at.path(), prefix).unwrap_err();
        let lazy_at = tempfile::tempdir().unwrap();
        let lazy = validate_zip_with_prefix(&module, lazy_at.path(), prefix).unwrap_err();
        assert_eq!(
            masked(lazy_at.path(), &lazy),
            masked(eager_at.path(), &eager)
        );
        // …and the golang fetch's fused walk, which decides it off the
        // dirhash pass and hands the archive back to the extraction.
        assert!(walk_module_zip(&module, Some(prefix)).unwrap().dest_clash);
    }

    /// And on a healthy archive: the pass accepts it, writes nothing, and
    /// answers the root-file probe without an extracted tree.
    #[test]
    fn validation_pass_accepts_and_answers_the_root_probe() {
        let tgz = make_tgz(&[
            ("package/package.json", b"{}", false),
            ("package/bin/cli.js", b"#!/usr/bin/env node\n", true),
        ]);
        let nowhere = tempfile::tempdir().unwrap();
        let nowhere = nowhere.path().join("package");
        assert!(validate_tgz(&tgz, &nowhere, Some("package.json")).unwrap());
        assert!(!validate_tgz(&tgz, &nowhere, Some("Cargo.toml")).unwrap());

        // A nested entry counts, exactly as the directory the extraction
        // creates for it made `metadata(dir.join(name))` succeed.
        let nested = make_tgz(&[("package/composer.json/x", b"{}", false)]);
        assert!(validate_tgz(&nested, &nowhere, Some("composer.json")).unwrap());

        let zip_bytes = make_zip(&[("pfx/composer.json", b"{}"), ("pfx/src/a.php", b"<?php")]);
        assert!(validate_zip(
            &zip_bytes,
            &nowhere,
            /*strip_first=*/ true,
            Some("composer.json")
        )
        .unwrap());
        assert!(!validate_zip(
            &zip_bytes,
            &nowhere,
            /*strip_first=*/ false,
            Some("composer.json")
        )
        .unwrap());

        validate_gem_data(&wrap_gem(&make_tgz(&[("lib/a.rb", b"x", false)])), &nowhere).unwrap();
        let prefix = "github.com/x/y@v1.0.0/";
        validate_zip_with_prefix(
            &make_module_zip(prefix, &[("go.mod", b"module m")]),
            &nowhere,
            prefix,
        )
        .unwrap();

        // A `./`-spelled root entry: `dest.join("./composer.json")` is
        // `<dest>/composer.json`, which is what the `metadata` probe this
        // replaces saw — `Path::components` keeps the leading `.`, which it
        // did not. A flat `composer archive`-built dist is the shape that
        // reaches this (the zipball layout is stripped first).
        let flat = make_zip(&[("root.txt", b"x"), ("./composer.json", b"{}")]);
        let extracted = tempfile::tempdir().unwrap();
        extract_zip(&flat, extracted.path(), /*strip_first=*/ false).unwrap();
        assert!(
            extracted.path().join("composer.json").exists(),
            "the extraction puts it at the root"
        );
        assert!(validate_zip(
            &flat,
            &nowhere,
            /*strip_first=*/ false,
            Some("composer.json")
        )
        .unwrap());
        // The tar twin, where the strip leaves the `./` behind.
        let dotted = make_tgz(&[("foo-1.0/./Cargo.toml", b"[package]", false)]);
        assert!(validate_tgz(&dotted, &nowhere, Some("Cargo.toml")).unwrap());
    }

    /// A zip with a unix mode per entry, so the parallel walk's `fchmod`
    /// can be checked against what the archive declares.
    fn make_zip_with_modes(files: &[(&str, &[u8], u32)]) -> Vec<u8> {
        use std::io::Write as _;
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, bytes, mode) in files {
            writer
                .start_file(
                    name.to_string(),
                    zip::write::SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Deflated)
                        .unix_permissions(*mode),
                )
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    /// Every member of a zip, read strictly in archive order with the mode
    /// the extractor gives it — the one-at-a-time oracle for the pool.
    fn in_order_members(archive: &[u8]) -> Vec<(String, Vec<u8>, u32)> {
        use std::io::Read as _;
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(archive)).unwrap();
        let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut out: Vec<(String, Vec<u8>, u32)> = Vec::new();
        for i in 0..zip.len() {
            let mut file = zip.by_index(i).unwrap();
            if file.is_dir() {
                continue;
            }
            let name = file.name().to_string();
            // `tree_of` reads no mode off a non-Unix disk (it reports 0),
            // so the oracle expects none there either.
            let mode = if !cfg!(unix) {
                0
            } else if file.unix_mode().is_some_and(|m| m & 0o111 != 0) {
                0o755
            } else {
                0o644
            };
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            match seen.get(&name) {
                Some(&at) => out[at] = (name, bytes, mode),
                None => {
                    seen.insert(name.clone(), out.len());
                    out.push((name, bytes, mode));
                }
            }
        }
        out.sort();
        out
    }

    /// An archive big enough to run on the pool must land exactly what the
    /// one-at-a-time walk landed: every member, its bytes, and its mode.
    /// The in-memory reader — which walks entries strictly in order — is the
    /// oracle.
    #[test]
    fn parallel_zip_extraction_matches_the_in_order_reader() {
        // Past both pool thresholds (entries and declared bytes), so this
        // really does run on the pool.
        let payloads: Vec<(String, Vec<u8>, u32)> = (0..200)
            .map(|i| {
                (
                    format!("pkg/dir{}/file{i}.txt", i % 7),
                    format!("contents of {i}\n").repeat(4096).into_bytes(),
                    if i % 3 == 0 { 0o755 } else { 0o644 },
                )
            })
            .collect();
        let refs: Vec<(&str, &[u8], u32)> = payloads
            .iter()
            .map(|(n, b, m)| (n.as_str(), b.as_slice(), *m))
            .collect();
        let archive = make_zip_with_modes(&refs);

        let dest = tempfile::tempdir().unwrap();
        extract_zip(&archive, dest.path(), /*strip_first=*/ false).unwrap();

        assert_eq!(tree_of(dest.path()), in_order_members(&archive));
    }

    /// A repeated destination — two entries that strip down to the same
    /// name — must end up with the LAST one's bytes however many threads
    /// wrote it.
    #[test]
    fn parallel_zip_resolves_repeated_destinations_last_wins() {
        let mut files: Vec<(String, Vec<u8>)> = (0..100)
            .map(|i| (format!("a/pad{i}.txt"), vec![b'p'; 128 * 1024]))
            .collect();
        files.push(("a/dup.txt".to_string(), b"first".to_vec()));
        files.push(("b/dup.txt".to_string(), b"second".to_vec()));
        let refs: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();
        let archive = make_zip(&refs);
        let dest = tempfile::tempdir().unwrap();
        extract_zip(&archive, dest.path(), /*strip_first=*/ true).unwrap();
        assert_eq!(
            std::fs::read(dest.path().join("dup.txt")).unwrap(),
            b"second",
            "the last spelling of a repeated name wins, as an in-order extraction left it"
        );
    }

    /// Two entries that differ only by ASCII case are ONE file on a
    /// case-insensitive volume (APFS, NTFS), which `PathBuf` equality
    /// cannot see — so the pool would hand them to two threads, each
    /// writing the same inode from offset 0, and land a torn mix of the
    /// two. The in-order reader is the oracle here too: whatever the
    /// volume does with the pair, the result must be what writing them one
    /// at a time, in archive order, produced.
    #[test]
    fn parallel_zip_keeps_case_colliding_entries_in_order() {
        // The colliding pair sits a full chunk apart and the archive is
        // past both pool thresholds, so without the aliasing check these
        // are the FIRST work item of two different threads.
        let a = vec![b'A'; 3 * 1024 * 1024];
        let b = vec![b'B'; 3 * 1024 * 1024];
        let pad: Vec<Vec<u8>> = (0..78)
            .map(|i| format!("pad {i}\n").repeat(4096).into_bytes())
            .collect();
        let mut files: Vec<(String, &[u8])> = vec![("LICENSE".to_string(), a.as_slice())];
        for (i, p) in pad.iter().enumerate().take(ZIP_CHUNK - 1) {
            files.push((format!("pad/a{i}.txt"), p.as_slice()));
        }
        files.push(("license".to_string(), b.as_slice()));
        for (i, p) in pad.iter().enumerate().skip(ZIP_CHUNK - 1) {
            files.push((format!("pad/b{i}.txt"), p.as_slice()));
        }
        let refs: Vec<(&str, &[u8])> = files.iter().map(|(n, b)| (n.as_str(), *b)).collect();
        let archive = make_zip(&refs);
        assert!(files.len() >= ZIP_PARALLEL_MIN_ENTRIES);

        // Repeated: a torn write is a race, so one clean run proves little.
        for _ in 0..8 {
            let dest = tempfile::tempdir().unwrap();
            extract_zip(&archive, dest.path(), /*strip_first=*/ false).unwrap();
            let got = std::fs::read(dest.path().join("LICENSE")).unwrap();
            assert!(
                got == b || got == a,
                "a case-colliding pair was torn: {} of {} bytes are the first entry's",
                got.iter().filter(|byte| **byte == b'A').count(),
                got.len()
            );
            // …and on this volume, specifically what the one-at-a-time
            // walk left: whichever of the two the filesystem kept.
            let oracle = tempfile::tempdir().unwrap();
            for (name, bytes) in [("LICENSE", &a), ("license", &b)] {
                std::fs::write(oracle.path().join(name), bytes).unwrap();
            }
            assert_eq!(
                got,
                std::fs::read(oracle.path().join("LICENSE")).unwrap(),
                "the pair must land what writing it in archive order landed"
            );
        }
    }

    /// The same for two spellings one volume folds and another does not:
    /// the walk cannot know which, so it stops spreading the archive.
    #[test]
    fn a_zip_whose_destinations_may_alias_is_not_spread() {
        let plain = |names: &[&str]| {
            let mut files: Vec<(String, Vec<u8>)> = (0..ZIP_PARALLEL_MIN_ENTRIES)
                .map(|i| (format!("pad/p{i}.txt"), vec![b'p'; 128 * 1024]))
                .collect();
            files.extend(names.iter().map(|n| ((*n).to_string(), vec![b'x'; 8])));
            let refs: Vec<(&str, &[u8])> = files
                .iter()
                .map(|(n, b)| (n.as_str(), b.as_slice()))
                .collect();
            make_zip(&refs)
        };
        let plan_for = |names: &[&str]| {
            let archive = plain(names);
            let dest = tempfile::tempdir().unwrap();
            let plan = plan_zip(
                &archive,
                dest.path(),
                /*strip_first=*/ false,
                Sink::Write,
                None,
                None,
            )
            .unwrap();
            (plan, dest)
        };
        for (label, names, spread) in [
            ("distinct names", vec!["one.txt", "two.txt"], true),
            ("ascii case twins", vec!["Read.md", "read.md"], false),
            ("a non-ascii name", vec!["café.txt"], false),
            ("a file that is also a dir", vec!["d", "d/inner"], false),
        ] {
            let (plan, _dest) = plan_for(&names);
            assert_eq!(!plan.in_order, spread, "{label}");
        }
        // A `./`-spelled twin is the same destination, not an aliasing one:
        // the repeated-name rule drops the earlier spelling, so what is
        // left is independent and the pool may still spread it.
        let (plan, _dest) = plan_for(&["x.txt", "./x.txt"]);
        assert!(!plan.in_order);
        assert_eq!(
            plan.entries.iter().filter(|e| e.target.is_some()).count(),
            ZIP_PARALLEL_MIN_ENTRIES + 1,
            "only one spelling of the repeated name is written"
        );
    }

    /// A refusal deep in a pool-sized archive still reads as the one the
    /// one-at-a-time walk raised at that entry.
    #[test]
    fn parallel_zip_reports_a_late_refusal_verbatim() {
        let mut files: Vec<(String, Vec<u8>)> = (0..80)
            .map(|i| (format!("pkg/ok{i}.txt"), vec![b'x'; 128 * 1024]))
            .collect();
        files.push(("../evil.txt".to_string(), b"evil".to_vec()));
        files.extend((0..80).map(|i| (format!("pkg/after{i}.txt"), vec![b'y'; 128 * 1024])));
        let refs: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();
        let archive = make_zip(&refs);
        let dest = tempfile::tempdir().unwrap();
        let err = extract_zip(&archive, dest.path(), /*strip_first=*/ false).unwrap_err();
        assert_eq!(
            err,
            "zip entry `../evil.txt` escapes the extraction dir — refusing the artifact"
        );
        assert!(
            !dest.path().join("pkg/after0.txt").exists(),
            "the walk stopped at the refusal; nothing past it is planned"
        );
        // And the validation pass, which never writes, says the same.
        assert_eq!(
            validate_zip(&archive, dest.path(), false, None).unwrap_err(),
            err
        );
    }

    /// Every file under `root`, relative, with its bytes and unix mode.
    fn tree_of(root: &Path) -> Vec<(String, Vec<u8>, u32)> {
        let mut out: Vec<(String, Vec<u8>, u32)> = walkdir::WalkDir::new(root)
            .into_iter()
            .flatten()
            .filter(|e| e.file_type().is_file())
            .map(|e| {
                let rel = e
                    .path()
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                let bytes = std::fs::read(e.path()).unwrap();
                #[cfg(unix)]
                let mode = {
                    use std::os::unix::fs::PermissionsExt as _;
                    e.metadata().unwrap().permissions().mode() & 0o777
                };
                #[cfg(not(unix))]
                let mode = 0;
                (rel, bytes, mode)
            })
            .collect();
        out.sort();
        out
    }

    #[test]
    fn verify_go_h1_accepts_matching_dirhash() {
        // The SUCCESS path is the golang service-download content verifier —
        // a round-trip against the module's own hasher must pass, and a
        // foreign h1 must name the mismatch.
        let zip_bytes = make_module_zip("m@v1/", &[("go.mod", b"module m\n")]);
        let h1 = go_h1_of_zip(&zip_bytes).unwrap();
        verify_go_h1(&zip_bytes, &h1).expect("a matching dirhash must verify");
        let err = verify_go_h1(
            &zip_bytes,
            "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
        .unwrap_err();
        assert!(err.contains("mismatch"), "{err}");
    }

    #[test]
    fn artifact_matches_integrity_contract() {
        // The repair-path / service-path whole-artifact verifier.
        // Foreign berry cacheKey: refused without attempting the rebuild.
        let err = artifact_matches_integrity(
            b"x",
            "pkg",
            &LockIntegrity::BerryChecksum(format!("8/{}", "0".repeat(128))),
        )
        .unwrap_err();
        assert!(err.contains("cannot verify tarball bytes"), "{err}");

        // 10c0: the cache-zip rebuild round-trips, and a tampered checksum
        // names the mismatch.
        let tgz = make_tgz(&[("package/package.json", br#"{"name":"left-pad"}"#, false)]);
        let err = artifact_matches_integrity(
            &tgz,
            "left-pad",
            &LockIntegrity::BerryChecksum(format!("10c0/{}", "0".repeat(128))),
        )
        .unwrap_err();
        assert!(err.contains("cannot verify tarball bytes"), "{err}");

        // GoH1 has a dedicated fetch-path verifier; None is reachable from a
        // repair against an npm-era lock recording no integrity. Both refuse.
        let err = artifact_matches_integrity(b"x", "pkg", &LockIntegrity::GoH1("h1:x".into()))
            .unwrap_err();
        assert!(err.contains("dedicated ecosystem fetcher"), "{err}");
        let err = artifact_matches_integrity(b"x", "pkg", &LockIntegrity::None).unwrap_err();
        assert!(err.contains("no integrity recorded"), "{err}");

        // …and the in-module verifier pins both as the Unverifiable KIND.
        match verify_integrity(b"x", &LockIntegrity::GoH1("h1:x".into())) {
            Err(FetchError::Unverifiable(_)) => {}
            other => panic!("GoH1 must be Unverifiable in verify_integrity, got {other:?}"),
        }
        match verify_integrity(b"x", &LockIntegrity::None) {
            Err(FetchError::Unverifiable(_)) => {}
            other => panic!("None must be Unverifiable in verify_integrity, got {other:?}"),
        }
    }

    #[test]
    fn sri_dashless_tokens_skip_and_sha256_verifies() {
        let bytes = b"hello";
        let b64 = base64::engine::general_purpose::STANDARD;
        // A dash-less token is skipped, not fatal — the usable hash beside
        // it still verifies.
        assert!(
            verify_sri(bytes, &format!("notanalgo {}", sri_of(bytes))).is_ok(),
            "a dash-less token must not poison the SRI string"
        );
        // sha256-strongest SRI: the sha256 digest arm actually computes and
        // compares — pass on the right digest, refuse on a wrong one.
        let good = b64.encode(Sha256::digest(bytes));
        assert!(verify_sri(bytes, &format!("sha256-{good}")).is_ok());
        let wrong = b64.encode(Sha256::digest(b"other"));
        let err = verify_sri(bytes, &format!("sha256-{wrong}")).unwrap_err();
        assert!(err.contains("sha256"), "{err}");
    }

    #[tokio::test]
    async fn download_refuses_lying_content_length() {
        // wiremock cannot send a mismatched Content-Length, so script a raw
        // socket: a 256 GiB header with no body must refuse on the DECLARED
        // size, before any body read or allocation.
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await; // request head
            let _ = sock
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 274877906944\r\n\
                      Connection: close\r\n\r\n",
                )
                .await;
            // Hold the socket until the client gives up on its own.
            let mut sink = [0u8; 16];
            let _ = sock.read(&mut sink).await;
        });

        let err = download(&build_registry_client(), &format!("http://{addr}/x.tgz"))
            .await
            .unwrap_err();
        assert!(
            err.contains("274877906944") && err.contains("cap"),
            "the refusal must fire on the declared Content-Length: {err}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn download_caps_streamed_bytes_without_content_length() {
        // With NO Content-Length (chunked encoding) the declared-size check
        // never runs — the streamed-bytes cap is the only guard against a
        // lying/absent-length server, so it must fire after ~128 MB.
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await; // request head
            if sock
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
            // Stream zeros until the client hits its cap and drops the
            // connection (our write then errors — the loop's exit).
            let chunk = vec![0u8; 1024 * 1024];
            let head = format!("{:x}\r\n", chunk.len());
            loop {
                if sock.write_all(head.as_bytes()).await.is_err()
                    || sock.write_all(&chunk).await.is_err()
                    || sock.write_all(b"\r\n").await.is_err()
                {
                    break;
                }
            }
        });

        let err = download(&build_registry_client(), &format!("http://{addr}/big.tgz"))
            .await
            .unwrap_err();
        assert!(
            err.contains("exceeded") && err.contains("cap"),
            "the stream cap must fire without a Content-Length: {err}"
        );
        server.abort();
    }

    /// Serves one GET per accepted connection: a 200 head declaring
    /// `chunks × 1 KiB`, then each 1 KiB chunk after its `gaps` delay.
    async fn paced_server(
        gaps: Vec<std::time::Duration>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let gaps = gaps.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await; // request head
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        gaps.len() * 1024
                    );
                    if sock.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                    for gap in gaps {
                        tokio::time::sleep(gap).await;
                        if sock.write_all(&[b'x'; 1024]).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (addr, server)
    }

    /// Every registry client: hosted upstream restore's
    /// `build_registry_client` + `download`, and vendored Maven's
    /// `fetch_registry_bytes` (which sends Maven's own user agent).
    async fn fetch_through_every_registry_client(url: &str) -> Vec<Result<Vec<u8>, String>> {
        vec![
            download(&build_registry_client(), url).await,
            crate::vendor::maven_repo::fetch_registry_bytes(url, MAX_DOWNLOAD_BYTES).await,
        ]
    }

    const SHORT_BOUNDS: ApiTimeouts = ApiTimeouts {
        connect: std::time::Duration::from_secs(2),
        read: std::time::Duration::from_millis(400),
    };

    #[tokio::test]
    async fn registry_clients_have_no_total_deadline() {
        // #872: the registry clients set a 60 s whole-request deadline, so
        // a slow but steady download was aborted mid-body. Under the shared
        // `ApiTimeouts` policy only silence counts: a body that trickles
        // for 4× the (shortened) idle bound, never pausing that long,
        // arrives whole through every registry client.
        let _bounds = test_timeouts::set(SHORT_BOUNDS);
        let gaps = vec![std::time::Duration::from_millis(100); 16];
        let (addr, server) = paced_server(gaps).await;
        let url = format!("http://{addr}/slow.tgz");
        for got in fetch_through_every_registry_client(&url).await {
            assert_eq!(
                got.expect("a progressing body must not time out").len(),
                16 * 1024
            );
        }
        server.abort();
    }

    #[tokio::test]
    async fn registry_clients_fail_a_body_that_stalls_past_the_idle_bound() {
        // A connection that goes silent mid-body fails at the idle bound
        // instead of holding the run until the server resumes (here 5 s
        // later; on `main` both clients waited it out and succeeded).
        let _bounds = test_timeouts::set(SHORT_BOUNDS);
        let mut gaps = vec![std::time::Duration::ZERO; 4];
        gaps.push(std::time::Duration::from_secs(5));
        let (addr, server) = paced_server(gaps).await;
        let url = format!("http://{addr}/stall.tgz");
        let started = std::time::Instant::now();
        for got in fetch_through_every_registry_client(&url).await {
            let err = got.expect_err("a stalled body must fail at the idle bound");
            assert!(err.contains("error reading"), "{err}");
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(4),
            "both fetches must give up at the idle bound, took {:?}",
            started.elapsed()
        );
        server.abort();
    }

    #[test]
    fn total_decompressed_cap_fails_closed_across_zip_extractors() {
        // The per-entry actual-bytes guards mean only HONEST content reaches
        // the total cap: four entries of exactly MAX_ENTRY_BYTES land the
        // running total exactly ON the 512 MB cap, and a fifth 1-byte entry
        // pushes past it — the cheapest honest fixture that trips the check.
        // (The suite's most expensive test: ~512 MB of zeros deflate once,
        // and each extractor inflates them back before refusing entry 5.)
        use std::io::Write as _;
        let zeros = vec![0u8; MAX_ENTRY_BYTES as usize];
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for i in 0..4 {
            writer
                .start_file(
                    format!("m@v1/z{i}.bin"),
                    zip::write::SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Deflated),
                )
                .unwrap();
            writer.write_all(&zeros).unwrap();
        }
        drop(zeros);
        writer
            .start_file(
                "m@v1/tip.bin",
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
        writer.write_all(b"x").unwrap();
        let bytes = writer.finish().unwrap().into_inner();

        {
            let tmp = tempfile::tempdir().unwrap();
            let err = extract_zip(&bytes, tmp.path(), /*strip_first=*/ false).unwrap_err();
            assert!(err.contains("decompresses past"), "{err}");
        }
        {
            let tmp = tempfile::tempdir().unwrap();
            let err = extract_zip_with_prefix(&bytes, tmp.path(), "m@v1/").unwrap_err();
            assert!(err.contains("decompresses past"), "{err}");
        }
        // The dirhash pre-pass counts ACTUAL decompressed bytes, in memory.
        let err = go_h1_of_zip(&bytes).unwrap_err();
        assert!(err.contains("decompresses past"), "{err}");
    }
}
