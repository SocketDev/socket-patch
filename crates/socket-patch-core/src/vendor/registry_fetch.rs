//! Pristine-artifact fetching for lockfile-resolved packages with no
//! installed copy.
//!
//! `vendor` needs an installed package dir to stage from; on a fresh clone
//! there is none. This module downloads the pristine artifact the lockfile
//! resolves (the lock-recorded URL when present, the conventional registry
//! URL otherwise), verifies it against the integrity the lock records
//! **FAIL-CLOSED and before anything is written to the staging dir**, and
//! extracts it into a private tempdir the vendor pipeline then treats as
//! the installed dir. The project tree — node_modules included — is never
//! touched.
//!
//! Trust model: the URL comes from the user's own committed lockfile (or a
//! conventional construction from it); content trust comes from the
//! lock-recorded hash, not the transport — which is also why an entry with
//! no verifier ([`LockIntegrity::None`]) is refused outright
//! ([`FetchError::Unverifiable`]) without any network I/O.

use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::constants::USER_AGENT;
use crate::crawlers::go_crawler::encode_module_path;
use crate::patch::apply::is_safe_relative_subpath;
use crate::patch::path_safety::is_safe_single_segment;

use super::lock_inventory::{LockIntegrity, LockfileEntry, SourceKind};

/// The default npm registry; override with `SOCKET_NPM_REGISTRY` (the
/// enterprise-mirror / test escape hatch — `.npmrc` parsing is out of
/// scope, but lock-recorded `resolved` URLs already carry custom hosts).
pub const DEFAULT_NPM_REGISTRY: &str = "https://registry.npmjs.org";

/// Whole-package caps — wider than `patch/package.rs`'s patch-archive caps
/// because these are full upstream packages, but still bounded so a
/// poisoned lockfile cannot turn the fetch into a disk/memory bomb.
const MAX_DOWNLOAD_BYTES: u64 = 128 * 1024 * 1024;
// `pub(crate)`: `common::read_zip_members` is the in-memory twin of
// [`extract_zip`] and must refuse exactly the same archives, so it reads the
// one set of caps rather than carrying a copy that can drift.
pub(crate) const MAX_TOTAL_DECOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const MAX_ENTRY_BYTES: u64 = 128 * 1024 * 1024;
pub(crate) const MAX_ENTRIES: usize = 60_000;

/// A fetched, verified package whose tree is written only when a branch
/// actually reads it.
///
/// The download, the size caps and the SRI / sha / dirhash verification all
/// stay EAGER, and so does the archive walk: before this value exists the
/// bytes have been validated against exactly the rules the extractor
/// enforces ([`Sink::Validate`]), so a truncated, oversized, traversing or
/// otherwise malformed artifact is still refused at the fetch, at the same
/// entry and with the same message. What is deferred is the WRITING — the
/// committed-artifact reuse, the in-sync hot path and the vendoring service
/// never read the tree, so an idempotent re-run on a lockfile-only checkout
/// no longer creates and deletes one.
///
/// Better still, most of the tree never reaches the tempdir at all: a local
/// build asks for the vendor stage directly ([`FetchedPackage::stage_into`]),
/// which the verified bytes write in one pass instead of an extraction and a
/// whole-tree copy out of it.
///
/// The tempdir lives exactly as long as this value — callers must hold it
/// until the vendor pipeline has finished staging from [`FetchedPackage::dir`].
pub struct FetchedPackage {
    dir: PathBuf,
    /// Where the bytes came from (surfaced in the fetch warning event).
    pub url: String,
    /// The verified bytes and the extractor that writes them — the same
    /// function an eager fetch called, kept so the tree can be produced
    /// wherever it is first wanted: the private tempdir
    /// ([`FetchedPackage::dir`]), or a vendor stage directly
    /// ([`FetchedPackage::stage_into`]).
    extract: std::sync::Arc<Extractor>,
    /// The tempdir materialisation's outcome, shared by every later caller
    /// so a failure reads the same each time.
    extracted: tokio::sync::OnceCell<Result<(), String>>,
    _tmp: tempfile::TempDir,
}

/// Writes a verified archive out under a destination, skipping any entry
/// whose final path component matches (`fresh_copy`'s `skip_file_name`).
type Extractor = dyn Fn(&Path, Option<&str>) -> Result<(), String> + Send + Sync;

impl std::fmt::Debug for FetchedPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchedPackage")
            .field("dir", &self.dir)
            .field("url", &self.url)
            .field(
                "extracted",
                &self.extracted.get().is_some_and(Result::is_ok),
            )
            .finish()
    }
}

impl FetchedPackage {
    fn pending(
        dir: PathBuf,
        url: String,
        tmp: tempfile::TempDir,
        extract: impl Fn(&Path, Option<&str>) -> Result<(), String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            dir,
            url,
            extract: std::sync::Arc::new(extract),
            extracted: tokio::sync::OnceCell::new(),
            _tmp: tmp,
        }
    }

    /// Where the package root WILL be. Pure — no I/O and no extraction, so
    /// it answers naming questions (a gem's `<name>-<version>` leaf, whether
    /// the parent is a gem home's `gems/`) without materialising anything.
    pub fn dir_path(&self) -> &Path {
        &self.dir
    }

    /// The package root (`package.json` at the top for npm) with its content
    /// on disk, extracted on the first call and kept for the rest of the run.
    pub async fn dir(&self) -> Result<&Path, String> {
        let done = self
            .extracted
            .get_or_init(|| self.write_tree(self.dir.clone(), None))
            .await;
        match done {
            Ok(()) => Ok(&self.dir),
            Err(detail) => Err(detail.clone()),
        }
    }

    /// Write the tree at `dst` instead of the tempdir: the vendor stage the
    /// local build patches, which a fetched source used to reach by
    /// extracting into the tempdir and copying the whole tree out of it
    /// again. `dst` is removed and recreated first, exactly as `fresh_copy`
    /// does, and `skip_file_name` drops the same entries it dropped.
    pub async fn stage_into(&self, dst: &Path, skip_file_name: Option<&str>) -> Result<(), String> {
        // An earlier branch already wrote the tempdir out (a dry-run
        // preview, or the release-variant probe the vendor loop runs for
        // pypi and gem). Copying it is cheaper than inflating the archive a
        // second time, and it is what this path did before the fetch went
        // lazy.
        if self.extracted.get().is_some_and(Result::is_ok) {
            return crate::patch::copy_tree::fresh_copy(&self.dir, dst, skip_file_name)
                .await
                .map_err(|e| e.to_string());
        }
        crate::patch::copy_tree::remove_tree(dst)
            .await
            .map_err(|e| format!("cannot clear {}: {e}", dst.display()))?;
        tokio::fs::create_dir_all(dst)
            .await
            .map_err(|e| format!("cannot create {}: {e}", dst.display()))?;
        self.write_tree(dst.to_path_buf(), skip_file_name.map(str::to_string))
            .await
    }

    /// Extraction is sync CPU + disk work; keep it off the runtime thread so
    /// the concurrent fetches around it keep moving.
    async fn write_tree(&self, dst: PathBuf, skip_file_name: Option<String>) -> Result<(), String> {
        let extract = std::sync::Arc::clone(&self.extract);
        match tokio::task::spawn_blocking(move || extract(&dst, skip_file_name.as_deref())).await {
            Ok(outcome) => outcome,
            Err(e) => Err(format!("extraction task failed: {e}")),
        }
    }
}

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

/// One shared client for all fetches in a run.
/// The registry HTTP client type, nameable by callers that don't depend on
/// reqwest directly (the CLI's pristine-source ladder).
pub type RegistryClient = reqwest::Client;

pub fn build_registry_client() -> RegistryClient {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
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

/// Fetch + verify + extract one lockfile entry. Ecosystems without a
/// fetcher yet return [`FetchError::Unverifiable`] (callers keep their
/// not-installed outcome).
pub async fn fetch_and_stage(
    entry: &LockfileEntry,
    client: &reqwest::Client,
) -> Result<FetchedPackage, FetchError> {
    if entry.integrity == LockIntegrity::None {
        return Err(FetchError::Unverifiable(format!(
            "the lockfile records no integrity hash for {}@{}; refusing to fetch \
             unverifiable content",
            entry.name, entry.version
        )));
    }
    match entry.ecosystem {
        "npm" => fetch_npm(entry, client).await,
        "cargo" => fetch_cargo(entry, client).await,
        "golang" => fetch_golang(entry, client).await,
        "composer" => fetch_composer(entry, client).await,
        "gem" => fetch_gem(entry, client).await,
        "pypi" => fetch_pypi(entry, client).await,
        other => Err(FetchError::Unverifiable(format!(
            "no registry fetcher for ecosystem `{other}`"
        ))),
    }
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
/// refused it. Only the environment-shaped `cannot create …` errors are
/// exclusive to [`Sink::Write`].
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

    /// Where `rel` is written, with its parent directory created, or `None`
    /// when the entry is not written (validating, or skipped by name).
    fn destination(&mut self, rel: &Path) -> Result<Option<PathBuf>, String> {
        if self.sink == Sink::Validate
            || self
                .skip_file_name
                .is_some_and(|skip| rel.file_name().is_some_and(|n| n == skip))
        {
            return Ok(None);
        }
        let target = self.dest.join(rel);
        if let Some(parent) = target.parent() {
            if !self.made.contains(parent) {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
                self.made.insert(parent.to_path_buf());
            }
        }
        Ok(Some(target))
    }

    /// The open destination file for `rel`, or `None` when the entry is not
    /// written. The tar walk stays one pass: a tar entry is only reachable
    /// by reading the one before it.
    fn open(&mut self, rel: &Path) -> Result<Option<std::fs::File>, String> {
        let Some(target) = self.destination(rel)? else {
            return Ok(None);
        };
        std::fs::File::create(&target)
            .map(Some)
            .map_err(|e| format!("cannot create {}: {e}", target.display()))
    }
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
pub(crate) fn validate_zip(
    bytes: &[u8],
    strip_first: bool,
    watch: Option<&str>,
) -> Result<bool, String> {
    walk_zip(
        bytes,
        Path::new(""),
        strip_first,
        Sink::Validate,
        watch,
        None,
    )
}

/// The zip walk, in two passes.
///
/// Pass one reads the central directory alone — no entry is inflated — and
/// answers everything the one-entry-at-a-time walk decided from headers, in
/// the same order over the same running total: the traversal guard, the
/// per-entry and total DECLARED caps, and each entry's destination (with
/// every parent directory created once, where the old walk re-created them
/// per entry). It stops at the first refusal, exactly where the single walk
/// stopped accumulating.
///
/// Pass two inflates the planned entries on a bounded pool of threads, each
/// with its own reader over the shared bytes. Inflating is the whole cost of
/// a big dist zip and it is per-entry independent, so the only thing the
/// pass has to serialise is the ANSWER: a repeated name is written by its
/// last spelling, as an in-order extraction left it, and the refusal
/// reported is the one at the lowest entry index — which, against pass one's
/// own index, reproduces the single walk's verdict entry for entry.
fn walk_zip(
    bytes: &[u8],
    dest: &Path,
    strip_first: bool,
    sink: Sink,
    watch: Option<&str>,
    skip_file_name: Option<&str>,
) -> Result<bool, String> {
    let plan = plan_zip(bytes, dest, strip_first, sink, watch, skip_file_name)?;
    let body_refusal = inflate_planned_entries(bytes, &plan.entries, plan.declared_total);
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
}

struct ZipPlan {
    entries: Vec<PlannedEntry>,
    /// The first header-shaped refusal and the entry index it fired at.
    header_refusal: Option<(usize, String)>,
    /// What the planned entries declare they decompress to — the pool's
    /// work estimate.
    declared_total: u64,
    seen_watched: bool,
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
    let mut out = EntrySink::new(dest, sink).skipping(skip_file_name);
    let mut plan = ZipPlan {
        entries: Vec::new(),
        header_refusal: None,
        declared_total: 0,
        seen_watched: false,
    };
    // Where each destination path was last planned, so a repeated name is
    // written only by its final spelling — what an in-order extraction that
    // overwrote it left behind.
    let mut written_at: std::collections::HashMap<PathBuf, usize> =
        std::collections::HashMap::new();
    let mut total: u64 = 0;
    for i in 0..archive.len() {
        // `by_index`, not the raw reader: an entry the decompressor refuses
        // (an unsupported method, an encrypted member) must be refused HERE,
        // at the index and with the words the one-pass walk used, rather
        // than falling through to a later check.
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
        let target = match out.destination(&rel) {
            Ok(target) => target,
            Err(detail) => {
                plan.header_refusal = Some((i, detail));
                break;
            }
        };
        if let Some(target) = target.as_ref() {
            if let Some(earlier) = written_at.insert(target.clone(), plan.entries.len()) {
                plan.entries[earlier].target = None;
            }
        }
        plan.seen_watched |= watch.is_some_and(|name| lands_at_root(&rel, name));
        plan.declared_total += declared;
        plan.entries.push(PlannedEntry {
            index: i,
            rel_str,
            declared,
            exec: file.unix_mode().is_some_and(|m| m & 0o111 != 0),
            target,
        });
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
) -> Option<(usize, String)> {
    let worth_spreading =
        entries.len() >= ZIP_PARALLEL_MIN_ENTRIES && declared_total >= ZIP_PARALLEL_MIN_BYTES;
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
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                let mut archive = match zip::ZipArchive::new(std::io::Cursor::new(bytes)) {
                    Ok(archive) => archive,
                    Err(e) => {
                        keep_lowest(&refusal, (0, format!("unreadable zip: {e}")));
                        return;
                    }
                };
                loop {
                    let at = cursor.fetch_add(ZIP_CHUNK, std::sync::atomic::Ordering::Relaxed);
                    if at >= entries.len() {
                        return;
                    }
                    let upto = (at + ZIP_CHUNK).min(entries.len());
                    for entry in &entries[at..upto] {
                        if let Some(hit) = inflate_one(&mut archive, entry) {
                            keep_lowest(&refusal, hit);
                        }
                    }
                }
            });
        }
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
    } = entry;
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
/// This is exactly what a `metadata(dest.join(name))` probe answered once
/// the eager extraction had run.
fn lands_at_root(rel: &Path, name: &str) -> bool {
    rel.components()
        .next()
        .is_some_and(|c| c.as_os_str() == name)
}

/// Composer dist zips: sha1-verified; a variable zipball top dir is
/// stripped when present, flat `composer archive`-built dists extract
/// as-is. The extracted dir plays the installed package dir.
async fn fetch_composer(
    entry: &LockfileEntry,
    client: &reqwest::Client,
) -> Result<FetchedPackage, FetchError> {
    let Some(url) = entry.resolved.clone() else {
        return Err(FetchError::Unverifiable(format!(
            "composer.lock records no dist URL for {}@{}",
            entry.name, entry.version
        )));
    };
    let bytes = download(client, &url).await.map_err(FetchError::Failed)?;
    verify_integrity(&bytes, &entry.integrity)?;
    let tmp = tempfile::tempdir()
        .map_err(|e| FetchError::Failed(format!("cannot create fetch tempdir: {e}")))?;
    let dir = tmp.path().join("package");
    // Strip only when the zip actually nests under a lone top dir (the
    // zipball layout) — flat `composer archive`-built dists carry
    // composer.json at the root; see [`zip_has_single_top_dir`].
    let strip_first = zip_has_single_top_dir(&bytes).map_err(FetchError::Failed)?;
    let has_manifest =
        validate_zip(&bytes, strip_first, Some("composer.json")).map_err(FetchError::Failed)?;
    if !has_manifest {
        return Err(FetchError::Failed(format!(
            "fetched dist for {}@{} carries no composer.json",
            entry.name, entry.version
        )));
    }
    Ok(FetchedPackage::pending(dir, url, tmp, move |dest, skip| {
        extract_zip_skipping(&bytes, dest, strip_first, skip)
    }))
}

/// `.gem` files are plain tar containers holding `data.tar.gz` (the
/// package content, no prefix dir) + metadata. The whole `.gem` is
/// sha256-verified against the Gemfile.lock CHECKSUMS entry first.
async fn fetch_gem(
    entry: &LockfileEntry,
    client: &reqwest::Client,
) -> Result<FetchedPackage, FetchError> {
    // The staged leaf must be the canonical `{name}-{version}`: the gem
    // vendor backend refuses any other leaf as a platform-suffixed install
    // (`platform_gem_unsupported`), so a generic name would kill the whole
    // auto-fetch path. The coordinates thereby become a tempdir path
    // component — `inventory_gemfile_lock` already filters both, but
    // re-assert locally (defense in depth), before any network I/O.
    if !is_safe_single_segment(&entry.name) || !is_safe_single_segment(&entry.version) {
        return Err(FetchError::Failed(format!(
            "unsafe gem coordinates `{}` @ `{}` — refusing to stage",
            entry.name, entry.version
        )));
    }
    let Some(url) = entry.resolved.clone() else {
        return Err(FetchError::Unverifiable(format!(
            "no download URL for {}@{}",
            entry.name, entry.version
        )));
    };
    let bytes = download(client, &url).await.map_err(FetchError::Failed)?;
    verify_integrity(&bytes, &entry.integrity)?;

    let tmp = tempfile::tempdir()
        .map_err(|e| FetchError::Failed(format!("cannot create fetch tempdir: {e}")))?;
    let dir = tmp.path().join(format!("{}-{}", entry.name, entry.version));
    validate_gem_data(&bytes).map_err(FetchError::Failed)?;
    Ok(FetchedPackage::pending(dir, url, tmp, move |dest, skip| {
        extract_gem_data_skipping(&bytes, dest, skip)
    }))
}

/// Pure-python wheels recorded by uv.lock (URL + sha256): the unzipped
/// wheel IS a site-packages layout (package dirs + `.dist-info/RECORD` at
/// the root), which is exactly the shape the pypi vendor backend stages
/// from.
/// PyPI's JSON API base; override with `SOCKET_PYPI_JSON_API` (tests point it
/// at a mock). Used only to turn a lock's file hash into a download URL for
/// locks that record hashes without URLs (poetry.lock).
pub const DEFAULT_PYPI_JSON_API: &str = "https://pypi.org/pypi";

fn pypi_json_api_base() -> String {
    std::env::var("SOCKET_PYPI_JSON_API")
        .ok()
        .map(|v| v.trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_PYPI_JSON_API.to_string())
}

/// Resolve the download URL of the release file whose sha256 the lock
/// records, via `GET <api>/<name>/<version>/json` → `urls[].digests.sha256`.
/// The hash, not the filename, selects the file, so a lock that names a wheel
/// PyPI has since re-uploaded under the same name cannot be satisfied by
/// different bytes — the download is still verified against the same hash.
///
/// `candidates` is the lock's digest set: a single digest (poetry.lock names
/// the wheel) takes the first release file carrying it; several digests
/// (Pipfile.lock lists every release file's hash) take the pure-Python
/// `-none-any.whl` whose digest is in the set — a platform wheel or sdist is
/// never chosen, because the vendored wheel must install everywhere.
async fn resolve_pypi_url_by_hash(
    entry: &LockfileEntry,
    candidates: &[String],
    client: &reqwest::Client,
) -> Result<String, FetchError> {
    let api = format!(
        "{}/{}/{}/json",
        pypi_json_api_base(),
        entry.name,
        entry.version
    );
    let resp = client.get(&api).send().await.map_err(|e| {
        FetchError::Failed(format!(
            "PyPI JSON API request for {} failed: {e}",
            entry.purl
        ))
    })?;
    if !resp.status().is_success() {
        return Err(FetchError::Failed(format!(
            "PyPI JSON API returned HTTP {} for {}",
            resp.status(),
            entry.purl
        )));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| {
        FetchError::Failed(format!(
            "PyPI JSON API response for {} is not JSON: {e}",
            entry.purl
        ))
    })?;
    let digest_matches = |file: &serde_json::Value| {
        file.get("digests")
            .and_then(|d| d.get("sha256"))
            .and_then(serde_json::Value::as_str)
            .is_some_and(|d| candidates.iter().any(|c| d.eq_ignore_ascii_case(c)))
    };
    let is_pure_wheel = |file: &serde_json::Value| {
        file.get("filename")
            .and_then(serde_json::Value::as_str)
            .or_else(|| file.get("url").and_then(serde_json::Value::as_str))
            .is_some_and(|name| {
                name.split(['?', '#'])
                    .next()
                    .is_some_and(|n| n.ends_with("-none-any.whl"))
            })
    };
    let files: Vec<&serde_json::Value> = body
        .get("urls")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|file| digest_matches(file))
        .collect();
    let chosen = if candidates.len() == 1 {
        files.first().copied()
    } else {
        files.iter().copied().find(|file| is_pure_wheel(file))
    };
    chosen
        .and_then(|file| file.get("url").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .ok_or_else(|| {
            FetchError::Unverifiable(if candidates.len() == 1 {
                format!(
                    "no PyPI release file for {}@{} matches the lockfile's sha256 {}",
                    entry.name, entry.version, candidates[0]
                )
            } else {
                format!(
                    "no platform-independent (`-none-any.whl`) PyPI release file for {}@{} \
                     matches any of the {} sha256 digests the lockfile records",
                    entry.name,
                    entry.version,
                    candidates.len()
                )
            })
        })
}

async fn fetch_pypi(
    entry: &LockfileEntry,
    client: &reqwest::Client,
) -> Result<FetchedPackage, FetchError> {
    let url = match (&entry.resolved, &entry.integrity) {
        (Some(url), _) => url.clone(),
        // poetry.lock records the wheel's hash but no URL: look the file up
        // by that hash (verified again after download).
        (None, LockIntegrity::Sha256Hex(sha256)) => {
            resolve_pypi_url_by_hash(entry, std::slice::from_ref(sha256), client).await?
        }
        // Pipfile.lock records every release file's hash without filenames:
        // pick the pure wheel whose digest is in the set (verified again
        // after download against that set).
        (None, LockIntegrity::Sha256AnyOf(digests)) => {
            resolve_pypi_url_by_hash(entry, digests, client).await?
        }
        (None, _) => {
            return Err(FetchError::Unverifiable(format!(
                "the lockfile records no platform-independent wheel URL or sha256 for {}@{}",
                entry.name, entry.version
            )));
        }
    };
    let bytes = download(client, &url).await.map_err(FetchError::Failed)?;
    verify_integrity(&bytes, &entry.integrity)?;
    let tmp = tempfile::tempdir()
        .map_err(|e| FetchError::Failed(format!("cannot create fetch tempdir: {e}")))?;
    let dir = tmp.path().join("site-packages");
    validate_zip(&bytes, /*strip_first=*/ false, None).map_err(FetchError::Failed)?;
    Ok(FetchedPackage::pending(dir, url, tmp, move |dest, skip| {
        extract_zip_skipping(&bytes, dest, /*strip_first=*/ false, skip)
    }))
}

/// crates.io static download host; override with `SOCKET_CRATES_REGISTRY`.
pub const DEFAULT_CRATES_REGISTRY: &str = "https://static.crates.io/crates";

fn crates_registry_base() -> String {
    std::env::var("SOCKET_CRATES_REGISTRY")
        .ok()
        .map(|v| v.trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_CRATES_REGISTRY.to_string())
}

/// `.crate` files are tar.gz with a `{name}-{version}/` top dir — the same
/// extraction path as npm tarballs. The Cargo.lock `checksum` is the sha256
/// of the `.crate` bytes.
async fn fetch_cargo(
    entry: &LockfileEntry,
    client: &reqwest::Client,
) -> Result<FetchedPackage, FetchError> {
    let url = entry.resolved.clone().unwrap_or_else(|| {
        format!(
            "{}/{}/{}-{}.crate",
            crates_registry_base(),
            entry.name,
            entry.name,
            entry.version
        )
    });
    let bytes = download(client, &url).await.map_err(FetchError::Failed)?;
    verify_integrity(&bytes, &entry.integrity)?;

    let tmp = tempfile::tempdir()
        .map_err(|e| FetchError::Failed(format!("cannot create fetch tempdir: {e}")))?;
    let dir = tmp.path().join("crate");
    if !validate_tgz(&bytes, Some("Cargo.toml")).map_err(FetchError::Failed)? {
        return Err(FetchError::Failed(format!(
            "fetched .crate for {}@{} carries no Cargo.toml — not a crate",
            entry.name, entry.version
        )));
    }
    Ok(FetchedPackage::pending(dir, url, tmp, move |dest, skip| {
        extract_tgz_skipping(&bytes, dest, skip)
    }))
}

/// go's default module proxy (the first element of go's default
/// `GOPROXY=https://proxy.golang.org,direct`).
pub const DEFAULT_GOPROXY: &str = "https://proxy.golang.org";

/// The module proxy go itself would ask for `module`, or `Err` when go would
/// not use a proxy for it: GOPROXY's first element is `off` or `direct`, or
/// the module matches GONOPROXY (defaulting to GOPRIVATE). Falling back to a
/// public proxy there would send a private module path off the machine.
/// A non-empty `SOCKET_GOPROXY` is an explicit choice and always wins.
fn goproxy_base(module: &str) -> Result<String, String> {
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
fn go_match_prefix_patterns(globs: &str, target: &str) -> bool {
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
fn go_h1_of_zip(bytes: &[u8]) -> Result<String, String> {
    Ok(walk_module_zip(bytes, None)?.h1)
}

/// What one walk over a module zip learned.
struct ModuleZipWalk {
    /// The `h1:` dirhash of the entries.
    h1: String,
    /// The refusal [`extract_zip_with_prefix`] would have raised over the
    /// same entries, held back — `None` when it would have extracted
    /// cleanly, and always `None` when no prefix was given.
    extract_refusal: Option<String>,
}

/// The dirhash walk, optionally also answering what the extraction walk
/// would have said about the same entries.
///
/// The golang registry fetch used to inflate every entry twice: once for
/// the dirhash, once to write the tree. Both walks read the same deflate
/// streams and both derive everything they check from the entry's name,
/// its declared size and how many bytes it actually decompresses to — all
/// of which this walk already has — so the second inflate bought nothing.
///
/// The ORDER the two walks produced is preserved exactly. The dirhash pass
/// ran to completion first, so its refusal still wins outright and returns
/// here; the extraction refusal is recorded at the lowest entry index,
/// where the second walk would have stopped, and handed back for the caller
/// to raise only after the dirhash has been compared — which is where the
/// second walk used to start.
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
        // its own order. Only up to the first refusal: past that the walk it
        // stands in for had already stopped, totals included.
        if let (Some(prefix), None) = (validate_prefix, extract_refusal.as_ref()) {
            extract_refusal =
                module_entry_refusal(&name, prefix, declared, entry_bytes, &mut declared_total);
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
pub(crate) fn validate_zip_with_prefix(bytes: &[u8], prefix: &str) -> Result<(), String> {
    walk_zip_with_prefix(bytes, Path::new(""), prefix, Sink::Validate, None)
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

async fn fetch_golang(
    entry: &LockfileEntry,
    client: &reqwest::Client,
) -> Result<FetchedPackage, FetchError> {
    let LockIntegrity::GoH1(expected) = &entry.integrity else {
        return Err(FetchError::Unverifiable(
            "go module entries verify via the go.sum h1 dirhash only".to_string(),
        ));
    };
    let url = match &entry.resolved {
        Some(url) => url.clone(),
        None => format!(
            "{}/{}/@v/{}.zip",
            goproxy_base(&entry.name).map_err(FetchError::Unverifiable)?,
            encode_module_path(&entry.name),
            encode_module_path(&entry.version)
        ),
    };
    let bytes = download(client, &url).await.map_err(FetchError::Failed)?;
    let prefix = format!("{}@{}/", entry.name, entry.version);
    // One inflate answers both the dirhash and the extraction rules; see
    // [`walk_module_zip`] for why that keeps the two refusals' order.
    let walk = walk_module_zip(&bytes, Some(&prefix)).map_err(FetchError::Failed)?;
    if walk.h1 != *expected {
        return Err(FetchError::Failed(format!(
            "go.sum dirhash mismatch: lockfile records {expected}, the fetched module zip \
             hashes to {}",
            walk.h1
        )));
    }
    if let Some(detail) = walk.extract_refusal {
        return Err(FetchError::Failed(detail));
    }
    let tmp = tempfile::tempdir()
        .map_err(|e| FetchError::Failed(format!("cannot create fetch tempdir: {e}")))?;
    let dir = tmp.path().join("module");
    Ok(FetchedPackage::pending(dir, url, tmp, move |dest, skip| {
        extract_zip_with_prefix_skipping(&bytes, dest, &prefix, skip)
    }))
}

async fn fetch_npm(
    entry: &LockfileEntry,
    client: &reqwest::Client,
) -> Result<FetchedPackage, FetchError> {
    fetch_npm_inner(entry, client, true).await
}

async fn fetch_npm_inner(
    entry: &LockfileEntry,
    client: &reqwest::Client,
    verify: bool,
) -> Result<FetchedPackage, FetchError> {
    // A foreign berry cacheKey is decidable from the lockfile alone: refuse
    // BEFORE the download, keeping the Unverifiable no-network contract (and
    // not spending a full tarball download on an entry we could never
    // verify).
    if verify {
        if let LockIntegrity::BerryChecksum(expected) = &entry.integrity {
            if !expected.starts_with("10c0/") {
                return Err(FetchError::Unverifiable(format!(
                    "yarn berry checksum `{expected}` uses a cacheKey other than 10c0; \
                     the cache-zip recipe is not reproducible for it"
                )));
            }
        }
    }
    let url = entry
        .resolved
        .clone()
        .unwrap_or_else(|| npm_tarball_url(&npm_registry_base(), &entry.name, &entry.version));
    let bytes = download(client, &url).await.map_err(FetchError::Failed)?;
    if !verify {
        // fetch_npm_unverified: the caller owns end-to-end verification.
    } else {
        match &entry.integrity {
            // yarn berry locks never hash the tarball itself — the checksum is
            // sha512 of the deterministic cache zip. Rebuild it from the fetched
            // bytes (the same spike-pinned recipe the berry wiring uses) and
            // compare. Only cacheKey 10c0 (yarn 4 default) is reproducible.
            LockIntegrity::BerryChecksum(expected) => {
                let actual = super::berry_zip::berry_cache_checksum_10c0(&bytes, &entry.name)
                    .map_err(FetchError::Failed)?;
                if &actual != expected {
                    return Err(FetchError::Failed(format!(
                        "yarn berry cache checksum mismatch: lockfile records {expected}, \
                         the fetched tarball rebuilds to {actual}"
                    )));
                }
            }
            other => verify_integrity(&bytes, other)?,
        }
    }

    let tmp = tempfile::tempdir()
        .map_err(|e| FetchError::Failed(format!("cannot create fetch tempdir: {e}")))?;
    let dir = tmp.path().join("package");
    if !validate_tgz(&bytes, Some("package.json")).map_err(FetchError::Failed)? {
        return Err(FetchError::Failed(format!(
            "fetched tarball for {}@{} carries no package.json — not an npm package",
            entry.name, entry.version
        )));
    }
    Ok(FetchedPackage::pending(dir, url, tmp, move |dest, skip| {
        extract_tgz_skipping(&bytes, dest, skip)
    }))
}

/// Stage a package from an on-disk vendored tarball (the fresh-clone
/// re-vendor path: the project has our committed artifact but no installed
/// copy). The bytes are verified against the LEDGER-recorded sha256 before
/// extraction — same fail-closed posture as the registry path; an entry
/// with no recorded hash is refused.
pub async fn stage_local_artifact(
    tgz_path: &Path,
    expected_sha256_hex: &str,
) -> Result<FetchedPackage, FetchError> {
    if expected_sha256_hex.is_empty() {
        return Err(FetchError::Unverifiable(
            "the vendor ledger records no sha256 for the artifact".to_string(),
        ));
    }
    // Guarded read (`open_regular_file`): a FIFO squatting at the committed
    // artifact path must fail fast instead of wedging the fresh-clone
    // re-vendor forever in an `open(2)` waiting for a writer — the caller's
    // metadata probe passes for a FIFO, so this is the first open. Same
    // guard class as the vendor lockfile reads.
    let bytes = {
        use tokio::io::AsyncReadExt as _;
        let (file, metadata) = crate::utils::fs::open_regular_file(tgz_path)
            .await
            .map_err(|e| FetchError::Failed(format!("cannot read {}: {e}", tgz_path.display())))?;
        // Enforce the cap BEFORE the size-matched allocation and read: the
        // committed artifact path can hold a huge (or sparse, cost-free to
        // craft) file, and a metadata-sized `with_capacity` would abort or
        // OOM instead of returning the clean cap error below. Declared size
        // here + actual bytes below — the same double enforcement as
        // [`download`]; the `take` holds the memory bound even against a
        // file that grows between this stat and the read.
        if metadata.len() > MAX_DOWNLOAD_BYTES {
            return Err(FetchError::Failed(format!(
                "{}: artifact exceeds the {MAX_DOWNLOAD_BYTES}-byte cap",
                tgz_path.display()
            )));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_DOWNLOAD_BYTES + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|e| FetchError::Failed(format!("cannot read {}: {e}", tgz_path.display())))?;
        bytes
    };
    if bytes.len() as u64 > MAX_DOWNLOAD_BYTES {
        return Err(FetchError::Failed(format!(
            "{}: artifact exceeds the {MAX_DOWNLOAD_BYTES}-byte cap",
            tgz_path.display()
        )));
    }
    let actual = hex::encode(Sha256::digest(&bytes));
    if !actual.eq_ignore_ascii_case(expected_sha256_hex) {
        return Err(FetchError::Failed(format!(
            "{}: sha256 mismatch against the vendor ledger (recorded {expected_sha256_hex}, \
             on-disk bytes hash to {actual})",
            tgz_path.display()
        )));
    }
    let tmp = tempfile::tempdir()
        .map_err(|e| FetchError::Failed(format!("cannot create staging tempdir: {e}")))?;
    let dir = tmp.path().join("package");
    validate_tgz(&bytes, None).map_err(FetchError::Failed)?;
    Ok(FetchedPackage::pending(
        dir,
        format!("file:{}", tgz_path.display()),
        tmp,
        move |dest, skip| extract_tgz_skipping(&bytes, dest, skip),
    ))
}

/// Capped download. http(s) only; the cap is enforced on the declared
/// Content-Length AND the actual stream (a lying server cannot blow past
/// it).
async fn download(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(format!("refusing non-http(s) artifact URL `{url}`"));
    }
    let mut resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("GET {url}: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("GET {url}: HTTP {status}"));
    }
    if let Some(len) = resp.content_length() {
        if len > MAX_DOWNLOAD_BYTES {
            return Err(format!(
                "{url}: artifact is {len} bytes (cap {MAX_DOWNLOAD_BYTES})"
            ));
        }
    }
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("reading {url}: {e}"))?
    {
        if bytes.len() as u64 + chunk.len() as u64 > MAX_DOWNLOAD_BYTES {
            return Err(format!(
                "{url}: artifact exceeds the {MAX_DOWNLOAD_BYTES}-byte cap"
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// Verify downloaded bytes against the lock-recorded verifier. Runs BEFORE
/// any disk write. Berry cache-zip checksums and go.sum dirhashes have
/// dedicated verifiers in their ecosystems' fetchers.
/// Fetch + stage an npm package from its conventional registry URL WITHOUT
/// content verification. The download/extract caps still apply.
///
/// SECURITY: callers MUST end-to-end verify whatever they derive from the
/// staged copy against an independent trust anchor before committing it —
/// repair's ledger reconstruction verifies the deterministically REBUILT
/// vendored tarball against the integrity the rewired lockfile records
/// (`artifact_matches_integrity`); a tampered pristine source then changes
/// the rebuilt bytes and fails closed.
pub async fn fetch_npm_unverified(
    name: &str,
    version: &str,
    client: &reqwest::Client,
) -> Result<FetchedPackage, FetchError> {
    let entry = LockfileEntry {
        ecosystem: "npm",
        source_kind: SourceKind::Unspecified,
        name: name.to_string(),
        version: version.to_string(),
        purl: format!("pkg:npm/{name}@{version}"),
        resolved: None,
        integrity: LockIntegrity::None,
    };
    fetch_npm_inner(&entry, client, false).await
}

/// Whole-artifact verification against a lock-recorded integrity (the same
/// verifiers the fetch path uses, including the berry cache-zip rebuild).
/// `name` feeds the berry cache-zip recipe; ignored otherwise.
pub fn artifact_matches_integrity(
    bytes: &[u8],
    name: &str,
    integrity: &LockIntegrity,
) -> Result<(), String> {
    match integrity {
        LockIntegrity::BerryChecksum(expected) => {
            if !expected.starts_with("10c0/") {
                return Err(format!(
                    "yarn berry checksum `{expected}` uses a cacheKey other than 10c0"
                ));
            }
            let actual = super::berry_zip::berry_cache_checksum_10c0(bytes, name)?;
            if &actual == expected {
                Ok(())
            } else {
                Err(format!(
                    "yarn berry cache checksum mismatch: lockfile records {expected}, the \
                     artifact rebuilds to {actual}"
                ))
            }
        }
        other => verify_integrity(bytes, other).map_err(|e| match e {
            FetchError::Failed(d) | FetchError::Unverifiable(d) => d,
        }),
    }
}

fn verify_integrity(bytes: &[u8], integrity: &LockIntegrity) -> Result<(), FetchError> {
    match integrity {
        LockIntegrity::Sri(sri) => verify_sri(bytes, sri).map_err(FetchError::Failed),
        LockIntegrity::Sha1Hex(expect) => {
            let actual = hex::encode(Sha1::digest(bytes));
            if &actual == expect {
                Ok(())
            } else {
                Err(FetchError::Failed(format!(
                    "sha1 mismatch: lockfile records {expect}, downloaded bytes hash to {actual}"
                )))
            }
        }
        LockIntegrity::Sha256Hex(expect) => {
            let actual = hex::encode(Sha256::digest(bytes));
            if actual.eq_ignore_ascii_case(expect) {
                Ok(())
            } else {
                Err(FetchError::Failed(format!(
                    "sha256 mismatch: lockfile records {expect}, downloaded bytes hash to {actual}"
                )))
            }
        }
        LockIntegrity::Sha256AnyOf(expected) => {
            let actual = hex::encode(Sha256::digest(bytes));
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
/// legacy package unvendorable whenever the prebuilt-artifact service misses
/// (the 2026-07 strapi clean-run regression). The bare-hex twin of this trust
/// decision already lives in the `LockIntegrity::Sha1Hex` arm above.
fn verify_sri(bytes: &[u8], sri: &str) -> Result<(), String> {
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

/// Whether every FILE entry in the zip nests under one shared top-level
/// directory — the GitHub/GitLab-zipball layout. This is the per-archive
/// `strip_first` decision Composer itself makes (ArchiveDownloader promotes
/// a lone top dir, else installs from the extract root): `composer archive`-
/// built dists (Satis archive builds, Artifactory/Nexus, private Packagist)
/// store composer.json at the archive ROOT, where an unconditional strip
/// would drop it and refuse a genuine, integrity-verified artifact.
fn zip_has_single_top_dir(bytes: &[u8]) -> Result<bool, String> {
    let archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| format!("unreadable zip: {e}"))?;
    let mut top: Option<&str> = None;
    for name in archive.file_names() {
        if name.ends_with('/') {
            continue; // dir entries: extraction skips them too
        }
        let Some((first, _)) = name.split_once('/') else {
            return Ok(false); // a root-level file — flat layout
        };
        if top.is_some_and(|t| t != first) {
            return Ok(false);
        }
        top = Some(first);
    }
    Ok(top.is_some())
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
    )
    .map(|_| ())
}

/// [`extract_tgz`]'s write-free twin: every refusal, nothing created.
/// Reports whether `watch` would land at the root (see [`lands_at_root`]).
pub(crate) fn validate_tgz(bytes: &[u8], watch: Option<&str>) -> Result<bool, String> {
    walk_tar_gz(
        bytes,
        Path::new(""),
        /*strip_first=*/ true,
        Sink::Validate,
        watch,
        None,
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
pub(crate) fn validate_gem_data(gem_bytes: &[u8]) -> Result<(), String> {
    walk_gem_data(gem_bytes, Path::new(""), Sink::Validate, None)
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
) -> Result<bool, String> {
    use std::io::Read as _;
    let gz = flate2::read::GzDecoder::new(bytes).take(MAX_TOTAL_DECOMPRESSED_BYTES);
    let mut archive = tar::Archive::new(gz);
    let mut out = EntrySink::new(dest, sink).skipping(skip_file_name);
    let mut seen_watched = false;
    let mut count = 0usize;
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
        if !entry.header().entry_type().is_file() {
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
    use super::*;
    use wiremock::matchers::{method, path as url_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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

    fn npm_entry(resolved: Option<String>, integrity: LockIntegrity) -> LockfileEntry {
        LockfileEntry {
            ecosystem: "npm",
            source_kind: SourceKind::Unspecified,
            name: "left-pad".into(),
            version: "1.3.0".into(),
            purl: "pkg:npm/left-pad@1.3.0".into(),
            resolved,
            integrity,
        }
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
        // npm-era lockfile entries carry ONLY `sha1-…` (the strapi clean-run
        // regression: `no usable hash in SRI`); it must verify…
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

    #[tokio::test]
    async fn fetch_verifies_sri_and_extracts_with_modes() {
        let tgz = make_tgz(&[
            ("package/package.json", br#"{"name":"left-pad"}"#, false),
            ("package/bin/cli.js", b"#!/usr/bin/env node\n", true),
            ("package/index.js", b"module.exports = 1;\n", false),
        ]);
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(url_path("/left-pad/-/left-pad-1.3.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tgz.clone()))
            .mount(&mock)
            .await;

        let entry = npm_entry(
            Some(format!("{}/left-pad/-/left-pad-1.3.0.tgz", mock.uri())),
            LockIntegrity::Sri(sri_of(&tgz)),
        );
        let fetched = fetch_and_stage(&entry, &build_registry_client())
            .await
            .unwrap();
        assert!(fetched.dir().await.unwrap().join("package.json").is_file());
        assert_eq!(
            std::fs::read(fetched.dir().await.unwrap().join("index.js")).unwrap(),
            b"module.exports = 1;\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(fetched.dir().await.unwrap().join("bin/cli.js"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o111, 0o111, "exec bit preserved");
        }
        // The tempdir dies with the holder.
        let dir = fetched.dir().await.unwrap().to_path_buf();
        drop(fetched);
        assert!(!dir.exists());
    }

    #[tokio::test]
    async fn integrity_mismatch_fails_before_extraction() {
        let tgz = make_tgz(&[("package/package.json", b"{}", false)]);
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(url_path("/left-pad/-/left-pad-1.3.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tgz))
            .mount(&mock)
            .await;

        let entry = npm_entry(
            Some(format!("{}/left-pad/-/left-pad-1.3.0.tgz", mock.uri())),
            LockIntegrity::Sri(sri_of(b"the lock expects different bytes")),
        );
        match fetch_and_stage(&entry, &build_registry_client()).await {
            Err(FetchError::Failed(msg)) => {
                assert!(msg.contains("mismatch"), "{msg}")
            }
            other => panic!("expected integrity failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unverifiable_entry_refuses_without_network() {
        // A URL that would hard-fail if contacted — Unverifiable proves the
        // decision happened before any I/O.
        let entry = npm_entry(
            Some("http://127.0.0.1:1/nope.tgz".into()),
            LockIntegrity::None,
        );
        match fetch_and_stage(&entry, &build_registry_client()).await {
            Err(FetchError::Unverifiable(msg)) => {
                assert!(msg.contains("no integrity"), "{msg}")
            }
            other => panic!("expected Unverifiable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn http_error_and_scheme_guard_fail_closed() {
        let mock = MockServer::start().await;
        // No mounted route → 404.
        let entry = npm_entry(
            Some(format!("{}/missing.tgz", mock.uri())),
            LockIntegrity::Sri(sri_of(b"x")),
        );
        match fetch_and_stage(&entry, &build_registry_client()).await {
            Err(FetchError::Failed(msg)) => assert!(msg.contains("404"), "{msg}"),
            other => panic!("expected HTTP failure, got {other:?}"),
        }

        let entry = npm_entry(
            Some("ftp://example.com/x.tgz".into()),
            LockIntegrity::Sri(sri_of(b"x")),
        );
        match fetch_and_stage(&entry, &build_registry_client()).await {
            Err(FetchError::Failed(msg)) => assert!(msg.contains("non-http"), "{msg}"),
            other => panic!("expected scheme refusal, got {other:?}"),
        }
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

    #[tokio::test]
    async fn berry_checksum_verifies_via_cache_zip_rebuild() {
        let tgz = make_tgz(&[
            ("package/package.json", br#"{"name":"left-pad"}"#, false),
            ("package/index.js", b"module.exports = 1;\n", false),
        ]);
        let expected =
            super::super::berry_zip::berry_cache_checksum_10c0(&tgz, "left-pad").unwrap();
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(url_path("/left-pad/-/left-pad-1.3.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tgz))
            .mount(&mock)
            .await;

        let entry = npm_entry(
            Some(format!("{}/left-pad/-/left-pad-1.3.0.tgz", mock.uri())),
            LockIntegrity::BerryChecksum(expected),
        );
        let fetched = fetch_and_stage(&entry, &build_registry_client())
            .await
            .unwrap();
        assert!(fetched.dir().await.unwrap().join("package.json").is_file());

        // Tampered checksum → Failed; foreign cacheKey → Unverifiable.
        let entry = npm_entry(
            Some(format!("{}/left-pad/-/left-pad-1.3.0.tgz", mock.uri())),
            LockIntegrity::BerryChecksum(format!("10c0/{}", "0".repeat(128))),
        );
        match fetch_and_stage(&entry, &build_registry_client()).await {
            Err(FetchError::Failed(msg)) => assert!(msg.contains("mismatch"), "{msg}"),
            other => panic!("expected mismatch, got {other:?}"),
        }
        let entry = npm_entry(
            Some(format!("{}/left-pad/-/left-pad-1.3.0.tgz", mock.uri())),
            LockIntegrity::BerryChecksum(format!("9/{}", "0".repeat(128))),
        );
        match fetch_and_stage(&entry, &build_registry_client()).await {
            Err(FetchError::Unverifiable(msg)) => assert!(msg.contains("cacheKey"), "{msg}"),
            other => panic!("expected Unverifiable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stage_local_artifact_verifies_ledger_sha256() {
        let tgz = make_tgz(&[("package/package.json", b"{}", false)]);
        let tmp = tempfile::tempdir().unwrap();
        let tgz_path = tmp.path().join("left-pad-1.3.0.tgz");
        std::fs::write(&tgz_path, &tgz).unwrap();
        let sha = hex::encode(Sha256::digest(&tgz));

        let staged = stage_local_artifact(&tgz_path, &sha).await.unwrap();
        assert!(staged.dir().await.unwrap().join("package.json").is_file());

        match stage_local_artifact(&tgz_path, &"0".repeat(64)).await {
            Err(FetchError::Failed(msg)) => assert!(msg.contains("mismatch"), "{msg}"),
            other => panic!("expected ledger mismatch, got {other:?}"),
        }
        match stage_local_artifact(&tgz_path, "").await {
            Err(FetchError::Unverifiable(_)) => {}
            other => panic!("expected Unverifiable for empty hash, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn cargo_crate_fetch_verifies_sha256_and_extracts() {
        // .crate = tar.gz with a {name}-{version}/ top dir.
        let crate_bytes = make_tgz(&[
            (
                "left-pad-1.3.0/Cargo.toml",
                b"[package]\nname = \"left-pad\"\n",
                false,
            ),
            ("left-pad-1.3.0/src/lib.rs", b"pub fn pad() {}\n", false),
        ]);
        let sha = hex::encode(Sha256::digest(&crate_bytes));
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(url_path("/left-pad/left-pad-1.3.0.crate"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(crate_bytes))
            .mount(&mock)
            .await;

        let entry = LockfileEntry {
            ecosystem: "cargo",
            source_kind: SourceKind::Unspecified,
            name: "left-pad".into(),
            version: "1.3.0".into(),
            purl: "pkg:cargo/left-pad@1.3.0".into(),
            resolved: Some(format!("{}/left-pad/left-pad-1.3.0.crate", mock.uri())),
            integrity: LockIntegrity::Sha256Hex(sha),
        };
        let fetched = fetch_and_stage(&entry, &build_registry_client())
            .await
            .unwrap();
        assert!(fetched.dir().await.unwrap().join("Cargo.toml").is_file());
        assert!(fetched.dir().await.unwrap().join("src/lib.rs").is_file());

        // Tampered checksum fails closed.
        let entry = LockfileEntry {
            integrity: LockIntegrity::Sha256Hex("0".repeat(64)),
            ..entry
        };
        match fetch_and_stage(&entry, &build_registry_client()).await {
            Err(FetchError::Failed(msg)) => assert!(msg.contains("mismatch"), "{msg}"),
            other => panic!("expected mismatch, got {other:?}"),
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

    #[tokio::test]
    async fn golang_module_fetch_verifies_h1_dirhash_and_extracts() {
        // Out-of-order files prove the sort; nested module path proves the
        // explicit-prefix strip (a first-component strip would be wrong).
        let prefix = "github.com/x/y@v1.0.0/";
        let files: [(&str, &[u8]); 3] = [
            ("go.mod", b"module github.com/x/y\n"),
            ("a/b.go", b"package a\n"),
            ("README.md", b"# y\n"),
        ];
        let zip_bytes = make_module_zip(prefix, &files);
        let expected = spec_h1(&files, prefix);
        assert_eq!(
            go_h1_of_zip(&zip_bytes).unwrap(),
            expected,
            "production dirhash matches the spec mirror"
        );

        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(url_path("/github.com/x/y/@v/v1.0.0.zip"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_bytes))
            .mount(&mock)
            .await;

        let entry = LockfileEntry {
            ecosystem: "golang",
            source_kind: SourceKind::Unspecified,
            name: "github.com/x/y".into(),
            version: "v1.0.0".into(),
            purl: "pkg:golang/github.com/x/y@v1.0.0".into(),
            resolved: Some(format!("{}/github.com/x/y/@v/v1.0.0.zip", mock.uri())),
            integrity: LockIntegrity::GoH1(expected),
        };
        let fetched = fetch_and_stage(&entry, &build_registry_client())
            .await
            .unwrap();
        assert!(fetched.dir().await.unwrap().join("go.mod").is_file());
        assert!(fetched.dir().await.unwrap().join("a/b.go").is_file());

        // Tampered h1 fails closed.
        let entry = LockfileEntry {
            integrity: LockIntegrity::GoH1(
                "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            ),
            ..entry
        };
        match fetch_and_stage(&entry, &build_registry_client()).await {
            Err(FetchError::Failed(msg)) => assert!(msg.contains("mismatch"), "{msg}"),
            other => panic!("expected mismatch, got {other:?}"),
        }
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

    #[tokio::test]
    async fn composer_dist_fetch_verifies_sha1_and_strips_top_dir() {
        // GitHub zipballs carry an `owner-repo-sha/` top dir.
        let zip_bytes = make_zip(&[
            (
                "Seldaek-monolog-abc123/composer.json",
                br#"{"name":"monolog/monolog"}"#,
            ),
            ("Seldaek-monolog-abc123/src/Logger.php", b"<?php\n"),
        ]);
        let sha1 = hex::encode(Sha1::digest(&zip_bytes));
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(url_path("/zipball/abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_bytes))
            .mount(&mock)
            .await;

        let entry = LockfileEntry {
            ecosystem: "composer",
            source_kind: SourceKind::Unspecified,
            name: "monolog/monolog".into(),
            version: "3.5.0".into(),
            purl: "pkg:composer/monolog/monolog@3.5.0".into(),
            resolved: Some(format!("{}/zipball/abc123", mock.uri())),
            integrity: LockIntegrity::Sha1Hex(sha1),
        };
        let fetched = fetch_and_stage(&entry, &build_registry_client())
            .await
            .unwrap();
        assert!(fetched.dir().await.unwrap().join("composer.json").is_file());
        assert!(fetched
            .dir()
            .await
            .unwrap()
            .join("src/Logger.php")
            .is_file());

        let entry = LockfileEntry {
            integrity: LockIntegrity::Sha1Hex("0".repeat(40)),
            ..entry
        };
        match fetch_and_stage(&entry, &build_registry_client()).await {
            Err(FetchError::Failed(msg)) => assert!(msg.contains("mismatch"), "{msg}"),
            other => panic!("expected mismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn composer_flat_dist_fetch_keeps_root_layout() {
        // `composer archive`-built dists (Satis archive builds, Artifactory/
        // Nexus, private Packagist) store composer.json at the archive ROOT —
        // no zipball top dir. Composer itself auto-detects the layout per
        // archive (ArchiveDownloader promotes a lone top dir, else installs
        // from the extract root); an unconditional first-component strip
        // drops the root composer.json and refuses a genuine, sha1-verified
        // artifact as "carries no composer.json".
        let zip_bytes = make_zip(&[
            ("composer.json", br#"{"name":"acme/flat"}"#),
            ("src/Flat.php", b"<?php\n"),
        ]);
        let sha1 = hex::encode(Sha1::digest(&zip_bytes));
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(url_path("/dists/acme-flat-1.0.0.zip"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_bytes))
            .mount(&mock)
            .await;

        let entry = LockfileEntry {
            ecosystem: "composer",
            source_kind: SourceKind::Unspecified,
            name: "acme/flat".into(),
            version: "1.0.0".into(),
            purl: "pkg:composer/acme/flat@1.0.0".into(),
            resolved: Some(format!("{}/dists/acme-flat-1.0.0.zip", mock.uri())),
            integrity: LockIntegrity::Sha1Hex(sha1),
        };
        let fetched = fetch_and_stage(&entry, &build_registry_client())
            .await
            .expect("a flat-layout dist is a genuine, integrity-verified artifact");
        assert!(fetched.dir().await.unwrap().join("composer.json").is_file());
        assert!(
            fetched.dir().await.unwrap().join("src/Flat.php").is_file(),
            "flat-layout paths must extract verbatim, not lose their first segment"
        );
    }

    #[test]
    fn zip_single_top_dir_detection() {
        // Zipball layout: everything nests under one top dir → strip.
        let zipball = make_zip(&[
            ("Seldaek-monolog-abc123/composer.json", b"{}".as_slice()),
            ("Seldaek-monolog-abc123/src/Logger.php", b"<?php\n"),
        ]);
        assert!(zip_has_single_top_dir(&zipball).unwrap());
        // Flat layout: a root-level file → extract as-is.
        let flat = make_zip(&[
            ("composer.json", b"{}".as_slice()),
            ("src/A.php", b"<?php\n"),
        ]);
        assert!(!zip_has_single_top_dir(&flat).unwrap());
        // Two top dirs with no root file: still not a lone-top-dir archive.
        let two = make_zip(&[("a/x.php", b"1".as_slice()), ("b/y.php", b"2".as_slice())]);
        assert!(!zip_has_single_top_dir(&two).unwrap());
        // No file entries at all: nothing to promote.
        assert!(!zip_has_single_top_dir(&make_zip(&[])).unwrap());
    }

    #[tokio::test]
    async fn gem_fetch_verifies_sha256_and_extracts_data_tar() {
        // .gem = plain tar holding data.tar.gz (content at the ROOT — no
        // prefix dir) + metadata.gz.
        let data_tgz = make_tgz(&[
            ("lib/rails.rb", b"module Rails; end\n", false),
            ("README.md", b"# rails\n", false),
        ]);
        let mut outer = tar::Builder::new(Vec::new());
        for (name, bytes) in [
            ("metadata.gz", b"meta".as_slice()),
            ("data.tar.gz", &data_tgz),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            outer.append_data(&mut header, name, bytes).unwrap();
        }
        let gem_bytes = outer.into_inner().unwrap();
        let sha = hex::encode(Sha256::digest(&gem_bytes));

        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(url_path("/downloads/rails-7.1.0.gem"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(gem_bytes))
            .mount(&mock)
            .await;

        let entry = LockfileEntry {
            ecosystem: "gem",
            source_kind: SourceKind::Unspecified,
            name: "rails".into(),
            version: "7.1.0".into(),
            purl: "pkg:gem/rails@7.1.0".into(),
            resolved: Some(format!("{}/downloads/rails-7.1.0.gem", mock.uri())),
            integrity: LockIntegrity::Sha256Hex(sha),
        };
        let fetched = fetch_and_stage(&entry, &build_registry_client())
            .await
            .unwrap();
        assert!(
            fetched.dir().await.unwrap().join("lib/rails.rb").is_file(),
            "data.tar.gz content extracts at the root (no strip)"
        );
        assert!(fetched.dir().await.unwrap().join("README.md").is_file());
        // The staged leaf must be the canonical `{name}-{version}`:
        // vendor_gem's platform-suffix guard refuses any other leaf
        // (`platform_gem_unsupported`), which killed lockfile auto-fetch
        // when this dir was named `gem`.
        assert_eq!(
            fetched
                .dir()
                .await
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy(),
            "rails-7.1.0",
            "staged dir leaf must satisfy vendor_gem's `{{name}}-{{version}}` check"
        );
    }

    #[tokio::test]
    async fn gem_fetch_refuses_unsafe_coordinates_without_network() {
        // The coordinates become the staged-dir leaf, so a separator-bearing
        // name must refuse — and BEFORE any I/O (the URL would hard-fail if
        // contacted).
        let entry = LockfileEntry {
            ecosystem: "gem",
            source_kind: SourceKind::Unspecified,
            name: "ra/ils".into(),
            version: "7.1.0".into(),
            purl: "pkg:gem/ra/ils@7.1.0".into(),
            resolved: Some("http://127.0.0.1:1/nope.gem".into()),
            integrity: LockIntegrity::Sha256Hex("0".repeat(64)),
        };
        match fetch_and_stage(&entry, &build_registry_client()).await {
            Err(FetchError::Failed(msg)) => {
                assert!(msg.contains("unsafe gem coordinates"), "{msg}")
            }
            other => panic!("expected coordinate refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn pypi_wheel_fetch_extracts_site_packages_layout() {
        let wheel = make_zip(&[
            ("requests/__init__.py", b"__version__ = '2.28.0'\n"),
            (
                "requests-2.28.0.dist-info/RECORD",
                b"requests/__init__.py,sha256=abc,24\n",
            ),
            ("requests-2.28.0.dist-info/WHEEL", b"Wheel-Version: 1.0\n"),
        ]);
        let sha = hex::encode(Sha256::digest(&wheel));
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(url_path("/packages/requests-2.28.0-py3-none-any.whl"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(wheel))
            .mount(&mock)
            .await;

        let entry = LockfileEntry {
            ecosystem: "pypi",
            source_kind: SourceKind::Unspecified,
            name: "requests".into(),
            version: "2.28.0".into(),
            purl: "pkg:pypi/requests@2.28.0".into(),
            resolved: Some(format!(
                "{}/packages/requests-2.28.0-py3-none-any.whl",
                mock.uri()
            )),
            integrity: LockIntegrity::Sha256Hex(sha),
        };
        let fetched = fetch_and_stage(&entry, &build_registry_client())
            .await
            .unwrap();
        // Wheel content at the root: a site-packages-shaped dir with the
        // dist-info RECORD the pypi vendor backend stages from.
        assert!(fetched
            .dir()
            .await
            .unwrap()
            .join("requests/__init__.py")
            .is_file());
        assert!(fetched
            .dir()
            .await
            .unwrap()
            .join("requests-2.28.0.dist-info/RECORD")
            .is_file());
    }

    /// poetry.lock records wheel hashes but no URLs: the fetcher resolves the
    /// file through PyPI's JSON API by sha256 and still verifies the bytes.
    #[tokio::test]
    #[serial_test::serial]
    async fn pypi_hash_only_entry_is_resolved_through_the_json_api() {
        let wheel = make_zip(&[
            ("requests/__init__.py", b"__version__ = '2.28.0'\n"),
            (
                "requests-2.28.0.dist-info/RECORD",
                b"requests/__init__.py,sha256=abc,24\n",
            ),
        ]);
        let sha = hex::encode(Sha256::digest(&wheel));
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(url_path("/packages/requests-2.28.0-py3-none-any.whl"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(wheel))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(url_path("/pypi/requests/2.28.0/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "urls": [
                    {"filename": "requests-2.28.0.tar.gz", "url": format!("{}/packages/requests-2.28.0.tar.gz", mock.uri()), "digests": {"sha256": "0".repeat(64)}},
                    {"filename": "requests-2.28.0-py3-none-any.whl", "url": format!("{}/packages/requests-2.28.0-py3-none-any.whl", mock.uri()), "digests": {"sha256": sha.to_uppercase()}},
                ]
            })))
            .mount(&mock)
            .await;
        let saved = std::env::var("SOCKET_PYPI_JSON_API").ok();
        std::env::set_var("SOCKET_PYPI_JSON_API", format!("{}/pypi/", mock.uri()));
        let restore = || match &saved {
            Some(v) => std::env::set_var("SOCKET_PYPI_JSON_API", v),
            None => std::env::remove_var("SOCKET_PYPI_JSON_API"),
        };
        let entry = LockfileEntry {
            ecosystem: "pypi",
            source_kind: SourceKind::Unspecified,
            name: "requests".into(),
            version: "2.28.0".into(),
            purl: "pkg:pypi/requests@2.28.0".into(),
            resolved: None,
            integrity: LockIntegrity::Sha256Hex(sha.clone()),
        };
        let fetched = fetch_and_stage(&entry, &build_registry_client()).await;
        // A hash no release file carries is refused before any download.
        let unknown = LockfileEntry {
            integrity: LockIntegrity::Sha256Hex("1".repeat(64)),
            ..entry.clone()
        };
        let missing = fetch_and_stage(&unknown, &build_registry_client()).await;
        // No hash at all: nothing to resolve by.
        let bare = LockfileEntry {
            integrity: LockIntegrity::Sri("sha512-x".into()),
            ..entry
        };
        let bare_result = fetch_and_stage(&bare, &build_registry_client()).await;
        restore();
        let fetched = fetched.unwrap();
        assert!(fetched
            .dir()
            .await
            .unwrap()
            .join("requests/__init__.py")
            .is_file());
        assert!(fetched.url.ends_with("requests-2.28.0-py3-none-any.whl"));
        match missing {
            Err(FetchError::Unverifiable(msg)) => assert!(msg.contains("matches"), "{msg}"),
            other => panic!("expected Unverifiable, got {other:?}"),
        }
        match bare_result {
            Err(FetchError::Unverifiable(msg)) => assert!(msg.contains("sha256"), "{msg}"),
            other => panic!("expected Unverifiable, got {other:?}"),
        }
    }

    /// Pipfile.lock records EVERY release file's digest without filenames:
    /// the fetcher must pick the pure-Python wheel by digest (never the sdist
    /// or a platform wheel that also matches), verify the download against
    /// the set, and refuse when no pure wheel's digest is recorded.
    #[tokio::test]
    #[serial_test::serial]
    async fn pypi_digest_set_entry_picks_the_pure_wheel_by_hash() {
        let wheel = make_zip(&[
            ("requests/__init__.py", b"__version__ = '2.28.0'\n"),
            (
                "requests-2.28.0.dist-info/RECORD",
                b"requests/__init__.py,sha256=abc,24\n",
            ),
        ]);
        let wheel_sha = hex::encode(Sha256::digest(&wheel));
        let sdist_sha = "0".repeat(64);
        let platform_sha = "9".repeat(64);
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(url_path("/packages/requests-2.28.0-py3-none-any.whl"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(wheel))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(url_path("/packages/requests-2.28.0.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"sdist bytes".to_vec()))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(url_path("/pypi/requests/2.28.0/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "urls": [
                    {"filename": "requests-2.28.0.tar.gz", "url": format!("{}/packages/requests-2.28.0.tar.gz", mock.uri()), "digests": {"sha256": sdist_sha}},
                    {"filename": "requests-2.28.0-cp312-cp312-manylinux_2_17_x86_64.whl", "url": format!("{}/packages/requests-2.28.0-cp312-cp312-manylinux_2_17_x86_64.whl", mock.uri()), "digests": {"sha256": platform_sha}},
                    {"filename": "requests-2.28.0-py3-none-any.whl", "url": format!("{}/packages/requests-2.28.0-py3-none-any.whl", mock.uri()), "digests": {"sha256": wheel_sha.to_uppercase()}},
                ]
            })))
            .mount(&mock)
            .await;
        let saved = std::env::var("SOCKET_PYPI_JSON_API").ok();
        std::env::set_var("SOCKET_PYPI_JSON_API", format!("{}/pypi/", mock.uri()));
        let restore = || match &saved {
            Some(v) => std::env::set_var("SOCKET_PYPI_JSON_API", v),
            None => std::env::remove_var("SOCKET_PYPI_JSON_API"),
        };
        let entry = LockfileEntry {
            ecosystem: "pypi",
            source_kind: SourceKind::Unspecified,
            name: "requests".into(),
            version: "2.28.0".into(),
            purl: "pkg:pypi/requests@2.28.0".into(),
            resolved: None,
            // sdist first, like Pipenv writes them: the ORDER must not pick
            // the sdist.
            integrity: LockIntegrity::Sha256AnyOf(vec![
                sdist_sha.clone(),
                platform_sha.clone(),
                wheel_sha.clone(),
            ]),
        };
        let fetched = fetch_and_stage(&entry, &build_registry_client()).await;
        // Only the sdist's and a platform wheel's digests recorded: no pure
        // wheel to choose → refused before any download.
        let no_pure = LockfileEntry {
            integrity: LockIntegrity::Sha256AnyOf(vec![sdist_sha.clone(), platform_sha.clone()]),
            ..entry.clone()
        };
        let no_pure_result = fetch_and_stage(&no_pure, &build_registry_client()).await;
        // Digests no release file carries → refused.
        let unknown = LockfileEntry {
            integrity: LockIntegrity::Sha256AnyOf(vec!["1".repeat(64), "2".repeat(64)]),
            ..entry.clone()
        };
        let unknown_result = fetch_and_stage(&unknown, &build_registry_client()).await;
        restore();
        let fetched = fetched.unwrap();
        assert!(fetched
            .dir()
            .await
            .unwrap()
            .join("requests/__init__.py")
            .is_file());
        assert!(
            fetched.url.ends_with("requests-2.28.0-py3-none-any.whl"),
            "{}",
            fetched.url
        );
        for (label, result) in [
            ("no pure wheel", no_pure_result),
            ("unknown", unknown_result),
        ] {
            match result {
                Err(FetchError::Unverifiable(msg)) => {
                    assert!(
                        msg.contains("none-any.whl") && msg.contains("digests"),
                        "{label}: {msg}"
                    )
                }
                other => panic!("{label}: expected Unverifiable, got {other:?}"),
            }
        }
        // The verifier itself: bytes matching ANY recorded digest pass, others fail.
        let set = LockIntegrity::Sha256AnyOf(vec![sdist_sha.clone(), wheel_sha.clone()]);
        // "sdist bytes" is not the recorded sdist digest ("000…"), so it must fail.
        assert!(verify_integrity(b"sdist bytes", &set).is_err());
        let real_sdist = LockIntegrity::Sha256AnyOf(vec![
            hex::encode(Sha256::digest(b"sdist bytes")),
            wheel_sha,
        ]);
        assert!(verify_integrity(b"sdist bytes", &real_sdist).is_ok());
        match verify_integrity(b"other", &real_sdist) {
            Err(FetchError::Failed(msg)) => assert!(msg.contains("none of the 2 digests"), "{msg}"),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c_path =
            std::ffi::CString::new(path.as_os_str().as_bytes()).expect("fifo path has no NUL");
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
        assert_eq!(
            rc,
            0,
            "mkfifo(2) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    /// A FIFO squatting at the committed artifact path must fail fast
    /// instead of wedging the fresh-clone re-vendor forever in an `open(2)`
    /// waiting for a writer — the caller's metadata probe passes for a FIFO,
    /// so this read is the first open. Same `open_regular_file` guard class
    /// as the vendor lockfile reads (lock_inventory.rs, npm_lock.rs).
    #[cfg(unix)]
    #[test]
    fn stage_local_artifact_fifo_fails_fast_instead_of_wedging() {
        let tmp = tempfile::tempdir().unwrap();
        let tgz_path = tmp.path().join("left-pad-1.3.0.tgz");
        mkfifo(&tgz_path);
        // Own runtime on a detached thread: a wedged open(2) lives in a
        // spawn_blocking task, and dropping (or #[tokio::test]-finishing) a
        // runtime with one wedged blocks forever — the timeout must live
        // OUTSIDE the runtime for the unfixed code to fail instead of hang.
        let (tx, rx) = std::sync::mpsc::channel();
        let path = tgz_path.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let res = rt.block_on(stage_local_artifact(&path, &"0".repeat(64)));
            std::mem::forget(rt);
            let _ = tx.send(res);
        });
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(Err(FetchError::Failed(msg))) => {
                assert!(msg.contains(&tgz_path.display().to_string()), "{msg}")
            }
            Ok(other) => panic!("expected Failed on a FIFO artifact, got {other:?}"),
            Err(_) => panic!("stage_local_artifact wedged on a FIFO artifact"),
        }
    }

    /// The 128 MB artifact cap must fire BEFORE the size-matched allocation
    /// and read: a huge file at the ledger-recorded artifact path (a sparse
    /// `truncate -s 64G` costs the attacker nothing) must get the clean
    /// FetchError cap message, not a metadata-sized `Vec::with_capacity`
    /// that aborts or OOMs — the module's documented memory-bomb bound.
    ///
    /// Runs in a CHILD PROCESS (the fs.rs RLIMIT_FSIZE precedent): peak RSS
    /// is process-wide and monotonic, so sibling tests in this binary (the
    /// 128 MB go_h1 bomb-cap test among them) would poison an in-process
    /// measurement.
    #[cfg(unix)]
    #[tokio::test]
    async fn stage_local_artifact_caps_oversized_artifact_before_buffering() {
        const CHILD_ENV: &str = "SOCKET_PATCH_CORE_TEST_STAGE_CAP_CHILD";
        const TEST_NAME: &str = "vendor::registry_fetch::tests::\
                                 stage_local_artifact_caps_oversized_artifact_before_buffering";
        if std::env::var_os(CHILD_ENV).is_none() {
            let exe = std::env::current_exe().expect("test binary path must resolve");
            let output = std::process::Command::new(exe)
                .args([TEST_NAME, "--exact", "--test-threads=1", "--nocapture"])
                .env(CHILD_ENV, "1")
                .output()
                .expect("the measured child test process must spawn");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success(),
                "the measured child run failed:\nstdout:\n{stdout}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stderr),
            );
            // Anti-vacuity: a renamed test would make the `--exact` filter
            // match nothing and the child exit 0 having proven nothing.
            assert!(
                stdout.contains("1 passed"),
                "the child run must execute exactly this test — filter drift \
                 after a rename? child stdout:\n{stdout}"
            );
            return;
        }

        // 1 GiB sparse: zero disk blocks, but 8× the cap — buffering it
        // before the cap check dirties ~1 GiB of RSS.
        const HUGE: u64 = 1024 * 1024 * 1024;
        let tmp = tempfile::tempdir().unwrap();
        let tgz_path = tmp.path().join("huge.tgz");
        std::fs::File::create(&tgz_path)
            .unwrap()
            .set_len(HUGE)
            .unwrap();

        match stage_local_artifact(&tgz_path, &"0".repeat(64)).await {
            Err(FetchError::Failed(msg)) => assert!(msg.contains("cap"), "{msg}"),
            other => panic!("expected the cap refusal, got {other:?}"),
        }

        let mut ru = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        assert_eq!(
            unsafe { libc::getrusage(libc::RUSAGE_SELF, ru.as_mut_ptr()) },
            0
        );
        let ru = unsafe { ru.assume_init() };
        // macOS reports ru_maxrss in bytes, Linux in kilobytes.
        let peak = if cfg!(target_os = "macos") {
            ru.ru_maxrss as u64
        } else {
            (ru.ru_maxrss as u64) * 1024
        };
        assert!(
            peak < HUGE / 2,
            "peak RSS {peak} bytes — the oversized artifact was buffered into \
             memory before the cap check"
        );
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

    #[tokio::test]
    async fn berry_foreign_cachekey_refuses_before_network() {
        // The cacheKey is decidable from the lockfile alone; the refusal must
        // be the Unverifiable contract's pre-network kind (the URL would
        // hard-fail if contacted), not a Failed download error — and yarn
        // 2/3 locks (cacheKey 8/9) must not cost a full tarball download
        // just to be refused afterwards.
        let entry = npm_entry(
            Some("http://127.0.0.1:1/nope.tgz".into()),
            LockIntegrity::BerryChecksum(format!("9/{}", "0".repeat(128))),
        );
        match fetch_and_stage(&entry, &build_registry_client()).await {
            Err(FetchError::Unverifiable(msg)) => assert!(msg.contains("cacheKey"), "{msg}"),
            other => panic!("expected pre-network Unverifiable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn pypi_no_wheel_url_message_is_single_spaced() {
        // No URL and no sha256 to resolve one by (a sha256 would consult the
        // PyPI JSON API — `pypi_hash_only_entry_is_resolved_through_the_json_api`).
        let entry = LockfileEntry {
            ecosystem: "pypi",
            source_kind: SourceKind::Unspecified,
            name: "requests".into(),
            version: "2.28.0".into(),
            purl: "pkg:pypi/requests@2.28.0".into(),
            resolved: None,
            integrity: LockIntegrity::Sri("sha512-x".into()),
        };
        match fetch_and_stage(&entry, &build_registry_client()).await {
            Err(FetchError::Unverifiable(msg)) => assert!(
                !msg.contains("  "),
                "user-facing message carries an embedded space run: {msg:?}"
            ),
            other => panic!("expected Unverifiable, got {other:?}"),
        }
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

    #[tokio::test]
    async fn unknown_ecosystem_refuses_before_network() {
        // Ecosystems without a fetcher (maven/nuget/deno) keep the caller's
        // not-installed outcome via Unverifiable — decided BEFORE any I/O
        // (the poison URL would hard-fail if contacted).
        let entry = LockfileEntry {
            ecosystem: "maven",
            source_kind: SourceKind::Unspecified,
            name: "org.apache.commons:commons-lang3".into(),
            version: "3.14.0".into(),
            purl: "pkg:maven/org.apache.commons/commons-lang3@3.14.0".into(),
            resolved: Some("http://127.0.0.1:1/x.jar".into()),
            integrity: LockIntegrity::Sha256Hex("0".repeat(64)),
        };
        match fetch_and_stage(&entry, &build_registry_client()).await {
            Err(FetchError::Unverifiable(msg)) => assert!(
                msg.contains("no registry fetcher for ecosystem `maven`"),
                "{msg}"
            ),
            other => panic!("expected pre-network Unverifiable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn per_ecosystem_unverifiable_refusals_without_network() {
        // Each refusal is decidable from the lockfile alone, so each must be
        // the Unverifiable kind — poison URLs prove no I/O happened.
        let client = build_registry_client();

        // composer.lock entry with no dist URL.
        let entry = LockfileEntry {
            ecosystem: "composer",
            source_kind: SourceKind::Unspecified,
            name: "monolog/monolog".into(),
            version: "3.5.0".into(),
            purl: "pkg:composer/monolog/monolog@3.5.0".into(),
            resolved: None,
            integrity: LockIntegrity::Sha1Hex("0".repeat(40)),
        };
        match fetch_and_stage(&entry, &client).await {
            Err(FetchError::Unverifiable(msg)) => {
                assert!(msg.contains("no dist URL"), "{msg}")
            }
            other => panic!("expected composer Unverifiable, got {other:?}"),
        }

        // Gem entry (safe coordinates) with no download URL.
        let entry = LockfileEntry {
            ecosystem: "gem",
            source_kind: SourceKind::Unspecified,
            name: "rails".into(),
            version: "7.1.0".into(),
            purl: "pkg:gem/rails@7.1.0".into(),
            resolved: None,
            integrity: LockIntegrity::Sha256Hex("0".repeat(64)),
        };
        match fetch_and_stage(&entry, &client).await {
            Err(FetchError::Unverifiable(msg)) => {
                assert!(msg.contains("no download URL"), "{msg}")
            }
            other => panic!("expected gem Unverifiable, got {other:?}"),
        }

        // Go modules verify via the go.sum h1 dirhash ONLY: any other
        // integrity kind refuses before the URL is even built.
        let entry = LockfileEntry {
            ecosystem: "golang",
            source_kind: SourceKind::Unspecified,
            name: "github.com/x/y".into(),
            version: "v1.0.0".into(),
            purl: "pkg:golang/github.com/x/y@v1.0.0".into(),
            resolved: Some("http://127.0.0.1:1/m.zip".into()),
            integrity: LockIntegrity::Sha256Hex("0".repeat(64)),
        };
        match fetch_and_stage(&entry, &client).await {
            Err(FetchError::Unverifiable(msg)) => {
                assert!(msg.contains("h1 dirhash"), "{msg}")
            }
            other => panic!("expected golang Unverifiable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn cargo_crate_without_cargo_toml_refuses() {
        // A sha256-VERIFIED .crate that extracts without a Cargo.toml is not
        // a crate — the post-extraction shape check must fail the fetch.
        let crate_bytes = make_tgz(&[("left-pad-1.3.0/src/lib.rs", b"pub fn pad() {}\n", false)]);
        let sha = hex::encode(Sha256::digest(&crate_bytes));
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(url_path("/left-pad/left-pad-1.3.0.crate"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(crate_bytes))
            .mount(&mock)
            .await;

        let entry = LockfileEntry {
            ecosystem: "cargo",
            source_kind: SourceKind::Unspecified,
            name: "left-pad".into(),
            version: "1.3.0".into(),
            purl: "pkg:cargo/left-pad@1.3.0".into(),
            resolved: Some(format!("{}/left-pad/left-pad-1.3.0.crate", mock.uri())),
            integrity: LockIntegrity::Sha256Hex(sha),
        };
        match fetch_and_stage(&entry, &build_registry_client()).await {
            Err(FetchError::Failed(msg)) => assert!(msg.contains("no Cargo.toml"), "{msg}"),
            other => panic!("expected shape refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn composer_dist_without_composer_json_refuses() {
        // sha1-verified zipball whose lone top dir carries no composer.json:
        // the layout detection strips the top dir, finds nothing, refuses.
        let zip_bytes = make_zip(&[("pkg-1.0/README.md", b"# not a composer package\n")]);
        let sha1 = hex::encode(Sha1::digest(&zip_bytes));
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(url_path("/dists/pkg-1.0.zip"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_bytes))
            .mount(&mock)
            .await;

        let entry = LockfileEntry {
            ecosystem: "composer",
            source_kind: SourceKind::Unspecified,
            name: "acme/pkg".into(),
            version: "1.0.0".into(),
            purl: "pkg:composer/acme/pkg@1.0.0".into(),
            resolved: Some(format!("{}/dists/pkg-1.0.zip", mock.uri())),
            integrity: LockIntegrity::Sha1Hex(sha1),
        };
        match fetch_and_stage(&entry, &build_registry_client()).await {
            Err(FetchError::Failed(msg)) => assert!(msg.contains("no composer.json"), "{msg}"),
            other => panic!("expected shape refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn npm_tarball_without_package_json_refuses() {
        // SRI-verified tarball with no package.json — not an npm package.
        let tgz = make_tgz(&[("package/index.js", b"module.exports = 1;\n", false)]);
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(url_path("/left-pad/-/left-pad-1.3.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tgz.clone()))
            .mount(&mock)
            .await;

        let entry = npm_entry(
            Some(format!("{}/left-pad/-/left-pad-1.3.0.tgz", mock.uri())),
            LockIntegrity::Sri(sri_of(&tgz)),
        );
        match fetch_and_stage(&entry, &build_registry_client()).await {
            Err(FetchError::Failed(msg)) => assert!(msg.contains("no package.json"), "{msg}"),
            other => panic!("expected shape refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn cargo_conventional_url_honors_registry_override() {
        // Cargo.lock records no `resolved` URL for registry crates — the
        // conventional `{base}/{name}/{name}-{version}.crate` construction
        // (and the SOCKET_CRATES_REGISTRY override feeding it) must run.
        let crate_bytes = make_tgz(&[(
            "left-pad-1.3.0/Cargo.toml",
            b"[package]\nname = \"left-pad\"\n",
            false,
        )]);
        let sha = hex::encode(Sha256::digest(&crate_bytes));
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(url_path("/left-pad/left-pad-1.3.0.crate"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(crate_bytes))
            .mount(&mock)
            .await;

        let entry = LockfileEntry {
            ecosystem: "cargo",
            source_kind: SourceKind::Unspecified,
            name: "left-pad".into(),
            version: "1.3.0".into(),
            purl: "pkg:cargo/left-pad@1.3.0".into(),
            resolved: None,
            integrity: LockIntegrity::Sha256Hex(sha),
        };
        let saved = std::env::var("SOCKET_CRATES_REGISTRY").ok();
        // Trailing slash on purpose: the base must be trimmed before use.
        std::env::set_var("SOCKET_CRATES_REGISTRY", format!("{}/", mock.uri()));
        let result = fetch_and_stage(&entry, &build_registry_client()).await;
        match saved {
            Some(v) => std::env::set_var("SOCKET_CRATES_REGISTRY", v),
            None => std::env::remove_var("SOCKET_CRATES_REGISTRY"),
        }
        let fetched = result.expect("the conventional crate URL must fetch");
        assert_eq!(
            fetched.url,
            format!("{}/left-pad/left-pad-1.3.0.crate", mock.uri()),
            "conventional URL: {{base}}/{{name}}/{{name}}-{{version}}.crate"
        );
        assert!(fetched.dir().await.unwrap().join("Cargo.toml").is_file());
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn golang_conventional_url_escapes_name_and_version() {
        // No resolved URL → the conventional GOPROXY zip URL, with the
        // module-path CASE ESCAPING applied to BOTH the name and the version
        // (an uppercase letter becomes `!lowercase` in the URL, while the
        // zip's interior prefix keeps the unescaped coordinates).
        let prefix = "github.com/Azure/y@v1.0.0-RC1/";
        let files: [(&str, &[u8]); 1] = [("go.mod", b"module github.com/Azure/y\n")];
        let zip_bytes = make_module_zip(prefix, &files);
        let expected_h1 = spec_h1(&files, prefix);

        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(url_path("/github.com/!azure/y/@v/v1.0.0-!r!c1.zip"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_bytes))
            .mount(&mock)
            .await;

        let entry = LockfileEntry {
            ecosystem: "golang",
            source_kind: SourceKind::Unspecified,
            name: "github.com/Azure/y".into(),
            version: "v1.0.0-RC1".into(),
            purl: "pkg:golang/github.com/Azure/y@v1.0.0-RC1".into(),
            resolved: None,
            integrity: LockIntegrity::GoH1(expected_h1),
        };
        let saved_socket = std::env::var("SOCKET_GOPROXY").ok();
        let saved = std::env::var("GOPROXY").ok();
        std::env::set_var("SOCKET_GOPROXY", mock.uri());
        std::env::remove_var("GOPROXY");
        let result = fetch_and_stage(&entry, &build_registry_client()).await;
        match saved_socket {
            Some(v) => std::env::set_var("SOCKET_GOPROXY", v),
            None => std::env::remove_var("SOCKET_GOPROXY"),
        }
        match saved {
            Some(v) => std::env::set_var("GOPROXY", v),
            None => std::env::remove_var("GOPROXY"),
        }
        let fetched = result.expect("the conventional module zip URL must fetch");
        assert_eq!(
            fetched.url,
            format!("{}/github.com/!azure/y/@v/v1.0.0-!r!c1.zip", mock.uri()),
            "case escaping must apply to the name AND the version"
        );
        assert!(fetched.dir().await.unwrap().join("go.mod").is_file());
    }

    /// go never sends a module path to a proxy when GOPROXY starts with
    /// `off` / `direct`, or when the module matches GONOPROXY (defaulting to
    /// GOPRIVATE). The pristine fetch must not either: it refuses before any
    /// network I/O instead of falling back to proxy.golang.org.
    #[tokio::test]
    #[serial_test::serial]
    async fn golang_fetch_never_uses_a_proxy_go_would_not() {
        let mock = MockServer::start().await;
        let entry = LockfileEntry {
            ecosystem: "golang",
            name: "example.com/private/mod".into(),
            version: "v1.0.0".into(),
            purl: "pkg:golang/example.com/private/mod@v1.0.0".into(),
            resolved: None,
            integrity: LockIntegrity::GoH1("h1:AAAA".into()),
            source_kind: SourceKind::Unspecified,
        };
        let keys = ["SOCKET_GOPROXY", "GOPROXY", "GOPRIVATE", "GONOPROXY"];
        let saved: Vec<Option<String>> = keys.iter().map(|k| std::env::var(k).ok()).collect();
        for k in keys {
            std::env::remove_var(k);
        }
        let proxy = mock.uri();
        let cases: Vec<(String, &str, &str, bool)> = vec![
            ("off".into(), "", "", false),
            ("direct".into(), "", "", false),
            (format!("off,{proxy}"), "", "", false),
            (format!("direct|{proxy}"), "", "", false),
            (proxy.clone(), "example.com/private", "", false),
            (proxy.clone(), "example.com/*", "", false),
            (proxy.clone(), "*.example", "", true),
            (proxy.clone(), "example.com/private", "other.example", true),
        ];
        let mut outcomes = Vec::new();
        for (goproxy, goprivate, gonoproxy, uses_proxy) in &cases {
            std::env::set_var("GOPROXY", goproxy);
            std::env::set_var("GOPRIVATE", goprivate);
            std::env::set_var("GONOPROXY", gonoproxy);
            let result = fetch_and_stage(&entry, &build_registry_client()).await;
            outcomes.push((
                goproxy.clone(),
                *goprivate,
                *gonoproxy,
                *uses_proxy,
                result.err(),
            ));
        }
        for (k, v) in keys.iter().zip(saved) {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        for (goproxy, goprivate, gonoproxy, uses_proxy, err) in &outcomes {
            let case = format!("GOPROXY={goproxy} GOPRIVATE={goprivate} GONOPROXY={gonoproxy}");
            if *uses_proxy {
                assert!(
                    matches!(err, Some(FetchError::Failed(_))),
                    "{case}: {err:?}"
                );
            } else {
                assert!(
                    matches!(err, Some(FetchError::Unverifiable(d)) if d.contains("GO")),
                    "{case}: {err:?}"
                );
            }
        }
        let hits = mock.received_requests().await.unwrap_or_default().len();
        assert_eq!(hits, 2, "only the two proxy-eligible cases reach the proxy");
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
            let lazy = validate_tgz(&bytes, Some("package.json")).unwrap_err();
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
            let lazy = validate_zip(&bytes, strip, Some("composer.json")).unwrap_err();
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
            let lazy = validate_zip_with_prefix(&bytes, prefix).unwrap_err();
            assert_eq!(lazy, eager, "{label}");
            // And the golang fetch's fused walk, which answers the same
            // question off the dirhash pass's single inflate.
            match walk_module_zip(&bytes, Some(prefix)) {
                // The dirhash pass guards the caps too and refuses first —
                // exactly where the pair of walks did.
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
            let lazy = validate_gem_data(&bytes).unwrap_err();
            assert_eq!(lazy, eager, "{label}");
        }
    }

    /// And on a healthy archive: the pass accepts it, writes nothing, and
    /// answers the root-file probe the fetchers used to run against the
    /// extracted tree.
    #[test]
    fn validation_pass_accepts_and_answers_the_root_probe() {
        let tgz = make_tgz(&[
            ("package/package.json", b"{}", false),
            ("package/bin/cli.js", b"#!/usr/bin/env node\n", true),
        ]);
        assert!(validate_tgz(&tgz, Some("package.json")).unwrap());
        assert!(!validate_tgz(&tgz, Some("Cargo.toml")).unwrap());

        // A nested entry counts, exactly as the directory the extraction
        // creates for it made `metadata(dir.join(name))` succeed.
        let nested = make_tgz(&[("package/composer.json/x", b"{}", false)]);
        assert!(validate_tgz(&nested, Some("composer.json")).unwrap());

        let zip_bytes = make_zip(&[("pfx/composer.json", b"{}"), ("pfx/src/a.php", b"<?php")]);
        assert!(validate_zip(
            &zip_bytes,
            /*strip_first=*/ true,
            Some("composer.json")
        )
        .unwrap());
        assert!(!validate_zip(
            &zip_bytes,
            /*strip_first=*/ false,
            Some("composer.json")
        )
        .unwrap());

        validate_gem_data(&wrap_gem(&make_tgz(&[("lib/a.rb", b"x", false)]))).unwrap();
        let prefix = "github.com/x/y@v1.0.0/";
        validate_zip_with_prefix(&make_module_zip(prefix, &[("go.mod", b"module m")]), prefix)
            .unwrap();
    }

    /// A deferred source extracts to exactly what the eager fetch wrote —
    /// same tree, same bytes, same modes — and says so only once.
    #[tokio::test]
    async fn deferred_extraction_materializes_the_eager_tree() {
        let tgz = make_tgz(&[
            ("package/package.json", br#"{"name":"left-pad"}"#, false),
            ("package/index.js", b"module.exports=1\n", false),
            ("package/bin/cli.js", b"#!/usr/bin/env node\n", true),
        ]);
        let eager = tempfile::tempdir().unwrap();
        extract_tgz(&tgz, eager.path()).unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("package");
        let bytes = tgz.clone();
        let fetched = FetchedPackage::pending(
            dir.clone(),
            "https://example.invalid/left-pad.tgz".to_string(),
            tmp,
            move |dest, skip| extract_tgz_skipping(&bytes, dest, skip),
        );
        // The path is known before anything is written, and nothing is.
        assert_eq!(fetched.dir_path(), dir);
        assert!(!dir.exists(), "a pending source writes nothing until read");

        assert_eq!(fetched.dir().await.unwrap(), dir);
        for rel in ["package.json", "index.js", "bin/cli.js"] {
            assert_eq!(
                std::fs::read(dir.join(rel)).unwrap(),
                std::fs::read(eager.path().join(rel)).unwrap(),
                "{rel}"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                assert_eq!(
                    std::fs::metadata(dir.join(rel))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    std::fs::metadata(eager.path().join(rel))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    "{rel} mode"
                );
            }
        }
        // A second read is the same answer, not a second extraction.
        assert_eq!(fetched.dir().await.unwrap(), dir);
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
            let mode = if file.unix_mode().is_some_and(|m| m & 0o111 != 0) {
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
        assert_eq!(validate_zip(&archive, false, None).unwrap_err(), err);
    }

    /// Staging a pending source straight into the vendor stage must leave
    /// exactly what extracting it and copying the tree out left: same
    /// files, same bytes, same modes, same skip.
    #[tokio::test]
    async fn staging_a_pending_source_equals_extract_then_copy() {
        let tgz = make_tgz(&[
            ("crate/Cargo.toml", b"[package]\nname=\"x\"\n", false),
            ("crate/src/lib.rs", b"pub fn x() {}\n", false),
            ("crate/build.sh", b"#!/bin/sh\n", true),
            ("crate/.cargo-checksum.json", b"{}", false),
            ("crate/vendor/.cargo-checksum.json", b"{}", false),
        ]);
        for skip in [None, Some(".cargo-checksum.json")] {
            // The oracle: what the eager fetch + `fresh_copy` produced.
            let tmp = tempfile::tempdir().unwrap();
            let extracted = tmp.path().join("crate");
            extract_tgz(&tgz, &extracted).unwrap();
            let oracle = tempfile::tempdir().unwrap();
            let oracle_stage = oracle.path().join("stage");
            crate::patch::copy_tree::fresh_copy(&extracted, &oracle_stage, skip)
                .await
                .unwrap();

            let holder = tempfile::tempdir().unwrap();
            let bytes = tgz.clone();
            let fetched = FetchedPackage::pending(
                holder.path().join("crate"),
                "https://example.invalid/x.crate".to_string(),
                holder,
                move |dest, skip| extract_tgz_skipping(&bytes, dest, skip),
            );
            let staged_root = tempfile::tempdir().unwrap();
            let staged = staged_root.path().join("stage");
            fetched.stage_into(&staged, skip).await.unwrap();
            assert!(
                !fetched.dir_path().exists(),
                "a direct stage writes no tempdir tree"
            );
            assert_eq!(tree_of(&staged), tree_of(&oracle_stage), "skip: {skip:?}");
        }
    }

    /// And when something read the tree first, the stage is still the same
    /// — it just comes off that tree instead of a second inflate.
    #[tokio::test]
    async fn staging_after_materializing_still_matches() {
        let tgz = make_tgz(&[
            ("pkg/a.rb", b"A\n", false),
            ("pkg/bin/run", b"#!/bin/sh\n", true),
        ]);
        let holder = tempfile::tempdir().unwrap();
        let bytes = tgz.clone();
        let fetched = FetchedPackage::pending(
            holder.path().join("pkg"),
            "https://example.invalid/x.gem".to_string(),
            holder,
            move |dest, skip| extract_tgz_skipping(&bytes, dest, skip),
        );
        let materialized = fetched.dir().await.unwrap().to_path_buf();
        let staged_root = tempfile::tempdir().unwrap();
        let staged = staged_root.path().join("stage");
        fetched.stage_into(&staged, None).await.unwrap();
        assert_eq!(tree_of(&staged), tree_of(&materialized));
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
                    .into_owned();
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

    /// An extraction that cannot be written reports the same failure to
    /// every later caller, and never half-answers.
    #[tokio::test]
    async fn deferred_extraction_failure_is_sticky() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("package");
        let fetched = FetchedPackage::pending(
            dir.clone(),
            "https://example.invalid/x.tgz".to_string(),
            tmp,
            |_, _| Err("cannot create /nope: nope".to_string()),
        );
        assert_eq!(
            fetched.dir().await.unwrap_err(),
            "cannot create /nope: nope"
        );
        assert_eq!(
            fetched.dir().await.unwrap_err(),
            "cannot create /nope: nope",
            "the outcome is decided once and shared"
        );
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
        assert!(err.contains("cacheKey other than 10c0"), "{err}");

        // 10c0: the cache-zip rebuild round-trips, and a tampered checksum
        // names the mismatch.
        let tgz = make_tgz(&[("package/package.json", br#"{"name":"left-pad"}"#, false)]);
        let good = super::super::berry_zip::berry_cache_checksum_10c0(&tgz, "left-pad").unwrap();
        artifact_matches_integrity(&tgz, "left-pad", &LockIntegrity::BerryChecksum(good))
            .expect("the rebuilt cache checksum must match");
        let err = artifact_matches_integrity(
            &tgz,
            "left-pad",
            &LockIntegrity::BerryChecksum(format!("10c0/{}", "0".repeat(128))),
        )
        .unwrap_err();
        assert!(err.contains("mismatch"), "{err}");

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
            err.contains("exceeds the") && err.contains("cap"),
            "the stream cap must fire without a Content-Length: {err}"
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
