//! Agent-mode patches of JVM jars (#264): Maven `~/.m2` and Gradle
//! `files-2.1` copies alike.
//!
//! A Maven patch record comes in two shapes ([`classify`]):
//!
//! * **Leaf** — every key names a file of the version directory
//!   (`package/<a>-<v>.pom`, a whole-file `<a>-<v>.jar`). It patches in
//!   place like any other ecosystem, per copy.
//! * **Members** — the keys are members INSIDE the artifact's jar
//!   (`META-INF/NOTICE.txt`, `com/x/Y.class`). Rewriting members in place
//!   would need a deterministic local repack, which nothing downstream could
//!   verify, so the whole jar is swapped for the patch service's build of it
//!   instead ([`apply_jar_swap`]): its patched members must hash to the
//!   record's `afterHash`es and every other member a JVM would load must
//!   equal the installed jar's ([`super::jar_members`], which also sets the
//!   size limits a jar is read within). The original jar is kept at
//!   `<.socket>/jvm-originals/<sha256>.jar` — outside `blobs/`, so no blob
//!   cleanup ever removes it — and [`rollback_jar_swap`] restores it byte
//!   for byte. A copy this project holds no backup of (another project or
//!   an earlier workspace patched it) can still be restored from upstream:
//!   a Gradle copy when the download hashes to its hash directory's name,
//!   a `~/.m2` copy when the download matches the registry's checksum and
//!   is the patched copy's jar with the record's members at their
//!   `beforeHash`.
//!
//! Offline, or without the patch service, a member record writes nothing
//! (`jvm_agent_service_required`): vendored or hosted mode carry it instead.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::crawlers::gradle_cache;
use crate::hash::git_sha256::compute_git_sha256_from_bytes;
use crate::manifest::schema::PatchFileInfo;
use crate::patch::apply::{
    apply_file_patch_at, files_in_order, normalize_file_path, ApplyResult, VerifyResult,
    VerifyStatus,
};
use crate::patch::jar_members::{difference_outside_patch, Difference, Digests, Jar, JarError};
use crate::patch::rollback::{RollbackResult, VerifyRollbackResult, VerifyRollbackStatus};
use crate::patch::sidecars::{self, maven as maven_sidecars};
use crate::utils::purl::{parse_maven_purl, purl_qualifier};
use crate::vendor::VendorServiceConfig;

/// Where original jars are kept, under the manifest's `.socket/` directory.
pub const ORIGINALS_DIR: &str = "jvm-originals";

/// A jar is past a limit [`super::jar_members`] reads jars within: the
/// service's jar refuses the whole swap, an installed one fails its copy.
pub const JAR_TOO_LARGE: &str = "jvm_jar_too_large";
/// The service's jar is not the record's patch of an installed jar: it
/// lacks the `afterHash` members or cannot be read (the whole swap is
/// refused), or it differs from one copy outside the patched members (that
/// copy fails).
pub const SERVICE_JAR_MISMATCH: &str = "jvm_agent_service_jar_mismatch";

/// One copy's result of a swap. `refusal` is set when the copy was left
/// alone for a reason a run reports as a warning too ([`JAR_TOO_LARGE`],
/// [`SERVICE_JAR_MISMATCH`]); `result.error` is that refusal, formatted.
#[derive(Debug, Clone)]
pub struct SwappedCopy {
    pub result: ApplyResult,
    pub refusal: Option<SwapRefusal>,
}

impl std::ops::Deref for SwappedCopy {
    type Target = ApplyResult;
    fn deref(&self) -> &ApplyResult {
        &self.result
    }
}

/// `work` on the blocking pool: a digest pass inflates a jar up to the jar
/// limits, which is no work for an async worker.
async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    match tokio::task::spawn_blocking(work).await {
        Ok(value) => value,
        Err(e) => match e.try_into_panic() {
            Ok(panic) => std::panic::resume_unwind(panic),
            Err(e) => panic!("the blocking pool is gone: {e}"),
        },
    }
}

/// The two shapes of a Maven patch record (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordShape {
    /// Every key names a file of the version directory.
    Leaf,
    /// The keys are members of the jar `jar_leaf`.
    Members { jar_leaf: String },
}

/// The file name of the artifact a Maven purl names:
/// `<artifactId>-<version>[-<classifier>].<ext>` (`ext` defaults to `jar`).
pub fn jar_leaf(purl: &str) -> Option<String> {
    let (_, artifact, version) = parse_maven_purl(purl)?;
    let classifier = purl_qualifier(purl, "classifier")
        .filter(|c| !c.is_empty())
        .map(|c| format!("-{c}"))
        .unwrap_or_default();
    let ext = purl_qualifier(purl, "ext")
        .or_else(|| purl_qualifier(purl, "type"))
        .filter(|e| !e.is_empty())
        .unwrap_or("jar");
    let leaf = format!("{artifact}-{version}{classifier}.{ext}");
    (!leaf.contains(['/', '\\']) && leaf != "..").then_some(leaf)
}

/// Whether a patch-file key names a member inside a jar rather than a file
/// of the version directory: a nested path, or a class file.
pub fn is_member_key(key: &str) -> bool {
    let normalized = normalize_file_path(key);
    normalized.contains(['/', '\\']) || normalized.ends_with(".class")
}

/// [`RecordShape`] of a record of `purl`. Only a Maven purl with a jar-like
/// artifact can be [`RecordShape::Members`].
pub fn classify(purl: &str, files: &HashMap<String, PatchFileInfo>) -> RecordShape {
    if !purl.starts_with("pkg:maven/") || !files.keys().any(|k| is_member_key(k)) {
        return RecordShape::Leaf;
    }
    match jar_leaf(purl) {
        Some(jar_leaf) => RecordShape::Members { jar_leaf },
        None => RecordShape::Leaf,
    }
}

// ── verification ────────────────────────────────────────────────────────

/// Per-member verify results of a record against the jar bytes `jar`, in
/// key order: a member at its `afterHash` is `AlreadyPatched`, at its
/// `beforeHash` `Ready`, anything else `HashMismatch`; an absent member is
/// `NotFound` (or `Ready` when the patch adds it). An unreadable jar makes
/// every member `NotFound`, and so does one past the jar limits (a caller
/// that tells the two apart asks [`member_statuses`]).
pub fn verify_member_bytes(
    jar: &[u8],
    files: &HashMap<String, PatchFileInfo>,
) -> Vec<VerifyResult> {
    member_statuses(jar, files).unwrap_or_else(|_| statuses(files, |_| None))
}

/// [`verify_member_bytes`], read within the jar limits
/// ([`super::jar_members`]) from the first byte: the limits on the
/// archive's entry count and central directory are held to its end records
/// before anything parses the directory, and a member is inflated only
/// within the pass's budget. `Err` is a jar past a limit; nothing of it was
/// parsed or inflated beyond that limit.
fn member_statuses(
    jar: &[u8],
    files: &HashMap<String, PatchFileInfo>,
) -> Result<Vec<VerifyResult>, JarError> {
    let mut archive = match Jar::of_bytes(jar) {
        Ok(archive) => Some(archive),
        Err(e) if e.is_too_large() => return Err(e),
        Err(_) => None,
    };
    let mut too_large = None;
    let results = statuses(files, |member| {
        match archive.as_mut()?.member_git_sha256(member) {
            Ok(hash) => hash,
            Err(e) => {
                if e.is_too_large() {
                    too_large.get_or_insert(e);
                }
                None
            }
        }
    });
    match too_large {
        Some(e) => Err(e),
        None => Ok(results),
    }
}

/// The verify result of each record member, given its current git-blob
/// hash in the jar (`None` when the jar does not hold it).
fn statuses(
    files: &HashMap<String, PatchFileInfo>,
    mut hash_of: impl FnMut(&str) -> Option<String>,
) -> Vec<VerifyResult> {
    files_in_order(files)
        .into_iter()
        .map(|(key, info)| {
            let member = normalize_file_path(key);
            let hash = hash_of(member);
            let (status, current) = match hash {
                None if info.before_hash.is_empty() => (VerifyStatus::Ready, None),
                None => (VerifyStatus::NotFound, None),
                Some(h) if h == info.after_hash => (VerifyStatus::AlreadyPatched, Some(h)),
                Some(h) if h == info.before_hash || info.before_hash.is_empty() => {
                    (VerifyStatus::Ready, Some(h))
                }
                Some(h) => (VerifyStatus::HashMismatch, Some(h)),
            };
            VerifyResult {
                file: key.clone(),
                status,
                message: match status {
                    VerifyStatus::NotFound => Some(format!("Jar member not found: {member}")),
                    VerifyStatus::HashMismatch => {
                        Some("Jar member hash does not match expected value".to_string())
                    }
                    _ => None,
                },
                current_hash: current,
                expected_hash: (status == VerifyStatus::HashMismatch)
                    .then(|| info.before_hash.clone()),
                target_hash: Some(info.after_hash.clone()),
            }
        })
        .collect()
}

/// One status for a whole member set: `AlreadyPatched` when every member
/// is, else the first `NotFound`, else the first `HashMismatch`, else
/// `Ready`.
pub fn aggregate(results: &[VerifyResult]) -> VerifyStatus {
    if !results.is_empty()
        && results
            .iter()
            .all(|r| r.status == VerifyStatus::AlreadyPatched)
    {
        return VerifyStatus::AlreadyPatched;
    }
    for wanted in [VerifyStatus::NotFound, VerifyStatus::HashMismatch] {
        if results.iter().any(|r| r.status == wanted) {
            return wanted;
        }
    }
    VerifyStatus::Ready
}

/// The member records' twin of `verify_file_patch`: `files` checked
/// against the members of `dir/<jar_leaf>`. `jar_leaf` is explicit so a
/// hosted copy can be checked under its suffixed name
/// (`<a>-<base>-socket.<hex8>.jar`). A missing or unreadable jar is
/// `NotFound`.
pub async fn verify_members(
    dir: &Path,
    jar_leaf: &str,
    files: &HashMap<String, PatchFileInfo>,
) -> VerifyStatus {
    if files.is_empty() {
        return VerifyStatus::NotFound;
    }
    match crate::utils::fs::read_regular_to_bytes(&dir.join(jar_leaf)).await {
        Ok(bytes) => aggregate(&verify_member_bytes(&bytes, files)),
        Err(_) => VerifyStatus::NotFound,
    }
}

/// The directories holding `jar_leaf` for the package at `pkg_path`: each
/// Gradle hash directory that holds it (a version dir expands through
/// [`gradle_cache::installed_copies`]), or `pkg_path` itself when the jar
/// sits there (`~/.m2`). Empty when no copy holds it.
pub fn jar_copies(pkg_path: &Path, jar_leaf: &str) -> Vec<PathBuf> {
    let probe = HashMap::from([(
        jar_leaf.to_string(),
        PatchFileInfo {
            before_hash: String::new(),
            after_hash: String::new(),
        },
    )]);
    gradle_cache::installed_copies(pkg_path, &probe)
        .into_iter()
        .map(|(dir, _)| dir)
        .filter(|dir| dir.join(jar_leaf).is_file())
        .collect()
}

// ── derived copies ──────────────────────────────────────────────────────

/// What [`derived_copies`] found of the copies Gradle derived from a
/// cached jar.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DerivedVerdict {
    /// Copies proven derived from the PRISTINE jar (see
    /// [`gradle_cache::DerivedCopies::stale`]): they still serve the old
    /// bytes.
    pub stale: Vec<PathBuf>,
    /// Same-named copies whose bytes are neither the pristine jar nor the
    /// jar now in the hash dir, and that are older than that jar: Gradle
    /// may have derived them from the pristine jar.
    pub unverified: Vec<PathBuf>,
    /// The walk did not cover every derived-cache root.
    pub incomplete: bool,
}

impl DerivedVerdict {
    /// Whether every derived copy is proven to carry the hash dir's
    /// current bytes (or there is none).
    pub fn clean(&self) -> bool {
        self.stale.is_empty() && self.unverified.is_empty() && !self.incomplete
    }
}

/// The [`gradle_cache::DerivedIndex`] of each Gradle user home a run
/// checks, built on first use: one walk per home however many jars are
/// checked. Cheap to clone (shared).
#[derive(Debug, Clone, Default)]
pub struct DerivedCache(
    std::sync::Arc<std::sync::Mutex<HashMap<PathBuf, std::sync::Arc<gradle_cache::DerivedIndex>>>>,
);

impl DerivedCache {
    fn index(&self, home: &Path) -> std::sync::Arc<gradle_cache::DerivedIndex> {
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(home.to_path_buf())
            .or_insert_with(|| std::sync::Arc::new(gradle_cache::DerivedIndex::build(home)))
            .clone()
    }
}

/// The copies Gradle derived (outside `files-2.1`) from the jar `jar_leaf`
/// of the hash dir `hash_dir`, whose name is the PRISTINE jar's sha1:
/// [`gradle_cache::stale_derived_copies`] over the dir's user home. A
/// same-named copy is dropped from `unverified` when it is byte-identical
/// to the jar now in the hash dir, or no older than it: Gradle keys its
/// derived caches by the input's content, so a copy made after the jar was
/// rewritten was made from the rewritten jar — that is how an instrumented
/// build-logic jar (never byte-equal to its input) rebuilt after the patch
/// is told from one left over from the pristine jar. `None` for anything
/// but a writable Gradle hash dir. Blocking.
pub fn derived_copies(hash_dir: &Path, jar_leaf: &str) -> Option<DerivedVerdict> {
    derived_copies_in(&DerivedCache::default(), hash_dir, jar_leaf)
}

/// [`derived_copies`] over `cache`'s index of the user home.
pub fn derived_copies_in(
    cache: &DerivedCache,
    hash_dir: &Path,
    jar_leaf: &str,
) -> Option<DerivedVerdict> {
    if !maven_sidecars::is_gradle_hash_dir(hash_dir) {
        return None;
    }
    let home = maven_sidecars::gradle_user_home_of(hash_dir)?;
    let pristine_sha1 = hash_dir.file_name()?.to_str()?;
    let found = cache.index(&home).query(jar_leaf, pristine_sha1);
    let jar = hash_dir.join(jar_leaf);
    // Both reads are of user-writable Gradle cache files: the FIFO-safe
    // reader fails fast on a FIFO or device instead of wedging in open(2).
    let current = crate::utils::fs::read_regular_to_bytes_sync(&jar)
        .ok()
        .map(|b| sha1_hex(&b));
    let written = std::fs::metadata(&jar).and_then(|m| m.modified()).ok();
    let unverified = found
        .unknown
        .into_iter()
        .filter(|p| {
            let Ok(copy) = crate::utils::fs::read_regular_to_bytes_sync(p) else {
                return true;
            };
            if Some(sha1_hex(&copy)) == current {
                return false;
            }
            let made = std::fs::metadata(p).and_then(|m| m.modified()).ok();
            !matches!((made, written), (Some(made), Some(written)) if made >= written)
        })
        .collect();
    Some(DerivedVerdict {
        stale: found.stale,
        unverified,
        incomplete: found.incomplete,
    })
}

// ── swap ────────────────────────────────────────────────────────────────

/// A refusal of the whole swap: nothing was written. `code` is a stable
/// routing tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapRefusal {
    pub code: &'static str,
    pub message: String,
}

impl SwapRefusal {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// One member-keyed record to swap in across its copies.
#[derive(Debug, Clone, Copy)]
pub struct JarSwap<'a> {
    pub purl: &'a str,
    pub uuid: &'a str,
    pub jar_leaf: &'a str,
    pub files: &'a HashMap<String, PatchFileInfo>,
    /// The manifest's `.socket/` directory (backups go under
    /// [`ORIGINALS_DIR`]).
    pub socket_dir: &'a Path,
    pub dry_run: bool,
}

fn result_for(swap: &JarSwap<'_>, dir: &Path) -> ApplyResult {
    ApplyResult {
        package_key: swap.purl.to_string(),
        package_path: dir.display().to_string(),
        success: false,
        files_verified: Vec::new(),
        files_patched: Vec::new(),
        applied_via: HashMap::new(),
        error: None,
        sidecar: None,
        cause: None,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    crate::utils::digest::sha256_hex_of(bytes)
}

fn sha1_hex(bytes: &[u8]) -> String {
    crate::utils::digest::sha1_hex_of(bytes)
}

/// `<socket_dir>/jvm-originals/<sha256>.jar`.
pub fn backup_path(socket_dir: &Path, original: &[u8]) -> PathBuf {
    socket_dir
        .join(ORIGINALS_DIR)
        .join(format!("{}.jar", sha256_hex(original)))
}

/// Keep `original` under [`ORIGINALS_DIR`] (content-addressed: an existing
/// backup with the right bytes is kept as is).
async fn write_backup(socket_dir: &Path, original: &[u8]) -> Result<(), String> {
    let path = backup_path(socket_dir, original);
    if let Ok(existing) = crate::utils::fs::read_regular_to_bytes(&path).await {
        if existing == original {
            return Ok(());
        }
    }
    let dir = socket_dir.join(ORIGINALS_DIR);
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    crate::utils::fs::atomic_write_bytes(&path, original)
        .await
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Write `bytes` over `dir/<leaf>` (stage + rename, mode and owner kept).
async fn write_jar(dir: &Path, leaf: &str, bytes: &[u8]) -> std::io::Result<Option<String>> {
    apply_file_patch_at(dir, leaf, bytes, &compute_git_sha256_from_bytes(bytes)).await
}

/// The patch service's build of `uuid` as verified jar bytes.
async fn service_jar(
    service: Option<&VendorServiceConfig>,
    uuid: &str,
) -> Result<Vec<u8>, SwapRefusal> {
    use crate::vendor::service_fetch::{fetch_verified_archive, ServiceArtifact};
    let required = |why: &str| {
        SwapRefusal::new(
            "jvm_agent_service_required",
            format!(
                "this patch rewrites members inside the jar, so agent mode swaps in the patch \
                 service's build of the whole jar, and {why}; nothing was written. Run online, \
                 or use `--mode vendored` / `--mode hosted`."
            ),
        )
    };
    let Some(cfg) = service else {
        return Err(required("no patch service is configured"));
    };
    if cfg.offline {
        return Err(required("--offline is set"));
    }
    if !cfg.service_enabled() {
        return Err(required("the patch service is disabled for this run"));
    }
    match fetch_verified_archive(cfg, uuid).await {
        ServiceArtifact::Ready(archive) => Ok(archive.bytes),
        ServiceArtifact::IntegrityMismatch(why) => Err(SwapRefusal::new(
            "jvm_agent_service_integrity",
            format!("the patch service's jar failed integrity verification: {why}"),
        )),
        ServiceArtifact::Pending => Err(required("the patch service is still building it")),
        ServiceArtifact::Unavailable(why) | ServiceArtifact::Failed(why) => Err(required(
            &format!("the patch service did not provide it ({why})"),
        )),
    }
}

/// Swap the patch service's build of `swap`'s jar into every copy in
/// `copies` (directories holding `jar_leaf`, see [`jar_copies`]).
///
/// Each copy's members are verified first: a copy already patched is left
/// alone; a copy whose members are neither the pristine nor the patched
/// bytes fails on its own (its jar is not the one the record was made for).
/// The service jar must carry every `afterHash` and, for each copy it
/// replaces, every unpatched member of that copy's jar. Each distinct
/// original is backed up before any copy is written; a write that fails
/// puts every copy already swapped back. `Err` means nothing was written.
/// `Ok` carries one result per copy.
pub async fn apply_jar_swap(
    swap: &JarSwap<'_>,
    copies: &[PathBuf],
    service: Option<&VendorServiceConfig>,
) -> Result<Vec<SwappedCopy>, SwapRefusal> {
    let mut refusals = HashMap::new();
    let results = swap_copies(swap, copies, service, &mut refusals).await?;
    Ok(results
        .into_iter()
        .enumerate()
        .map(|(i, result)| SwappedCopy {
            result,
            refusal: refusals.remove(&i),
        })
        .collect())
}

/// [`apply_jar_swap`]; a copy's coded refusal goes to `refusals` by index.
async fn swap_copies(
    swap: &JarSwap<'_>,
    copies: &[PathBuf],
    service: Option<&VendorServiceConfig>,
    refusals: &mut HashMap<usize, SwapRefusal>,
) -> Result<Vec<ApplyResult>, SwapRefusal> {
    let mut results = Vec::new();
    let mut pending: Vec<(usize, Vec<u8>)> = Vec::new();
    for dir in copies {
        let mut result = result_for(swap, dir);
        let original = match crate::utils::fs::read_regular_to_bytes(&dir.join(swap.jar_leaf)).await
        {
            Ok(bytes) => bytes,
            Err(e) => {
                result.error = Some(format!(
                    "Cannot apply patch: {} - {e}",
                    dir.join(swap.jar_leaf).display()
                ));
                results.push(result);
                continue;
            }
        };
        // The bounded reader is the first thing to parse the copy: one past
        // the jar limits is refused here, before anything allocates for it.
        result.files_verified = match member_statuses(&original, swap.files) {
            Ok(verified) => verified,
            Err(e) => {
                let refusal = SwapRefusal::new(
                    JAR_TOO_LARGE,
                    format!(
                        "{} cannot be read within the jar limits: {e}. It was left as it is. \
                         `--mode hosted` does not read the jar.",
                        dir.join(swap.jar_leaf).display()
                    ),
                );
                result.error = Some(format!("{}: {}", refusal.code, refusal.message));
                refusals.insert(results.len(), refusal);
                results.push(result);
                continue;
            }
        };
        match aggregate(&result.files_verified) {
            VerifyStatus::AlreadyPatched => result.success = true,
            VerifyStatus::Ready => pending.push((results.len(), original)),
            _ => {
                let bad = result
                    .files_verified
                    .iter()
                    .find(|v| {
                        !matches!(v.status, VerifyStatus::Ready | VerifyStatus::AlreadyPatched)
                    })
                    .expect("a NotFound or HashMismatch member exists");
                let mut error = format!(
                    "Cannot apply patch: {} - {}",
                    bad.file,
                    bad.message.clone().unwrap_or_default()
                );
                if bad.status == VerifyStatus::HashMismatch {
                    // Not the original and not this patch: most often an
                    // earlier revision of the patch, applied from another
                    // project or workspace whose backup is not here.
                    error.push_str(&format!(
                        ". {} holds neither the original member nor this patch's: another \
                         revision of the patch may have been applied from another project or \
                         workspace, or the jar was rebuilt. Roll that patch back where it was \
                         applied, or delete {} so the build downloads the jar again, then apply.",
                        dir.join(swap.jar_leaf).display(),
                        dir.display()
                    ));
                }
                result.error = Some(error);
            }
        }
        results.push(result);
    }
    if pending.is_empty() {
        return Ok(results);
    }

    let jar = service_jar(service, swap.uuid).await?;
    // One pass off the async workers: every member's content of the
    // service's jar, read within the jar limits before anything else
    // inflates the download, then of each original. Identical originals
    // (one jar in several caches) are read once, keyed by their sha256.
    let files = swap.files.clone();
    let (jar, originals, service_members, differences) = blocking(move || {
        use sha2::Digest as _;
        let service = Digests::of_bytes(&jar).map(|members| {
            // After the bounded pass: this inflates only what that one did.
            crate::vendor::common::zip_bytes_match_after_hashes(&jar, &files).then_some(members)
        });
        // Per copy: everything the patch does not touch must be upstream's.
        let mut read: HashMap<[u8; 32], Result<Difference, JarError>> = HashMap::new();
        let copies: Vec<Result<Difference, JarError>> = match &service {
            Ok(Some(service)) => pending
                .iter()
                .map(|(_, original)| {
                    read.entry(sha2::Sha256::digest(original).into())
                        .or_insert_with(|| {
                            Digests::of_bytes(original).and_then(|members| {
                                difference_outside_patch(
                                    (original, &members),
                                    (&jar, service),
                                    &files,
                                )
                            })
                        })
                        .clone()
                })
                .collect(),
            _ => Vec::new(),
        };
        (jar, pending, service, copies)
    })
    .await;
    match service_members {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(SwapRefusal::new(
                SERVICE_JAR_MISMATCH,
                "the patch service's jar does not carry the record's patched members",
            ))
        }
        Err(JarError::TooLarge(why)) => {
            return Err(SwapRefusal::new(
                JAR_TOO_LARGE,
                format!(
                    "the patch service's build of {} cannot be checked against the installed \
                     jar: {why}. Nothing was written. `--mode hosted` does not read the jar.",
                    swap.jar_leaf
                ),
            ))
        }
        Err(JarError::Unreadable(why)) => {
            return Err(SwapRefusal::new(
                SERVICE_JAR_MISMATCH,
                format!("the patch service's jar cannot be read: {why}"),
            ))
        }
    };
    let mut pending = Vec::new();
    for ((i, original), difference) in originals.into_iter().zip(differences) {
        let path = Path::new(&results[i].package_path).join(swap.jar_leaf);
        let refusal = match difference {
            Ok(difference) => {
                if difference.is_empty() {
                    pending.push((i, original));
                    continue;
                }
                SwapRefusal::new(
                    SERVICE_JAR_MISMATCH,
                    format!(
                        "the patch service's jar differs from {} outside the patched members: \
                         {}. The two are not the same jar apart from the patch, so that copy \
                         was left as it is.",
                        path.display(),
                        difference.describe()
                    ),
                )
            }
            Err(JarError::TooLarge(why)) => SwapRefusal::new(
                JAR_TOO_LARGE,
                format!(
                    "{} cannot be checked against the patch service's jar: {why}. It was left \
                     as it is. `--mode hosted` does not read the jar.",
                    path.display()
                ),
            ),
            Err(JarError::Unreadable(why)) => {
                results[i].error = Some(format!("Cannot apply patch: {} - {why}", path.display()));
                continue;
            }
        };
        results[i].error = Some(format!("{}: {}", refusal.code, refusal.message));
        refusals.insert(i, refusal);
    }
    if swap.dry_run {
        for (i, _) in &pending {
            results[*i].success = true;
        }
        return Ok(results);
    }
    for (_, original) in &pending {
        write_backup(swap.socket_dir, original)
            .await
            .map_err(|e| SwapRefusal::new("jvm_jar_backup_failed", e))?;
    }

    let mut swapped: Vec<(usize, &Vec<u8>, Option<maven_sidecars::Snapshot>)> = Vec::new();
    for (i, original) in &pending {
        let dir = PathBuf::from(&results[*i].package_path);
        let pre = if maven_sidecars::is_gradle_hash_dir(&dir) {
            None
        } else {
            Some(maven_sidecars::snapshot(&dir, &[swap.jar_leaf.to_string()]).await)
        };
        match write_jar(&dir, swap.jar_leaf, &jar).await {
            Ok(note) => {
                results[*i].error = note;
                swapped.push((*i, original, pre));
            }
            Err(e) => {
                // Put every copy already swapped back, then fail them all:
                // a half-swapped GAV is worse than an unpatched one.
                let failed = dir.join(swap.jar_leaf);
                for (j, original, _) in &swapped {
                    let copy = PathBuf::from(&results[*j].package_path);
                    let restored = write_jar(&copy, swap.jar_leaf, original).await;
                    results[*j].error = Some(put_back_note(
                        &format!("writing {} failed", failed.display()),
                        restored,
                    ));
                }
                results[*i].error = Some(format!("{}: {e}", dir.join(swap.jar_leaf).display()));
                if maven_sidecars::is_locked_by_daemon(&e, &dir.join(swap.jar_leaf)) {
                    results[*i].sidecar = Some(sidecars::SidecarRecord {
                        purl: swap.purl.to_string(),
                        ecosystem: "maven".to_string(),
                        files: Vec::new(),
                        advisory: Some(maven_sidecars::locked_by_daemon_advisory(
                            &dir.join(swap.jar_leaf),
                        )),
                    });
                }
                return Ok(results);
            }
        }
    }
    let patched_keys: Vec<String> = files_in_order(swap.files)
        .into_iter()
        .map(|(k, _)| k.clone())
        .collect();
    for (i, original, pre) in swapped {
        let dir = PathBuf::from(&results[i].package_path);
        match sidecars::dispatch_fixup_with(
            swap.purl,
            &dir,
            &[swap.jar_leaf.to_string()],
            pre.as_ref(),
        )
        .await
        {
            Ok(record) => {
                results[i].success = true;
                results[i].files_patched = patched_keys.clone();
                results[i].sidecar = record;
            }
            // A copy whose checksum files could not follow the jar fails,
            // with the original jar (and what was already rewritten) put
            // back, as the generic engine does.
            Err(e) => {
                let restored = write_jar(&dir, swap.jar_leaf, original).await;
                if let Some(pre) = &pre {
                    let _ = maven_sidecars::resync(&dir, pre).await;
                }
                let message = put_back_note(&format!("sidecar fixup failed: {e}"), restored);
                results[i].error = Some(message.clone());
                results[i].sidecar = Some(sidecars::fixup_failed_record(swap.purl, message));
            }
        }
    }
    Ok(results)
}

/// What became of a copy that was written and then had to be put back
/// because of `why`: `restored` is the outcome of writing its previous jar
/// over it again. A copy that could not be put back says so; it still holds
/// the bytes the failed operation wrote.
fn put_back_note(why: &str, restored: std::io::Result<Option<String>>) -> String {
    match restored {
        Ok(_) => format!("rolled back: {why}"),
        Err(e) => format!("left changed: {why}, and putting the previous jar back failed: {e}"),
    }
}

// ── rollback ────────────────────────────────────────────────────────────

/// Where a rollback finds the original jar of a copy.
#[derive(Debug, Clone, Copy)]
pub struct JarRestore<'a> {
    pub purl: &'a str,
    pub jar_leaf: &'a str,
    pub files: &'a HashMap<String, PatchFileInfo>,
    pub socket_dir: &'a Path,
    pub dry_run: bool,
    /// Never contact the network (no upstream re-download).
    pub offline: bool,
}

/// The backups under [`ORIGINALS_DIR`], in name order.
fn backups(socket_dir: &Path) -> Vec<PathBuf> {
    let mut names: Vec<PathBuf> = std::fs::read_dir(socket_dir.join(ORIGINALS_DIR))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "jar"))
        .collect();
    names.sort();
    names
}

/// The backup of a Gradle copy: the one that hashes to the copy's hash
/// directory, which names the jar Gradle downloaded there, and holds the
/// record's members at their `beforeHash`. The patched copy is not read:
/// the directory says what its original is.
fn gradle_backup(
    socket_dir: &Path,
    dir: &Path,
    files: &HashMap<String, PatchFileInfo>,
) -> Option<Vec<u8>> {
    let hash = dir.file_name()?.to_str()?;
    backups(socket_dir).into_iter().find_map(|path| {
        let bytes = crate::utils::fs::read_regular_to_bytes_sync(&path).ok()?;
        (gradle_cache::hash_eq(hash, &sha1_hex(&bytes)) && members_at_before(&bytes, files))
            .then_some(bytes)
    })
}

/// What a `~/.m2` copy's original can be told from.
enum M2Original {
    /// The backup that is its original.
    Backup(Vec<u8>),
    /// No backup is; the copy's members, for judging an upstream jar.
    NoBackup(Digests),
    /// The copy cannot be compared with anything: why.
    Unread(JarError),
}

/// The backup of a `~/.m2` copy `current`, which nothing names: the one
/// that is its original ([`is_original_of`]). The copy is read first, and
/// once: one that cannot be compared has no original to look for.
fn m2_backup(
    socket_dir: &Path,
    current: &[u8],
    files: &HashMap<String, PatchFileInfo>,
) -> M2Original {
    let members = match Digests::of_bytes(current) {
        Ok(members) => members,
        Err(e) => return M2Original::Unread(e),
    };
    let found = backups(socket_dir).into_iter().find_map(|path| {
        let bytes = crate::utils::fs::read_regular_to_bytes_sync(&path).ok()?;
        is_original_of(&bytes, (current, &members), files).then_some(bytes)
    });
    match found {
        Some(bytes) => M2Original::Backup(bytes),
        None => M2Original::NoBackup(members),
    }
}

/// Whether `candidate` holds each record member at its `beforeHash` (a
/// member the patch adds, with an empty `beforeHash`, absent).
fn members_at_before(candidate: &[u8], files: &HashMap<String, PatchFileInfo>) -> bool {
    verify_member_bytes(candidate, files).iter().all(|v| {
        v.status == VerifyStatus::Ready
            && files
                .get(&v.file)
                .is_some_and(|i| v.current_hash.as_deref().unwrap_or("") == i.before_hash)
    })
}

/// Whether the jar `candidate` is the original of a patched copy whose
/// members are `patched_copy`: each record member at its `beforeHash` (a
/// member the patch adds, with an empty `beforeHash`, absent), and every
/// other member the patched copy's.
fn is_original_of(
    candidate: &[u8],
    patched_copy: (&[u8], &Digests),
    files: &HashMap<String, PatchFileInfo>,
) -> bool {
    members_at_before(candidate, files)
        && Digests::of_bytes(candidate).is_ok_and(|members| {
            difference_outside_patch((candidate, &members), patched_copy, files)
                .is_ok_and(|difference| difference.is_empty())
        })
}

/// The upstream jar of a Gradle copy, accepted only when it hashes to the
/// copy's hash-directory name (the sha1 Gradle verified when it downloaded
/// the pristine jar).
async fn upstream_for_gradle_copy(purl: &str, jar_leaf: &str, dir: &Path) -> Option<Vec<u8>> {
    let hash = dir.file_name()?.to_str()?;
    let (group, artifact, version) = parse_maven_purl(purl)?;
    let url = format!(
        "{}/{}/{jar_leaf}",
        crate::vendor::jvm::layout::registry_base(),
        crate::vendor::jvm::layout::version_dir(&group, &artifact, &version)
    );
    let bytes = crate::vendor::maven_repo::fetch_registry_bytes(
        &url,
        crate::vendor::registry_fetch::MAX_DOWNLOAD_BYTES,
    )
    .await
    .ok()?;
    gradle_cache::hash_eq(hash, &sha1_hex(&bytes)).then_some(bytes)
}

/// The upstream jar of a `~/.m2` copy, which no hash directory vouches
/// for: a registry download is accepted only when it matches the checksum
/// the registry publishes beside it (`.sha512`, else `.sha1`) and is the
/// original of the patched copy `current` ([`is_original_of`]: the record's
/// members at their `beforeHash`, every other member the copy's own). The
/// `.sha1` Maven wrote beside the jar cannot vouch for it: the swap rewrote
/// that file for the patched jar. `Err` says what was missing.
async fn upstream_for_m2_copy(
    restore: &JarRestore<'_>,
    current: Vec<u8>,
    members: Digests,
) -> (Vec<u8>, Result<Vec<u8>, String>) {
    let Some((group, artifact, version)) = parse_maven_purl(restore.purl) else {
        let why = "its purl names no Maven coordinates".to_string();
        return (current, Err(why));
    };
    let fetched = crate::vendor::maven_repo::verified_registry_file(
        &group,
        &artifact,
        &version,
        restore.jar_leaf,
    )
    .await;
    let bytes = match fetched {
        Ok(bytes) => bytes,
        Err(why) => return (current, Err(why)),
    };
    let files = restore.files.clone();
    let (current, bytes, original) = blocking(move || {
        let original = is_original_of(&bytes, (&current, &members), &files);
        (current, bytes, original)
    })
    .await;
    if !original {
        let why = format!(
            "the registry's {} is not the jar this copy was patched from",
            restore.jar_leaf
        );
        return (current, Err(why));
    }
    (current, Ok(bytes))
}

/// What to do about a copy with no original to restore: said with every
/// [`rollback_jar_swap`] failure for want of one.
fn recover_hint(dir: &Path) -> String {
    format!(
        "To recover, run the rollback from the project that applied the patch (its \
         .socket/{ORIGINALS_DIR} holds the original), or delete {} so the build downloads the \
         jar again.",
        dir.display()
    )
}

fn rollback_result(purl: &str, dir: &Path) -> RollbackResult {
    RollbackResult {
        package_key: purl.to_string(),
        package_path: dir.display().to_string(),
        success: false,
        files_verified: Vec::new(),
        files_rolled_back: Vec::new(),
        error: None,
        sidecar: None,
    }
}

fn rollback_verify(results: &[VerifyResult]) -> Vec<VerifyRollbackResult> {
    results
        .iter()
        .map(|v| VerifyRollbackResult {
            file: v.file.clone(),
            status: match v.status {
                VerifyStatus::AlreadyPatched => VerifyRollbackStatus::Ready,
                VerifyStatus::Ready => VerifyRollbackStatus::AlreadyOriginal,
                VerifyStatus::HashMismatch => VerifyRollbackStatus::HashMismatch,
                VerifyStatus::NotFound => VerifyRollbackStatus::NotFound,
            },
            message: v.message.clone(),
            current_hash: v.current_hash.clone(),
            expected_hash: v.target_hash.clone(),
            target_hash: None,
        })
        .collect()
}

/// Restore the original jar of every copy in `copies` that holds the
/// patched members: from its [`ORIGINALS_DIR`] backup, else, online, from
/// upstream: a Gradle copy when the download hashes to the copy's hash
/// directory, a `~/.m2` copy when it passes [`upstream_for_m2_copy`]. A
/// copy with neither fails with `jvm_jar_backup_missing`, says why and how
/// to recover, and is left as it is; so is a copy whose members match
/// neither side. A copy already original is a no-op. One result per copy.
pub async fn rollback_jar_swap(
    restore: &JarRestore<'_>,
    copies: &[PathBuf],
) -> Vec<RollbackResult> {
    let mut out = Vec::new();
    for dir in copies {
        let mut result = rollback_result(restore.purl, dir);
        let path = dir.join(restore.jar_leaf);
        let current = match crate::utils::fs::read_regular_to_bytes(&path).await {
            Ok(bytes) => bytes,
            Err(e) => {
                result.error = Some(format!("Cannot roll back: {} - {e}", path.display()));
                out.push(result);
                continue;
            }
        };
        // The bounded reader is the first thing to parse the copy: one past
        // the jar limits fails here, before any backup is read or anything
        // is downloaded.
        let verified = match member_statuses(&current, restore.files) {
            Ok(verified) => verified,
            Err(e) => {
                result.error = Some(format!(
                    "{JAR_TOO_LARGE}: {} cannot be read within the jar limits: {e}. It was \
                     left as it is; delete {} so the build downloads the jar again.",
                    path.display(),
                    dir.display()
                ));
                out.push(result);
                continue;
            }
        };
        result.files_verified = rollback_verify(&verified);
        let all = |s: VerifyStatus| verified.iter().all(|v| v.status == s);
        if all(VerifyStatus::Ready) {
            result.success = true;
            out.push(result);
            continue;
        }
        if !all(VerifyStatus::AlreadyPatched) {
            let bad = verified
                .iter()
                .find(|v| v.status != VerifyStatus::AlreadyPatched)
                .expect("a member that is not patched exists");
            result.error = Some(crate::patch::rollback::cannot_rollback_error(
                &bad.file,
                bad.message
                    .as_deref()
                    .unwrap_or("Jar member is neither patched nor original"),
            ));
            out.push(result);
            continue;
        }
        let gradle = maven_sidecars::is_gradle_hash_dir(dir);
        const OFFLINE: &str = "--offline prevents downloading it again";
        let (socket_dir, files) = (restore.socket_dir.to_path_buf(), restore.files.clone());
        // Why upstream could not stand in for a missing backup.
        let (current, original) = if gradle {
            let hash_dir = dir.clone();
            let found = blocking(move || gradle_backup(&socket_dir, &hash_dir, &files)).await;
            let original = match found {
                Some(bytes) => Ok(bytes),
                None if restore.offline => Err(OFFLINE.to_string()),
                None => upstream_for_gradle_copy(restore.purl, restore.jar_leaf, dir)
                    .await
                    .ok_or_else(|| "no upstream download matches its hash directory".to_string()),
            };
            (current, original)
        } else {
            // The copy is read before anything is looked for or downloaded:
            // one that cannot be compared has its own failure, not a
            // missing backup's.
            let (current, found) = blocking(move || {
                let found = m2_backup(&socket_dir, &current, &files);
                (current, found)
            })
            .await;
            let (current, original) = match found {
                M2Original::Backup(bytes) => (current, Ok(bytes)),
                M2Original::NoBackup(_) if restore.offline => (current, Err(OFFLINE.to_string())),
                M2Original::NoBackup(members) => {
                    upstream_for_m2_copy(restore, current, members).await
                }
                M2Original::Unread(e) => {
                    let delete = format!(
                        "It was left as it is; delete {} so the build downloads the jar again.",
                        dir.display()
                    );
                    result.error = Some(match e {
                        JarError::TooLarge(why) => format!(
                            "{JAR_TOO_LARGE}: {} holds this patch's members, but cannot be \
                             compared with a backup or with upstream: {why}. {delete}",
                            path.display()
                        ),
                        JarError::Unreadable(why) => {
                            format!("Cannot roll back: {} - {why}. {delete}", path.display())
                        }
                    });
                    out.push(result);
                    continue;
                }
            };
            (current, original)
        };
        let original = match original {
            Ok(bytes) => bytes,
            Err(why) => {
                result.error = Some(format!(
                    "jvm_jar_backup_missing: {} holds this patch, but {} has no backup of the \
                     original (another project or an earlier workspace applied it), and {why}. {}",
                    path.display(),
                    restore.socket_dir.join(ORIGINALS_DIR).display(),
                    recover_hint(dir)
                ));
                out.push(result);
                continue;
            }
        };
        if restore.dry_run {
            result.success = true;
            out.push(result);
            continue;
        }
        let pre = if gradle {
            None
        } else {
            Some(maven_sidecars::snapshot(dir, &[restore.jar_leaf.to_string()]).await)
        };
        match write_jar(dir, restore.jar_leaf, &original).await {
            Ok(note) => {
                let resynced = match pre.as_ref().filter(|p| !p.is_empty()) {
                    Some(pre) => maven_sidecars::resync(dir, pre).await,
                    None => Ok(Vec::new()),
                };
                match resynced {
                    Ok(files) => {
                        result.success = true;
                        result.error = note;
                        result.files_rolled_back = files_in_order(restore.files)
                            .into_iter()
                            .map(|(k, _)| k.clone())
                            .collect();
                        result.sidecar = (!files.is_empty()).then(|| sidecars::SidecarRecord {
                            purl: restore.purl.to_string(),
                            ecosystem: "maven".to_string(),
                            files,
                            advisory: None,
                        });
                    }
                    // The copy stays what its record says, patched: the
                    // patched jar goes back, and the checksum files with
                    // it (apply's twin).
                    Err(e) => {
                        let restored = write_jar(dir, restore.jar_leaf, &current).await;
                        if let Some(pre) = &pre {
                            let _ = maven_sidecars::resync(dir, pre).await;
                        }
                        let message =
                            put_back_note(&format!("sidecar resync failed: {e}"), restored);
                        result.error = Some(message.clone());
                        result.sidecar = Some(sidecars::fixup_failed_record(restore.purl, message));
                    }
                }
            }
            Err(e) => {
                result.error = Some(format!("{}: {e}", path.display()));
                if maven_sidecars::is_locked_by_daemon(&e, &path) {
                    result.sidecar = Some(sidecars::SidecarRecord {
                        purl: restore.purl.to_string(),
                        ecosystem: "maven".to_string(),
                        files: Vec::new(),
                        advisory: Some(maven_sidecars::locked_by_daemon_advisory(&path)),
                    });
                }
            }
        }
        out.push(result);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn jar(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, bytes) in members {
            out.start_file(*name, opts).unwrap();
            out.write_all(bytes).unwrap();
        }
        out.finish().unwrap().into_inner()
    }

    fn info(before: &[u8], after: &[u8]) -> PatchFileInfo {
        PatchFileInfo {
            before_hash: compute_git_sha256_from_bytes(before),
            after_hash: compute_git_sha256_from_bytes(after),
        }
    }

    const PURL: &str = "pkg:maven/com.example/lib@1.0";

    use crate::test_env::EnvGuard;

    fn record() -> HashMap<String, PatchFileInfo> {
        HashMap::from([(
            "META-INF/NOTICE.txt".to_string(),
            info(b"pristine", b"patched"),
        )])
    }

    fn pristine_jar() -> Vec<u8> {
        jar(&[("META-INF/NOTICE.txt", b"pristine"), ("a/B.class", b"code")])
    }

    fn patched_jar() -> Vec<u8> {
        jar(&[("META-INF/NOTICE.txt", b"patched"), ("a/B.class", b"code")])
    }

    #[test]
    fn classify_and_jar_leaf() {
        let leaf = HashMap::from([("package/lib-1.0.pom".to_string(), info(b"a", b"b"))]);
        assert_eq!(classify(PURL, &leaf), RecordShape::Leaf);
        assert_eq!(
            classify(PURL, &record()),
            RecordShape::Members {
                jar_leaf: "lib-1.0.jar".to_string()
            }
        );
        let top_class = HashMap::from([("Main.class".to_string(), info(b"a", b"b"))]);
        assert!(matches!(
            classify(PURL, &top_class),
            RecordShape::Members { .. }
        ));
        // Only Maven records can be member-keyed.
        let npm = HashMap::from([("package/lib/x.js".to_string(), info(b"a", b"b"))]);
        assert_eq!(classify("pkg:npm/x@1.0.0", &npm), RecordShape::Leaf);
        assert_eq!(
            jar_leaf("pkg:maven/com.example/lib@1.0?classifier=linux&ext=jar").as_deref(),
            Some("lib-1.0-linux.jar")
        );
        assert_eq!(
            jar_leaf("pkg:maven/com.example/lib@1.0?type=aar").as_deref(),
            Some("lib-1.0.aar")
        );
    }

    /// The explicit leaf is what is read: a hosted copy verifies under its
    /// suffixed jar name.
    #[tokio::test]
    async fn verify_members_with_explicit_leaf() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("lib-1.0-socket.0123abcd.jar"), patched_jar()).unwrap();
        std::fs::write(d.path().join("lib-1.0.jar"), pristine_jar()).unwrap();
        assert_eq!(
            verify_members(d.path(), "lib-1.0-socket.0123abcd.jar", &record()).await,
            VerifyStatus::AlreadyPatched
        );
        assert_eq!(
            verify_members(d.path(), "lib-1.0.jar", &record()).await,
            VerifyStatus::Ready
        );
        assert_eq!(
            verify_members(d.path(), "absent.jar", &record()).await,
            VerifyStatus::NotFound
        );
        std::fs::write(
            d.path().join("other.jar"),
            jar(&[("META-INF/NOTICE.txt", b"something else")]),
        )
        .unwrap();
        assert_eq!(
            verify_members(d.path(), "other.jar", &record()).await,
            VerifyStatus::HashMismatch
        );
    }

    fn swap<'a>(
        files: &'a HashMap<String, PatchFileInfo>,
        socket: &'a Path,
        dry_run: bool,
    ) -> JarSwap<'a> {
        JarSwap {
            purl: PURL,
            uuid: "11111111-1111-4111-8111-111111111111",
            jar_leaf: "lib-1.0.jar",
            files,
            socket_dir: socket,
            dry_run,
        }
    }

    /// Offline (or no service): refused before anything is written, the
    /// installed jar untouched and no backup made.
    #[tokio::test]
    async fn offline_refuses_with_nothing_written() {
        let d = tempfile::tempdir().unwrap();
        let socket = d.path().join(".socket");
        let copy = d.path().join("m2/com/example/lib/1.0");
        std::fs::create_dir_all(&copy).unwrap();
        std::fs::write(copy.join("lib-1.0.jar"), pristine_jar()).unwrap();
        let files = record();
        let cfg = VendorServiceConfig {
            maven_config: None,
            source: crate::vendor::VendorSource::default(),
            client: None,
            use_public_proxy: true,
            vendor_url: None,
            patch_server_url: None,
            patch_server_origins: Vec::new(),
            offline: true,
        };
        for service in [None, Some(&cfg)] {
            let err = apply_jar_swap(&swap(&files, &socket, false), &[copy.clone()], service)
                .await
                .unwrap_err();
            assert_eq!(err.code, "jvm_agent_service_required");
        }
        assert_eq!(
            std::fs::read(copy.join("lib-1.0.jar")).unwrap(),
            pristine_jar()
        );
        assert!(!socket.exists());
    }

    /// An already-patched copy needs no service at all.
    #[tokio::test]
    async fn already_patched_needs_no_service() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("lib-1.0.jar"), patched_jar()).unwrap();
        let files = record();
        let out = apply_jar_swap(
            &swap(&files, &d.path().join(".socket"), false),
            &[d.path().to_path_buf()],
            None,
        )
        .await
        .unwrap();
        assert!(out[0].success && out[0].files_patched.is_empty());
    }

    /// A patch service granting `uuid` and serving `served` under an SRI
    /// computed over `sri_of`, and a config pointing at it.
    async fn mock_service(
        served: &[u8],
        sri_of: &[u8],
    ) -> (wiremock::MockServer, VendorServiceConfig) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let uuid = "11111111-1111-4111-8111-111111111111";
        let sri = {
            use base64::Engine as _;
            use sha2::Digest as _;
            format!(
                "sha512-{}",
                base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(sri_of))
            )
        };
        let url = format!("{}/artifacts/{uuid}/lib-1.0.jar", server.uri());
        Mock::given(method("POST"))
            .and(path("/patch/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": { uuid: {
                    "status": "granted", "purl": PURL, "url": url,
                    "artifacts": [{ "kind": "tarball", "url": url, "integrity": { "sha512": sri } }]
                }}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/artifacts/{uuid}/lib-1.0.jar")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(served.to_vec()))
            .mount(&server)
            .await;
        let client = crate::api::client::ApiClient::new(crate::api::client::ApiClientOptions {
            api_url: server.uri(),
            api_token: None,
            route: crate::api::client::ApiRoute::Proxy,
        });
        let cfg = VendorServiceConfig {
            maven_config: None,
            source: crate::vendor::VendorSource::default(),
            client: Some(client),
            use_public_proxy: true,
            vendor_url: Some(server.uri()),
            patch_server_url: None,
            patch_server_origins: Vec::new(),
            offline: false,
        };
        (server, cfg)
    }

    /// The swap through a mocked patch service: the original is backed up
    /// under jvm-originals, the copy carries the service jar, a matching
    /// `.sha1` follows it; rollback restores both byte for byte.
    #[tokio::test]
    async fn swap_backs_up_and_rollback_is_byte_exact() {
        let service = patched_jar();
        let (_server, cfg) = mock_service(&service, &service).await;

        let d = tempfile::tempdir().unwrap();
        let socket = d.path().join(".socket");
        let copy = d.path().join("m2/com/example/lib/1.0");
        std::fs::create_dir_all(&copy).unwrap();
        let original = pristine_jar();
        std::fs::write(copy.join("lib-1.0.jar"), &original).unwrap();
        let sha1_text = format!("{}\n", sha1_hex(&original));
        std::fs::write(copy.join("lib-1.0.jar.sha1"), &sha1_text).unwrap();

        let files = record();
        let out = apply_jar_swap(&swap(&files, &socket, false), &[copy.clone()], Some(&cfg))
            .await
            .unwrap();
        assert!(out[0].success, "{:?}", out[0].error);
        assert_eq!(out[0].files_patched, ["META-INF/NOTICE.txt"]);
        assert_eq!(std::fs::read(copy.join("lib-1.0.jar")).unwrap(), service);
        assert_eq!(
            std::fs::read(backup_path(&socket, &original)).unwrap(),
            original
        );
        assert_eq!(
            std::fs::read_to_string(copy.join("lib-1.0.jar.sha1")).unwrap(),
            format!("{}\n", sha1_hex(&service))
        );

        let restore = JarRestore {
            purl: PURL,
            jar_leaf: "lib-1.0.jar",
            files: &files,
            socket_dir: &socket,
            dry_run: false,
            offline: true,
        };
        let back = rollback_jar_swap(&restore, &[copy.clone()]).await;
        assert!(back[0].success, "{:?}", back[0].error);
        assert_eq!(std::fs::read(copy.join("lib-1.0.jar")).unwrap(), original);
        assert_eq!(
            std::fs::read_to_string(copy.join("lib-1.0.jar.sha1")).unwrap(),
            sha1_text
        );
        // A second rollback is a no-op.
        let again = rollback_jar_swap(&restore, &[copy.clone()]).await;
        assert!(again[0].success && again[0].files_rolled_back.is_empty());
    }

    /// No backup: a ~/.m2 copy fails `jvm_jar_backup_missing` and is left
    /// as it is; a Gradle copy is re-downloaded from upstream and accepted
    /// only when the download hashes to its hash directory.
    #[tokio::test]
    #[serial_test::serial]
    async fn missing_backup_falls_back_to_verified_upstream_for_gradle() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let d = tempfile::tempdir().unwrap();
        let socket = d.path().join(".socket");
        let original = pristine_jar();
        let m2 = d.path().join("m2/com/example/lib/1.0");
        std::fs::create_dir_all(&m2).unwrap();
        std::fs::write(m2.join("lib-1.0.jar"), patched_jar()).unwrap();
        let version = d
            .path()
            .join(".gradle/caches/modules-2/files-2.1/com.example/lib/1.0");
        let hash_dir = version.join(sha1_hex(&original));
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(hash_dir.join("lib-1.0.jar"), patched_jar()).unwrap();

        let files = record();
        let mut restore = JarRestore {
            purl: PURL,
            jar_leaf: "lib-1.0.jar",
            files: &files,
            socket_dir: &socket,
            dry_run: false,
            offline: true,
        };
        let out = rollback_jar_swap(&restore, &[m2.clone(), hash_dir.clone()]).await;
        for r in &out {
            assert!(!r.success);
            assert!(r
                .error
                .as_deref()
                .unwrap()
                .starts_with("jvm_jar_backup_missing"));
        }
        assert_eq!(
            std::fs::read(hash_dir.join("lib-1.0.jar")).unwrap(),
            patched_jar()
        );

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/com/example/lib/1.0/lib-1.0.jar"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(original.clone()))
            .mount(&server)
            .await;
        let _registry = EnvGuard::set("SOCKET_MAVEN_REGISTRY", server.uri());
        restore.offline = false;
        let out = rollback_jar_swap(&restore, &[hash_dir.clone()]).await;
        assert!(out[0].success, "{:?}", out[0].error);
        assert_eq!(
            std::fs::read(hash_dir.join("lib-1.0.jar")).unwrap(),
            original
        );

        // A download that does not hash to the directory is refused.
        std::fs::write(hash_dir.join("lib-1.0.jar"), patched_jar()).unwrap();
        let wrong = version.join("0".repeat(40));
        std::fs::create_dir_all(&wrong).unwrap();
        std::fs::write(wrong.join("lib-1.0.jar"), patched_jar()).unwrap();
        let out = rollback_jar_swap(&restore, &[wrong.clone()]).await;
        assert!(!out[0].success);
        assert_eq!(
            std::fs::read(wrong.join("lib-1.0.jar")).unwrap(),
            patched_jar()
        );
    }

    /// A service jar that fails the integrity checks is refused before
    /// anything is written: (a) its patched member is not at `afterHash`,
    /// (b) a member the patch does not touch differs from the installed
    /// jar's, or one is added, (c) its bytes fail the grant's SRI.
    #[tokio::test]
    async fn tampered_service_jar_is_refused_with_nothing_written() {
        let altered = jar(&[("META-INF/NOTICE.txt", b"patched"), ("a/B.class", b"evil")]);
        let extra = jar(&[
            ("META-INF/NOTICE.txt", b"patched"),
            ("a/B.class", b"code"),
            ("a/Backdoor.class", b"evil"),
        ]);
        let wrong_after = jar(&[("META-INF/NOTICE.txt", b"other"), ("a/B.class", b"code")]);
        // An added class under symlink mode bits: a JVM loads it by name
        // whatever its mode, so it counts like any other member.
        let smuggled = crate::patch::jar_members::testing::jar_with_modes(&[
            ("META-INF/NOTICE.txt", b"patched", None),
            ("a/B.class", b"code", None),
            ("a/Backdoor.class", b"evil", Some(0o120777)),
        ]);
        // (served, sri over, whole-swap refusal code or the difference a
        // per-copy failure names)
        let cases: Vec<(Vec<u8>, Vec<u8>, Result<&str, &str>)> = vec![
            (
                wrong_after.clone(),
                wrong_after,
                Ok("jvm_agent_service_jar_mismatch"),
            ),
            (altered.clone(), altered, Err("1 changed (`a/B.class`)")),
            (extra.clone(), extra, Err("1 added (`a/Backdoor.class`)")),
            (
                smuggled.clone(),
                smuggled,
                Err("1 added (`a/Backdoor.class`)"),
            ),
            (
                patched_jar(),
                b"not the served bytes".to_vec(),
                Ok("jvm_agent_service_integrity"),
            ),
        ];
        for (served, sri_of, refusal) in cases {
            let (_server, cfg) = mock_service(&served, &sri_of).await;
            let d = tempfile::tempdir().unwrap();
            let socket = d.path().join(".socket");
            let copy = d.path().join("m2/com/example/lib/1.0");
            std::fs::create_dir_all(&copy).unwrap();
            std::fs::write(copy.join("lib-1.0.jar"), pristine_jar()).unwrap();
            let files = record();
            let out =
                apply_jar_swap(&swap(&files, &socket, false), &[copy.clone()], Some(&cfg)).await;
            match refusal {
                Ok(code) => assert_eq!(out.unwrap_err().code, code),
                Err(difference) => {
                    let out = out.unwrap();
                    assert!(!out[0].success);
                    let error = out[0].error.as_deref().unwrap();
                    // The copy's failure carries the contract's code and
                    // says which members differ.
                    assert_eq!(out[0].refusal.as_ref().unwrap().code, SERVICE_JAR_MISMATCH);
                    assert!(
                        error.starts_with(
                            "jvm_agent_service_jar_mismatch: the patch service's jar differs from "
                        ) && error.contains(&format!("outside the patched members: {difference}."))
                            && error.contains("lib-1.0.jar"),
                        "{error}"
                    );
                }
            }
            assert_eq!(
                std::fs::read(copy.join("lib-1.0.jar")).unwrap(),
                pristine_jar()
            );
            assert!(!socket.exists(), "no backup may be written");
        }
    }

    /// A record that ADDS a member (empty `beforeHash`) rolls back from its
    /// backup: the original, which lacks the member, is the right one.
    #[tokio::test]
    async fn added_member_rolls_back_from_backup() {
        let d = tempfile::tempdir().unwrap();
        let socket = d.path().join(".socket");
        let copy = d.path().join("m2/com/example/lib/1.0");
        std::fs::create_dir_all(&copy).unwrap();
        let original = pristine_jar();
        let patched = jar(&[
            ("META-INF/NOTICE.txt", b"patched"),
            ("a/B.class", b"code"),
            ("a/Helper.class", b"helper"),
        ]);
        std::fs::write(copy.join("lib-1.0.jar"), &patched).unwrap();
        let backup = backup_path(&socket, &original);
        std::fs::create_dir_all(backup.parent().unwrap()).unwrap();
        std::fs::write(&backup, &original).unwrap();
        let mut files = record();
        files.insert(
            "a/Helper.class".to_string(),
            PatchFileInfo {
                before_hash: String::new(),
                after_hash: compute_git_sha256_from_bytes(b"helper"),
            },
        );
        let restore = JarRestore {
            purl: PURL,
            jar_leaf: "lib-1.0.jar",
            files: &files,
            socket_dir: &socket,
            dry_run: false,
            offline: true,
        };
        let back = rollback_jar_swap(&restore, &[copy.clone()]).await;
        assert!(back[0].success, "{:?}", back[0].error);
        assert_eq!(std::fs::read(copy.join("lib-1.0.jar")).unwrap(), original);
    }

    fn restore<'a>(
        files: &'a HashMap<String, PatchFileInfo>,
        socket: &'a Path,
        offline: bool,
    ) -> JarRestore<'a> {
        JarRestore {
            purl: PURL,
            jar_leaf: "lib-1.0.jar",
            files,
            socket_dir: socket,
            dry_run: false,
            offline,
        }
    }

    /// A jar over both limits of the wheel reader the swap used to compare
    /// through (10,000 entries, 64 MiB inflated) is swapped and rolled back
    /// like any other. It used to be refused as "the patch service's jar is
    /// unreadable".
    #[tokio::test]
    async fn a_jar_over_the_wheel_reader_limits_swaps_and_rolls_back() {
        use crate::patch::jar_members::testing::big_jar;
        const ENTRIES: usize = 10_001;
        const BYTES: u64 = 65 * 1024 * 1024;
        let original = big_jar(ENTRIES, BYTES, &[("META-INF/NOTICE.txt", b"pristine")]);
        let service = big_jar(ENTRIES, BYTES, &[("META-INF/NOTICE.txt", b"patched")]);
        assert!(crate::vendor::verify::read_zip_bytes_to_map(&service).is_err());
        let (_server, cfg) = mock_service(&service, &service).await;

        let d = tempfile::tempdir().unwrap();
        let socket = d.path().join(".socket");
        let copy = d.path().join("m2/com/example/lib/1.0");
        std::fs::create_dir_all(&copy).unwrap();
        std::fs::write(copy.join("lib-1.0.jar"), &original).unwrap();
        let files = record();
        let out = apply_jar_swap(&swap(&files, &socket, false), &[copy.clone()], Some(&cfg))
            .await
            .unwrap();
        assert!(out[0].success, "{:?}", out[0].error);
        assert!(std::fs::read(copy.join("lib-1.0.jar")).unwrap() == service);

        let back = rollback_jar_swap(&restore(&files, &socket, true), &[copy.clone()]).await;
        assert!(back[0].success, "{:?}", back[0].error);
        assert!(std::fs::read(copy.join("lib-1.0.jar")).unwrap() == original);
    }

    /// A jar past the jar limits says which limit, and whose jar: the
    /// service's refuses the whole swap, an installed one fails its copy.
    /// Nothing is written either way.
    #[tokio::test]
    async fn a_jar_past_the_jar_limits_names_the_limit() {
        // 65 MiB of zeros deflates to a few kilobytes: over the 64 MiB a
        // small archive may inflate to.
        let bomb = |notice: &[u8], with_bomb: bool| {
            use std::io::Read as _;
            let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            out.start_file("META-INF/NOTICE.txt", opts).unwrap();
            out.write_all(notice).unwrap();
            out.start_file("a/B.class", opts).unwrap();
            out.write_all(b"code").unwrap();
            if with_bomb {
                out.start_file("a/zeros.bin", opts).unwrap();
                std::io::copy(&mut std::io::repeat(0).take(65 * 1024 * 1024), &mut out).unwrap();
            }
            out.finish().unwrap().into_inner()
        };
        let limit = "it inflates to more than 64 MiB, over 100 times its own size (1 MiB) and \
                     the 64 MiB every jar may use";
        let files = record();
        // (service jar, installed jar, whole-swap refusal?)
        for (service, installed, whole) in [
            (bomb(b"patched", true), bomb(b"pristine", true), true),
            (bomb(b"patched", false), bomb(b"pristine", true), false),
        ] {
            let (_server, cfg) = mock_service(&service, &service).await;
            let d = tempfile::tempdir().unwrap();
            let socket = d.path().join(".socket");
            let copy = d.path().join("m2/com/example/lib/1.0");
            std::fs::create_dir_all(&copy).unwrap();
            std::fs::write(copy.join("lib-1.0.jar"), &installed).unwrap();
            let out =
                apply_jar_swap(&swap(&files, &socket, false), &[copy.clone()], Some(&cfg)).await;
            if whole {
                let refusal = out.unwrap_err();
                assert_eq!(refusal.code, JAR_TOO_LARGE);
                assert!(
                    refusal.message.starts_with(
                        "the patch service's build of lib-1.0.jar cannot be checked against the \
                         installed jar: it inflates"
                    ) && refusal.message.contains(limit),
                    "{}",
                    refusal.message
                );
            } else {
                let out = out.unwrap();
                let error = out[0].error.as_deref().unwrap();
                assert!(!out[0].success);
                assert_eq!(out[0].refusal.as_ref().unwrap().code, JAR_TOO_LARGE);
                assert!(
                    error.contains("lib-1.0.jar cannot be checked against the patch service's jar")
                        && error.contains(limit),
                    "{error}"
                );
            }
            assert!(std::fs::read(copy.join("lib-1.0.jar")).unwrap() == installed);
            assert!(!socket.exists(), "no backup may be written");
        }
    }

    /// A registry serving `jar` at lib-1.0.jar with the `.sha1` of `summed`
    /// (`None`: it publishes no checksum).
    async fn registry(jar: &[u8], summed: Option<&[u8]>) -> wiremock::MockServer {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/com/example/lib/1.0/lib-1.0.jar"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(jar.to_vec()))
            .mount(&server)
            .await;
        if let Some(summed) = summed {
            Mock::given(method("GET"))
                .and(path("/com/example/lib/1.0/lib-1.0.jar.sha1"))
                .respond_with(ResponseTemplate::new(200).set_body_string(sha1_hex(summed)))
                .mount(&server)
                .await;
        }
        server
    }

    /// A `~/.m2` copy another project (or an earlier workspace) patched has
    /// no backup under this project's `.socket/`. Its rollback downloads the
    /// original, and takes it only when it matches the registry's checksum
    /// and is the jar the copy was patched from. The copy and its `.sha1`
    /// come back byte for byte.
    #[tokio::test]
    #[serial_test::serial]
    async fn an_m2_copy_patched_elsewhere_is_restored_from_verified_upstream() {
        let d = tempfile::tempdir().unwrap();
        let socket = d.path().join("second-project/.socket");
        let copy = d.path().join("m2/com/example/lib/1.0");
        std::fs::create_dir_all(&copy).unwrap();
        let (original, patched) = (pristine_jar(), patched_jar());
        // What the first project's apply left: the service jar and a
        // `.sha1` that describes it.
        let patch_copy = || {
            std::fs::write(copy.join("lib-1.0.jar"), &patched).unwrap();
            std::fs::write(copy.join("lib-1.0.jar.sha1"), sha1_hex(&patched)).unwrap();
        };
        let files = record();

        patch_copy();
        let server = registry(&original, Some(&original)).await;
        let _registry = EnvGuard::set("SOCKET_MAVEN_REGISTRY", server.uri());
        let back = rollback_jar_swap(&restore(&files, &socket, false), &[copy.clone()]).await;
        assert!(back[0].success, "{:?}", back[0].error);
        assert_eq!(back[0].files_rolled_back, ["META-INF/NOTICE.txt"]);
        assert_eq!(std::fs::read(copy.join("lib-1.0.jar")).unwrap(), original);
        assert_eq!(
            std::fs::read_to_string(copy.join("lib-1.0.jar.sha1")).unwrap(),
            sha1_hex(&original)
        );
        assert!(!socket.exists(), "a rollback writes no backup");
        drop(_registry);

        // Anything less leaves the copy as it is and says what to do.
        let other_base = jar(&[
            ("META-INF/NOTICE.txt", b"pristine"),
            ("a/B.class", b"other"),
        ]);
        let cases: Vec<(wiremock::MockServer, bool, &str)> = vec![
            (
                registry(&original, Some(b"some other bytes")).await,
                false,
                "the download does not match the registry's checksum",
            ),
            (
                registry(&original, None).await,
                false,
                "the registry publishes no checksum for it",
            ),
            (
                registry(&other_base, Some(&other_base)).await,
                false,
                "the registry's lib-1.0.jar is not the jar this copy was patched from",
            ),
            (
                // The patched jar itself is not its own original.
                registry(&patched, Some(&patched)).await,
                false,
                "the registry's lib-1.0.jar is not the jar this copy was patched from",
            ),
            (
                wiremock::MockServer::start().await,
                false,
                "the registry did not serve it",
            ),
            (
                registry(&original, Some(&original)).await,
                true,
                "--offline prevents downloading it again",
            ),
        ];
        for (server, offline, why) in cases {
            patch_copy();
            let _registry = EnvGuard::set("SOCKET_MAVEN_REGISTRY", server.uri());
            let back = rollback_jar_swap(&restore(&files, &socket, offline), &[copy.clone()]).await;
            let error = back[0].error.as_deref().unwrap();
            assert!(!back[0].success, "{why}");
            assert!(
                error.starts_with("jvm_jar_backup_missing: ")
                    && error.contains("has no backup of the original (another project or an earlier workspace applied it)")
                    && error.contains(why)
                    && error.contains("To recover, run the rollback from the project that applied the patch")
                    && error.contains(&format!("or delete {} so the build downloads the jar again", copy.display())),
                "{why}: {error}"
            );
            assert_eq!(std::fs::read(copy.join("lib-1.0.jar")).unwrap(), patched);
        }
    }

    /// A rollback reads the copy before it looks for anything. A `~/.m2`
    /// copy past the jar limits has that failure, not a missing backup's,
    /// and nothing is downloaded for it. A Gradle copy's hash directory
    /// names its original, so its backup is found without reading the copy.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_rollback_checks_the_copy_before_it_blames_a_missing_backup() {
        use std::io::Read as _;
        // The patched member, and 65 MiB of zeros deflated to kilobytes.
        let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zw.start_file("META-INF/NOTICE.txt", opts).unwrap();
        zw.write_all(b"patched").unwrap();
        zw.start_file("a/zeros.bin", opts).unwrap();
        std::io::copy(&mut std::io::repeat(0).take(65 * 1024 * 1024), &mut zw).unwrap();
        let oversized = zw.finish().unwrap().into_inner();
        let original = pristine_jar();
        let files = record();
        let server = wiremock::MockServer::start().await;
        let _registry = EnvGuard::set("SOCKET_MAVEN_REGISTRY", server.uri());

        let d = tempfile::tempdir().unwrap();
        let socket = d.path().join(".socket");
        write_backup(&socket, &original).await.unwrap();
        let m2 = d.path().join("m2/com/example/lib/1.0");
        std::fs::create_dir_all(&m2).unwrap();
        std::fs::write(m2.join("lib-1.0.jar"), &oversized).unwrap();
        let back = rollback_jar_swap(&restore(&files, &socket, false), &[m2.clone()]).await;
        let error = back[0].error.as_deref().unwrap();
        assert!(!back[0].success);
        assert!(
            error.starts_with("jvm_jar_too_large: ")
                && error.contains("cannot be compared with a backup or with upstream: it inflates")
                && error.contains(&format!("delete {} so the build", m2.display()))
                && !error.contains("has no backup"),
            "{error}"
        );
        assert!(std::fs::read(m2.join("lib-1.0.jar")).unwrap() == oversized);
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "nothing is downloaded for a copy that cannot be compared"
        );

        let hash_dir = d
            .path()
            .join(".gradle/caches/modules-2/files-2.1/com.example/lib/1.0")
            .join(sha1_hex(&original));
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(hash_dir.join("lib-1.0.jar"), &oversized).unwrap();
        let back = rollback_jar_swap(&restore(&files, &socket, true), &[hash_dir.clone()]).await;
        assert!(back[0].success, "{:?}", back[0].error);
        assert!(std::fs::read(hash_dir.join("lib-1.0.jar")).unwrap() == original);
    }

    /// A signed jar the patch service patched and re-signed differs from
    /// the installed one in its signature files and in the manifest digests
    /// of the member the patch changes. It is swapped in, and rolled back to
    /// the original from the backup. Any other manifest change stays the
    /// coded refusal, with its reason.
    #[tokio::test]
    async fn a_resigned_provider_jar_swaps_and_rolls_back() {
        use crate::patch::jar_manifest::fixture::{edited, record as resigned, SERVED, UPSTREAM};
        let files = resigned();
        let d = tempfile::tempdir().unwrap();
        let socket = d.path().join(".socket");
        let copy = d.path().join("m2/com/example/lib/1.0");
        std::fs::create_dir_all(&copy).unwrap();
        std::fs::write(copy.join("lib-1.0.jar"), UPSTREAM).unwrap();

        let tampered =
            edited(|m| m.replace("Implementation-Version: 1.0", "Implementation-Version: 9"));
        let (_server, cfg) = mock_service(&tampered, &tampered).await;
        let out = apply_jar_swap(&swap(&files, &socket, false), &[copy.clone()], Some(&cfg))
            .await
            .unwrap();
        let refusal = out[0].refusal.as_ref().expect("a coded refusal");
        assert_eq!(refusal.code, SERVICE_JAR_MISMATCH);
        assert!(
            refusal
                .message
                .contains("1 changed (`META-INF/MANIFEST.MF`)")
                && refusal.message.contains("its main attributes differ"),
            "{}",
            refusal.message
        );
        assert_eq!(std::fs::read(copy.join("lib-1.0.jar")).unwrap(), UPSTREAM);

        let (_server, cfg) = mock_service(SERVED, SERVED).await;
        let out = apply_jar_swap(&swap(&files, &socket, false), &[copy.clone()], Some(&cfg))
            .await
            .unwrap();
        assert!(out[0].success, "{:?}", out[0].error);
        assert_eq!(std::fs::read(copy.join("lib-1.0.jar")).unwrap(), SERVED);

        let back = rollback_jar_swap(&restore(&files, &socket, true), &[copy.clone()]).await;
        assert!(back[0].success, "{:?}", back[0].error);
        assert_eq!(std::fs::read(copy.join("lib-1.0.jar")).unwrap(), UPSTREAM);
    }

    /// The bounded reader is the first thing that parses a copy, on apply
    /// and on rollback. This archive's end records declare 200,001 entries
    /// and it holds no central directory at all: only a reader that holds
    /// the records to the limit before parsing can call it too large. The
    /// apply needs no service for it, and the rollback reads no backup and
    /// downloads nothing.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_copy_past_the_limits_is_refused_before_it_is_parsed() {
        // With bytes after its end records: the reader finds them all the same.
        let mut hostile = crate::patch::jar_members::testing::declares_entries(200_001, 0);
        hostile.extend_from_slice(&[0u8; 70_000]);
        let limit = "it holds 200001 entries, over the limit of 200000";
        let files = record();
        assert_eq!(
            member_statuses(&hostile, &files).unwrap_err().to_string(),
            limit
        );
        // The callers that only ask for statuses see nothing verified.
        assert_eq!(
            aggregate(&verify_member_bytes(&hostile, &files)),
            VerifyStatus::NotFound
        );

        let server = wiremock::MockServer::start().await;
        let _registry = EnvGuard::set("SOCKET_MAVEN_REGISTRY", server.uri());
        let d = tempfile::tempdir().unwrap();
        let socket = d.path().join(".socket");
        write_backup(&socket, &pristine_jar()).await.unwrap();
        let copy = d.path().join("m2/com/example/lib/1.0");
        std::fs::create_dir_all(&copy).unwrap();
        std::fs::write(copy.join("lib-1.0.jar"), &hostile).unwrap();

        let out = apply_jar_swap(&swap(&files, &socket, false), &[copy.clone()], None)
            .await
            .unwrap();
        let refusal = out[0].refusal.as_ref().expect("a coded refusal");
        assert_eq!(refusal.code, JAR_TOO_LARGE);
        assert!(refusal.message.contains(limit), "{}", refusal.message);
        assert!(!out[0].success);

        let back = rollback_jar_swap(&restore(&files, &socket, false), &[copy.clone()]).await;
        let error = back[0].error.as_deref().unwrap();
        assert!(
            !back[0].success
                && error.starts_with("jvm_jar_too_large: ")
                && error.contains(limit)
                && !error.contains("has no backup"),
            "{error}"
        );
        assert!(std::fs::read(copy.join("lib-1.0.jar")).unwrap() == hostile);
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "nothing is downloaded for a copy past the limits"
        );
    }

    /// A copy that holds another revision of the patch (applied from another
    /// project) is neither side of this record: the apply fails that copy
    /// and says what the bytes may be and how to get back to the original.
    #[tokio::test]
    async fn a_copy_holding_another_revision_says_how_to_recover() {
        let d = tempfile::tempdir().unwrap();
        let copy = d.path().join("m2/com/example/lib/1.0");
        std::fs::create_dir_all(&copy).unwrap();
        let other_revision = jar(&[
            ("META-INF/NOTICE.txt", b"an earlier revision"),
            ("a/B.class", b"code"),
        ]);
        std::fs::write(copy.join("lib-1.0.jar"), &other_revision).unwrap();
        let files = record();
        let out = apply_jar_swap(
            &swap(&files, &d.path().join(".socket"), false),
            &[copy.clone()],
            None,
        )
        .await
        .unwrap();
        let error = out[0].error.as_deref().unwrap();
        assert!(!out[0].success);
        assert!(
            error.starts_with("Cannot apply patch: META-INF/NOTICE.txt - Jar member hash does not match expected value. ")
                && error.contains("holds neither the original member nor this patch's")
                && error.contains("another revision of the patch may have been applied from another project or workspace")
                && error.contains(&format!("or delete {} so the build downloads the jar again, then apply", copy.display())),
            "{error}"
        );
        assert_eq!(
            std::fs::read(copy.join("lib-1.0.jar")).unwrap(),
            other_revision
        );
    }

    /// A large deflated member is verified by streaming it through the
    /// shared zip-member hasher: the verdict matches the buffered hash for
    /// both record states, and an absent member keeps its own status.
    #[test]
    fn verify_member_bytes_streams_a_large_deflated_member() {
        use std::io::Read as _;
        const SIZE: u64 = 16 * 1024 * 1024;
        let zeros_hash = crate::hash::git_sha256::compute_git_sha256_from_std_reader(
            SIZE,
            std::io::repeat(0).take(SIZE),
        )
        .unwrap();
        let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        out.start_file("big.bin", opts).unwrap();
        std::io::copy(&mut std::io::repeat(0).take(SIZE), &mut out).unwrap();
        out.start_file("a/B.class", opts).unwrap();
        out.write_all(b"code").unwrap();
        let bytes = out.finish().unwrap().into_inner();
        assert!((bytes.len() as u64) < SIZE / 100, "member must be deflated");

        let ready = HashMap::from([(
            "big.bin".to_string(),
            PatchFileInfo {
                before_hash: zeros_hash.clone(),
                after_hash: compute_git_sha256_from_bytes(b"patched"),
            },
        )]);
        let got = verify_member_bytes(&bytes, &ready);
        assert_eq!(got[0].status, VerifyStatus::Ready);
        assert_eq!(got[0].current_hash.as_deref(), Some(zeros_hash.as_str()));

        let applied = HashMap::from([(
            "big.bin".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(b"pristine"),
                after_hash: zeros_hash.clone(),
            },
        )]);
        assert_eq!(
            verify_member_bytes(&bytes, &applied)[0].status,
            VerifyStatus::AlreadyPatched
        );

        let absent = HashMap::from([("gone.bin".to_string(), info(b"x", b"y"))]);
        assert_eq!(
            verify_member_bytes(&bytes, &absent)[0].status,
            VerifyStatus::NotFound
        );
    }
}
