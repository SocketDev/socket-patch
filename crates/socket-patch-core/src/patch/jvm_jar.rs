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
//!   record's `afterHash`es and every other member must equal the installed
//!   jar's. The original jar is kept at
//!   `<.socket>/jvm-originals/<sha256>.jar` — outside `blobs/`, so no blob
//!   cleanup ever removes it — and [`rollback_jar_swap`] restores it byte
//!   for byte. A Gradle copy without a backup can still be restored from
//!   upstream: its hash directory names the pristine jar's sha1, so a
//!   download is accepted only when it hashes to exactly that.
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
use crate::patch::rollback::{RollbackResult, VerifyRollbackResult, VerifyRollbackStatus};
use crate::patch::sidecars::{self, maven as maven_sidecars};
use crate::utils::digest::{sha1_hex_of, sha256_hex_of};
use crate::utils::purl::{parse_maven_purl, purl_qualifier};
use crate::vendor::VendorServiceConfig;

/// Where original jars are kept, under the manifest's `.socket/` directory.
pub const ORIGINALS_DIR: &str = "jvm-originals";

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
/// every member `NotFound`.
pub fn verify_member_bytes(
    jar: &[u8],
    files: &HashMap<String, PatchFileInfo>,
) -> Vec<VerifyResult> {
    use std::io::Read as _;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(jar)).ok();
    files_in_order(files)
        .into_iter()
        .map(|(key, info)| {
            let member = normalize_file_path(key);
            let content = archive.as_mut().and_then(|a| {
                let mut entry = a.by_name(member).ok()?;
                // Not `with_capacity(entry.size())`: the size is the jar's own claim,
                // and a crafted one would abort the allocation.
                let mut buf = Vec::new();
                entry.read_to_end(&mut buf).ok()?;
                Some(buf)
            });
            let (status, current) = match content.map(|c| compute_git_sha256_from_bytes(&c)) {
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
        .map(|b| sha1_hex_of(&b));
    let written = std::fs::metadata(&jar).and_then(|m| m.modified()).ok();
    let unverified = found
        .unknown
        .into_iter()
        .filter(|p| {
            let Ok(copy) = crate::utils::fs::read_regular_to_bytes_sync(p) else {
                return true;
            };
            if Some(sha1_hex_of(&copy)) == current {
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
    }
}

/// The members of a jar other than `patched` and signature files, for the
/// "everything else is upstream's" comparison.
fn unpatched_members(
    jar: &[u8],
    patched: &HashMap<String, PatchFileInfo>,
) -> Result<HashMap<String, Vec<u8>>, String> {
    let keys: Vec<&str> = patched.keys().map(|k| normalize_file_path(k)).collect();
    let mut members = crate::vendor::verify::read_zip_bytes_to_map(jar)?;
    members.retain(|name, _| {
        !keys.contains(&name.as_str()) && !crate::vendor::jvm::is_signature(name)
    });
    Ok(members)
}

/// `<socket_dir>/jvm-originals/<sha256>.jar`.
pub fn backup_path(socket_dir: &Path, original: &[u8]) -> PathBuf {
    socket_dir
        .join(ORIGINALS_DIR)
        .join(format!("{}.jar", sha256_hex_of(original)))
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
        result.files_verified = verify_member_bytes(&original, swap.files);
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
                result.error = Some(format!(
                    "Cannot apply patch: {} - {}",
                    bad.file,
                    bad.message.clone().unwrap_or_default()
                ));
            }
        }
        results.push(result);
    }
    if pending.is_empty() {
        return Ok(results);
    }

    let jar = service_jar(service, swap.uuid).await?;
    if !crate::vendor::common::zip_bytes_match_after_hashes(&jar, swap.files) {
        return Err(SwapRefusal::new(
            "jvm_agent_service_jar_mismatch",
            "the patch service's jar does not carry the record's patched members",
        ));
    }
    let service_rest = unpatched_members(&jar, swap.files).map_err(|e| {
        SwapRefusal::new(
            "jvm_agent_service_jar_mismatch",
            format!("the patch service's jar is unreadable: {e}"),
        )
    })?;
    // Per copy: everything the patch does not touch must be upstream's.
    pending.retain(|(i, original)| {
        let same =
            unpatched_members(original, swap.files).is_ok_and(|members| members == service_rest);
        if !same {
            results[*i].error = Some(format!(
                "Cannot apply patch: {} - the patch service's jar differs from the installed jar \
                 outside the patched members",
                swap.jar_leaf
            ));
        }
        same
    });
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
                for (j, original, _) in &swapped {
                    let dir = PathBuf::from(&results[*j].package_path);
                    let _ = write_jar(&dir, swap.jar_leaf, original).await;
                    results[*j].error = Some(format!(
                        "rolled back: writing {} failed",
                        dir.join(swap.jar_leaf).display()
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
    for (i, _, pre) in swapped {
        let dir = PathBuf::from(&results[i].package_path);
        results[i].success = true;
        results[i].files_patched = patched_keys.clone();
        results[i].sidecar = match sidecars::dispatch_fixup_with(
            swap.purl,
            &dir,
            &[swap.jar_leaf.to_string()],
            pre.as_ref(),
        )
        .await
        {
            Ok(record) => record,
            Err(e) => Some(sidecars::fixup_failed_record(
                swap.purl,
                format!("sidecar fixup failed (patch still applied): {e}"),
            )),
        };
    }
    Ok(results)
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

/// The backup under [`ORIGINALS_DIR`] that is the original of `current` (a
/// patched copy): its record members at their `beforeHash`, every other
/// member equal to `current`'s, and — for a Gradle hash dir — hashing to the
/// directory's name. Backups are tried in name order.
async fn find_backup(restore: &JarRestore<'_>, dir: &Path, current: &[u8]) -> Option<Vec<u8>> {
    let rest = unpatched_members(current, restore.files).ok()?;
    let gradle_hash = maven_sidecars::is_gradle_hash_dir(dir)
        .then(|| dir.file_name()?.to_str().map(str::to_string))
        .flatten();
    let mut names: Vec<PathBuf> = std::fs::read_dir(restore.socket_dir.join(ORIGINALS_DIR))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "jar"))
        .collect();
    names.sort();
    for path in names {
        let Ok(bytes) = crate::utils::fs::read_regular_to_bytes(&path).await else {
            continue;
        };
        if let Some(hash) = &gradle_hash {
            if !gradle_cache::hash_eq(hash, &sha1_hex_of(&bytes)) {
                continue;
            }
        }
        // Each member at its `beforeHash`; a member the patch adds (empty
        // `beforeHash`) must be absent from the original.
        let originals = verify_member_bytes(&bytes, restore.files);
        if originals.iter().all(|v| {
            v.status == VerifyStatus::Ready
                && restore
                    .files
                    .get(&v.file)
                    .is_some_and(|i| v.current_hash.as_deref().unwrap_or("") == i.before_hash)
        }) && unpatched_members(&bytes, restore.files).is_ok_and(|m| m == rest)
        {
            return Some(bytes);
        }
    }
    None
}

/// The upstream jar of a Gradle copy, accepted only when it hashes to the
/// copy's hash-directory name (the sha1 Gradle verified when it downloaded
/// the pristine jar).
async fn upstream_for_gradle_copy(purl: &str, jar_leaf: &str, dir: &Path) -> Option<Vec<u8>> {
    let hash = dir.file_name()?.to_str()?;
    let (group, artifact, version) = parse_maven_purl(purl)?;
    let url = format!(
        "{}/{}/{artifact}/{version}/{jar_leaf}",
        crate::vendor::maven_repo::maven_registry_base(),
        group.replace('.', "/")
    );
    let bytes = crate::vendor::maven_repo::fetch_registry_bytes(
        &url,
        crate::vendor::registry_fetch::MAX_DOWNLOAD_BYTES,
    )
    .await
    .ok()?;
    gradle_cache::hash_eq(hash, &sha1_hex_of(&bytes)).then_some(bytes)
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
/// patched members: from its [`ORIGINALS_DIR`] backup, else — for a Gradle
/// copy, online — from upstream when the download hashes to the copy's hash
/// directory. A copy with neither fails with `jvm_jar_backup_missing` and
/// is left as it is; so is a copy whose members match neither side. A copy
/// already original is a no-op. One result per copy.
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
        let verified = verify_member_bytes(&current, restore.files);
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
        let original = match find_backup(restore, dir, &current).await {
            Some(bytes) => Some(bytes),
            None if gradle && !restore.offline => {
                upstream_for_gradle_copy(restore.purl, restore.jar_leaf, dir).await
            }
            None => None,
        };
        let Some(original) = original else {
            result.error = Some(format!(
                "jvm_jar_backup_missing: no original of {} under {} (and {})",
                path.display(),
                restore.socket_dir.join(ORIGINALS_DIR).display(),
                if gradle && restore.offline {
                    "--offline prevents re-downloading it"
                } else if gradle {
                    "no upstream download matches its hash directory"
                } else {
                    "a ~/.m2 copy cannot be re-downloaded and verified"
                }
            ));
            out.push(result);
            continue;
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
                result.success = true;
                result.error = note;
                result.files_rolled_back = files_in_order(restore.files)
                    .into_iter()
                    .map(|(k, _)| k.clone())
                    .collect();
                if let Some(pre) = pre.filter(|p| !p.is_empty()) {
                    result.sidecar = match maven_sidecars::resync(dir, &pre).await {
                        Ok(files) if files.is_empty() => None,
                        Ok(files) => Some(sidecars::SidecarRecord {
                            purl: restore.purl.to_string(),
                            ecosystem: "maven".to_string(),
                            files,
                            advisory: None,
                        }),
                        Err(e) => Some(sidecars::fixup_failed_record(
                            restore.purl,
                            format!("sidecar resync failed (rollback still applied): {e}"),
                        )),
                    };
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

    /// Save/restore guard for env-var tests; every user is
    /// `#[serial_test::serial]`.
    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }
    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let prev = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, prev }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

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
            use_public_proxy: true,
            org_slug: None,
        });
        let cfg = VendorServiceConfig {
            maven_config: None,
            source: crate::vendor::VendorSource::default(),
            client: Some(client),
            use_public_proxy: true,
            vendor_url: Some(server.uri()),
            patch_server_url: None,
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
        let sha1_text = format!("{}\n", sha1_hex_of(&original));
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
            format!("{}\n", sha1_hex_of(&service))
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
        let hash_dir = version.join(sha1_hex_of(&original));
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
        let _registry = EnvGuard::set("SOCKET_MAVEN_REGISTRY", &server.uri());
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
        // (served, sri over, whole-swap refusal code or None for a per-copy error)
        let cases: Vec<(Vec<u8>, Vec<u8>, Option<&str>)> = vec![
            (
                wrong_after.clone(),
                wrong_after,
                Some("jvm_agent_service_jar_mismatch"),
            ),
            (altered.clone(), altered, None),
            (extra.clone(), extra, None),
            (
                patched_jar(),
                b"not the served bytes".to_vec(),
                Some("jvm_agent_service_integrity"),
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
                Some(code) => assert_eq!(out.unwrap_err().code, code),
                None => {
                    let out = out.unwrap();
                    assert!(!out[0].success);
                    assert!(
                        out[0]
                            .error
                            .as_deref()
                            .unwrap()
                            .contains("differs from the installed jar"),
                        "{:?}",
                        out[0].error
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
}
