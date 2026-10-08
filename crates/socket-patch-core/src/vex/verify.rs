//! On-disk verification: which manifest entries are actually applied?
//!
//! A patch is "applied" iff every file the manifest claims it modified
//! currently hashes to its `afterHash`. Anything else — missing file,
//! hash mismatch, even one file ahead of expectations — disqualifies
//! the patch from the VEX document. Callers feed the failures into a
//! stderr warning + `--json` envelope warning list; the spec we agreed
//! on is "never emit `affected` or `under_investigation` — just omit".
//!
//! The CLI is responsible for resolving PURL → on-disk package path
//! (it already does this for `apply` / `scan` via the ecosystem
//! dispatcher). We accept a pre-built map so this module stays free of
//! ecosystem-crawler dependencies.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::crawlers::Ecosystem;
use crate::manifest::schema::{PatchManifest, PatchRecord};
use crate::patch::apply::{verify_file_patch, VerifyStatus};
use crate::vendor::state::{lookup_entry, VendorEntry};
use crate::vendor::verify::{
    is_vlt_dir_entry, verify_vendored_patch_record, vlt_installed_copy_matches,
};

/// One entry per manifest PURL that did NOT pass verification. The
/// `reason` is a short snake_case tag the CLI can route on (matches
/// the `error_code` convention used by `json_envelope::PatchEvent`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedPatch {
    pub purl: String,
    pub reason: String,
}

/// Result of partitioning the manifest into applied vs failed sets.
#[derive(Debug, Clone, Default)]
pub struct VerifyOutcome {
    /// PURLs whose on-disk files all hash to their `afterHash`.
    pub applied: Vec<String>,
    /// PURLs whose verification failed (with a routing tag).
    pub failed: Vec<FailedPatch>,
    /// The subset of `applied` that was attested via the committed
    /// vendor artifact (`.socket/vendor/…`) rather than the installed
    /// tree. Every member is also present in `applied`.
    pub vendored: Vec<String>,
    /// The subset of `vendored` whose INSTALLED tree is present on disk
    /// but does NOT hash to the record's `afterHash` (pristine-unpatched,
    /// tampered, or a missing file). The attestation itself is unaffected —
    /// the committed artifact + lock wiring is the product the lockfile
    /// consumes — but callers must disclose the drift: a build that
    /// bypasses the vendor wiring runs unpatched code until the package
    /// manager re-installs. An ABSENT installed tree is the expected
    /// post-vendor state and is never flagged.
    pub vendored_out_of_sync: Vec<String>,
    /// Maven / Gradle: `(purl, copy)` for every installed copy of a failed
    /// purl that does not verify — the copy a build may still load
    /// unpatched. Callers name them (`vex_gradle_unpatched_copy`).
    pub unpatched_copies: Vec<(String, PathBuf)>,
}

/// Vendored-patch context for [`applied_patches_with_vendor`].
///
/// Built by the CLI from the committed `.socket/vendor/state.json` ledger
/// (plus the legacy `.socket/go-patches/` redirect synthesis); kept as plain
/// data so this module stays free of state-loading concerns.
#[derive(Debug, Clone, Default)]
pub struct VendorContext {
    /// Project root the vendor artifact paths are relative to.
    pub project_root: PathBuf,
    /// Vendor-state entries, keyed by manifest PURL (a manifest PURL also
    /// matches an entry whose `base_purl` equals it — qualified manifest
    /// keys resolve to the entry recorded under the base PURL).
    pub entries: HashMap<String, VendorEntry>,
    /// Legacy `apply`-redirect copies: PURL → absolute
    /// `.socket/go-patches/<module>@<version>` copy dir. These are verified
    /// with the ordinary dir-hash check (NOT the vendor artifact check —
    /// their paths live outside `.socket/vendor/`) and count as `applied`
    /// but not `vendored`.
    pub go_patches: HashMap<String, PathBuf>,
    /// Hosted-wiring evidence: PURL → the installed copies the BUILD
    /// consumes through its hosted (Socket patch server) wiring, resolved by
    /// the caller per package manager. When present for a PURL it REPLACES
    /// the crawler's `package_paths` entry — see [`HostedCopies`].
    pub hosted: HashMap<String, HostedCopies>,
}

/// The installed copies a hosted-wired PURL's build consumes — the CLI
/// resolves them per package manager, because a crawler's "first copy of
/// `name@version`" is not always one the build reads:
///
/// * a DISTINCT-STORE ecosystem keeps the hosted artifact apart from the
///   registry's copy of the same `name@version` — Go's replacement module
///   `patch.socket.dev/gopatch/<uuid>@<sver>`, cargo's per-registry
///   `registry/src/<host>-<hash>/`, maven's `<base>-socket.<hex8>` version
///   dir — so the registry copy (e.g. cached before the redirect) is a
///   PRISTINE SIBLING the build never reads: it is left out, never reported
///   as "unpatched";
/// * a SHARED-LOCATION ecosystem installs hosted and registry bytes at one
///   path (`node_modules`, site-packages, gem homes), so a pristine copy
///   there IS what runs — and when the crawler finds several, each may be
///   the one some consumer loads, so every one is listed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostedCopies {
    /// Every consumed copy found. EMPTY means none is installed yet: the
    /// PURL is `package_not_found` (which the not-installed lockfile basis
    /// may excuse) — never judged against a pristine sibling. Non-empty:
    /// EVERY copy must verify, the first failure's tag wins.
    pub paths: Vec<PathBuf>,
    /// Maven's suffixed version renames the artifact files: the record's
    /// `<artifactId>-<base>…` file names are found as
    /// `<artifactId>-<base>-socket.<hex8>…` in the consumed dir. `(from, to)`
    /// file-name prefix rewrite, applied to the record's keys.
    pub rename: Option<(String, String)>,
}

/// Walk the manifest and bucket each PURL into `applied` / `failed`.
///
/// `package_paths` is the CLI-supplied `purl -> on-disk package dir`
/// map (the CLI's `find_manifest_package_paths`). A PURL absent from the map is
/// recorded as `package_not_found` and ends up in `failed`.
pub async fn applied_patches(
    manifest: &PatchManifest,
    package_paths: &HashMap<String, PathBuf>,
) -> VerifyOutcome {
    applied_patches_with_vendor(manifest, package_paths, None).await
}

/// [`applied_patches`] with vendored-patch awareness.
///
/// Per-PURL precedence:
/// 1. A vendor-state entry (matched by map key or `base_purl`) means the
///    committed artifact is the SOLE evidence: success lands the PURL in
///    both `applied` and `vendored`; failure lands it in `failed` with the
///    vendor routing tag. There is deliberately no fallback to the
///    installed tree in either direction — an unpatched `node_modules` is
///    EXPECTED after vendoring and must not block attestation, and a
///    patched-looking installed tree must not launder a tampered vendor
///    artifact.
/// 2. A `go_patches` entry verifies the redirect copy dir with the normal
///    dir-hash check (`applied` only, not `vendored`); again no fallback —
///    an active redirect makes the copy dir the consumed bytes, while the
///    module cache stays pristine by design.
/// 3. A `hosted` entry verifies exactly the copies the hosted build consumes
///    ([`HostedCopies`]) — no fallback to `package_paths` either, whose
///    representative may be the pristine sibling the build never reads.
/// 4. Otherwise the installed tree, judged as [`applied_patches_with_copies`]
///    judges it.
///
/// `package_paths` carries ONE representative copy per PURL; see
/// [`applied_patches_with_copies`] for the every-copy form `vex` uses.
pub async fn applied_patches_with_vendor(
    manifest: &PatchManifest,
    package_paths: &HashMap<String, PathBuf>,
    vendor: Option<&VendorContext>,
) -> VerifyOutcome {
    let copies: HashMap<String, Vec<PathBuf>> = package_paths
        .iter()
        .map(|(purl, path)| (purl.clone(), vec![path.clone()]))
        .collect();
    applied_patches_with_copies(manifest, &copies, vendor).await
}

/// [`applied_patches_with_vendor`] over EVERY installed copy the crawler
/// found per PURL (crawl order), not one representative.
///
/// `apply` patches every physical copy (npm nests genuine duplicates of one
/// `name@version`), and any copy may be the one some dependent loads — so an
/// installed-tree record is applied only when EVERY copy verifies; the
/// first failing copy's tag wins, exactly like [`HostedCopies`]. Judging the
/// first copy alone would attest `not_affected` while a later install's
/// fresh, unpatched nested copy runs. An empty copy list is
/// `package_not_found`. The vendored drift probe likewise flags the PURL
/// when ANY installed copy is out of sync.
///
/// Maven: a copy is the `~/.m2` version dir or a Gradle `files-2.1`
/// version dir (expanded into its hash dirs), and a member-keyed record is
/// checked against the jar's members. Every failing Maven copy (not just
/// the first) lands in [`VerifyOutcome::unpatched_copies`] — the caller
/// lists only the copies some build consumes.
pub async fn applied_patches_with_copies(
    manifest: &PatchManifest,
    package_copies: &HashMap<String, Vec<PathBuf>>,
    vendor: Option<&VendorContext>,
) -> VerifyOutcome {
    let mut out = VerifyOutcome::default();

    for (purl, record) in &manifest.patches {
        let vendor_entry =
            vendor.and_then(|ctx| lookup_entry(&ctx.entries, purl).map(|e| (ctx, e)));
        let result = if let Some((ctx, entry)) = vendor_entry {
            verify_vendored_patch_record(&ctx.project_root, entry, record).await
        } else if let Some(copy_dir) = vendor.and_then(|ctx| ctx.go_patches.get(purl)) {
            verify_patch_record(copy_dir, record).await
        } else if let Some(copies) = vendor.and_then(|ctx| ctx.hosted.get(purl)) {
            verify_hosted_copies(purl, copies, record).await
        } else if let Some(paths) = package_copies.get(purl).filter(|p| !p.is_empty()) {
            if Ecosystem::from_purl(purl) == Some(Ecosystem::Maven) {
                let mut first_failure = None;
                for copy in paths {
                    if let Err(reason) = verify_patch_record_for(purl, copy, record).await {
                        out.unpatched_copies.push((purl.clone(), copy.clone()));
                        first_failure.get_or_insert(reason);
                    }
                }
                first_failure.map_or(Ok(()), Err)
            } else {
                verify_every_copy(paths, record).await
            }
        } else {
            Err("package_not_found".to_string())
        };

        match result {
            Ok(()) => {
                out.applied.push(purl.clone());
                if let Some((ctx, entry)) = vendor_entry {
                    out.vendored.push(purl.clone());
                    // Disclosure probe: with the vendor artifact healthy,
                    // also check whether the LIVE installed tree (when the
                    // crawler found one) carries the patch. Any mismatch is
                    // recorded in `vendored_out_of_sync` for the caller to
                    // warn about — it never changes the verdict, because
                    // there is deliberately no installed-tree fallback in
                    // either direction (see the precedence note above).
                    //
                    // Go is exempt: a directory `replace` makes the
                    // committed copy the only bytes any build of this
                    // module reads, and the module-cache `M@v` the crawler
                    // finds is immutable, go.sum-verified and therefore
                    // pristine BY CONSTRUCTION — its "drift" is no
                    // bypassing build, and "re-run your install to resync
                    // it" is advice no `go` command can follow.
                    //
                    // So is a Gradle `files-2.1` copy: a vendored Gradle
                    // build resolves the GAV from the committed repository
                    // only (exclusiveContent), so the cache copy is a
                    // pristine sibling the build never reads.
                    let go_cache_copy = Ecosystem::from_purl(purl) == Some(Ecosystem::Golang);
                    let installed = package_copies
                        .get(purl)
                        .filter(|_| !go_cache_copy)
                        .map(Vec::as_slice)
                        .unwrap_or_default()
                        .iter()
                        .filter(|p| !crate::crawlers::gradle_cache::is_gradle_version_dir(p));
                    for pkg_path in installed {
                        let in_sync = if is_vlt_dir_entry(entry) {
                            vlt_installed_copy_matches(&ctx.project_root, pkg_path, entry, record)
                                .await
                        } else {
                            verify_patch_record_for(purl, pkg_path, record)
                                .await
                                .is_ok()
                        };
                        if !in_sync {
                            out.vendored_out_of_sync.push(purl.clone());
                            break;
                        }
                    }
                }
            }
            Err(reason) => out.failed.push(FailedPatch {
                purl: purl.clone(),
                reason,
            }),
        }
    }

    out
}

/// Returns `Ok(())` if every file in `record.files` is `AlreadyPatched`.
/// Otherwise returns a short routing tag describing the first failure.
///
/// A record with **no files** is *not* treated as applied. Verification
/// is the strict counterpart to `--no-verify`: it must produce positive
/// on-disk evidence before a patch is attested as `not_affected`. A
/// zero-file record offers nothing to hash, so — per the module's
/// "omit when unconfirmed" contract — it is reported as `no_files` and
/// dropped from the VEX document rather than vacuously attested.
///
/// `pub`: this is the reference "is this installed tree patched?" oracle
/// (all-files-AlreadyPatched + zero-file semantics); `vendor::pypi` calls it
/// directly. The CLI's gem/python stale-install probes use its one-pass
/// equivalent [`judge_installed_record`], which
/// `judge_installed_record_matches_verify_and_evidence_scan` pins to it.
///
/// A Gradle `files-2.1` version dir is expanded through
/// [`installed_copies`](crate::crawlers::gradle_cache::installed_copies):
/// every hash directory holding a record file must verify.
pub async fn verify_patch_record(pkg_path: &Path, record: &PatchRecord) -> Result<(), String> {
    if record.files.is_empty() {
        return Err("no_files".to_string());
    }
    for (dir, files) in crate::crawlers::gradle_cache::installed_copies(pkg_path, &record.files) {
        let mut keys: Vec<&String> = files.keys().collect();
        keys.sort();
        for file_name in keys {
            let result = verify_file_patch(&dir, file_name, &files[file_name]).await;
            status_verdict(result.status)?;
        }
    }
    Ok(())
}

/// The routing tag of a non-`AlreadyPatched` file status.
fn status_verdict(status: VerifyStatus) -> Result<(), String> {
    match status {
        VerifyStatus::AlreadyPatched => Ok(()),
        VerifyStatus::Ready => Err("not_applied".to_string()),
        VerifyStatus::HashMismatch => Err("hash_mismatch".to_string()),
        VerifyStatus::NotFound => Err("file_not_found".to_string()),
    }
}

/// [`verify_patch_record`] for a record of `purl`: a member-keyed Maven
/// record ([`jvm_jar::classify`](crate::patch::jvm_jar::classify)) is
/// checked against the members of every copy of its jar under `pkg_path`
/// (each Gradle hash dir holding it, or the `~/.m2` version dir).
pub async fn verify_patch_record_for(
    purl: &str,
    pkg_path: &Path,
    record: &PatchRecord,
) -> Result<(), String> {
    use crate::patch::jvm_jar::{self, RecordShape};
    match jvm_jar::classify(purl, &record.files) {
        RecordShape::Members { jar_leaf } => {
            verify_member_copies(pkg_path, &jar_leaf, record).await
        }
        RecordShape::Leaf => verify_patch_record(pkg_path, record).await,
    }
}

/// Every copy of `jar_leaf` under `pkg_path` must carry the record's
/// patched members; no copy at all is `file_not_found`.
async fn verify_member_copies(
    pkg_path: &Path,
    jar_leaf: &str,
    record: &PatchRecord,
) -> Result<(), String> {
    use crate::patch::jvm_jar;
    if record.files.is_empty() {
        return Err("no_files".to_string());
    }
    let copies = jvm_jar::jar_copies(pkg_path, jar_leaf);
    if copies.is_empty() {
        return Err("file_not_found".to_string());
    }
    for dir in copies {
        status_verdict(jvm_jar::verify_members(&dir, jar_leaf, &record.files).await)?;
    }
    Ok(())
}

/// What one pass over an installed copy's record files proves: the
/// [`verify_patch_record`] verdict plus the stale-install probes' POSITIVE
/// staleness evidence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InstalledRecordJudgment {
    /// [`verify_patch_record`] would return `Ok`: the record has files and
    /// every one hashes to its `afterHash`.
    pub patched: bool,
    /// At least one record file was actually read and hashed to something
    /// other than its `afterHash` (`verify_file_patch`'s `Ready` or
    /// `HashMismatch` WITH a `current_hash`). Missing, unreadable and
    /// unsafe-path files are never evidence.
    pub stale_evidence: bool,
}

/// [`verify_patch_record`] and the stale-evidence scan in ONE blocking-pool
/// task, hashing each record file at most once. Stops at the
/// first file that proves staleness — which also settles `patched` —
/// exactly where both scans agree.
///
/// A Gradle `files-2.1` version dir is judged in every hash directory
/// holding a record file ([`installed_copies`]): patched only when every
/// copy is, stale when any copy proves it.
///
/// [`installed_copies`]: crate::crawlers::gradle_cache::installed_copies
pub async fn judge_installed_record(
    pkg_path: &Path,
    record: &PatchRecord,
) -> InstalledRecordJudgment {
    let copies: Vec<(PathBuf, Vec<(String, String)>)> =
        crate::crawlers::gradle_cache::installed_copies(pkg_path, &record.files)
            .into_iter()
            .map(|(dir, files)| {
                let files = files
                    .into_iter()
                    .map(|(name, info)| (name, info.after_hash))
                    .collect();
                (dir, files)
            })
            .collect();
    let has_files = !record.files.is_empty();
    crate::utils::fs::run_blocking(move || {
        let mut out = InstalledRecordJudgment {
            patched: has_files,
            stale_evidence: false,
        };
        for (dir, files) in &copies {
            let judged = judge_installed_files(dir, files);
            if judged.stale_evidence {
                return judged;
            }
            out.patched &= judged.patched;
        }
        out
    })
    .await
}

fn judge_installed_files(pkg_path: &Path, files: &[(String, String)]) -> InstalledRecordJudgment {
    use crate::patch::apply::{is_safe_relative_subpath, normalize_file_path};
    use crate::patch::file_hash::compute_file_git_sha256_sync;

    let mut all_patched = !files.is_empty();
    for (file_name, after_hash) in files {
        let normalized = normalize_file_path(file_name);
        // An unsafe key never resolves (verify_file_patch's NotFound).
        let hashed = is_safe_relative_subpath(normalized)
            .then(|| compute_file_git_sha256_sync(&pkg_path.join(normalized)).ok())
            .flatten();
        match hashed {
            Some(hash) if &hash == after_hash => {}
            Some(_) => {
                return InstalledRecordJudgment {
                    patched: false,
                    stale_evidence: true,
                }
            }
            None => all_patched = false,
        }
    }
    InstalledRecordJudgment {
        patched: all_patched,
        stale_evidence: false,
    }
}

/// Every copy must pass [`verify_patch_record`]; the first failure's tag
/// wins. The caller guarantees `paths` is non-empty.
async fn verify_every_copy(paths: &[PathBuf], record: &PatchRecord) -> Result<(), String> {
    for path in paths {
        verify_patch_record(path, record).await?;
    }
    Ok(())
}

/// [`HostedCopies`] verdict: no consumed copy is `package_not_found`; every
/// listed copy must pass [`verify_patch_record`] (under the maven file
/// rename, when set — a Gradle version dir expanded into its hash dirs),
/// the first failure's tag wins. A member-keyed Maven record is checked
/// against the members of the jar under its RENAMED (suffixed) name.
async fn verify_hosted_copies(
    purl: &str,
    copies: &HostedCopies,
    record: &PatchRecord,
) -> Result<(), String> {
    use crate::patch::jvm_jar::{self, RecordShape};
    if copies.paths.is_empty() {
        return Err("package_not_found".to_string());
    }
    if let RecordShape::Members { jar_leaf } = jvm_jar::classify(purl, &record.files) {
        let jar_leaf = match &copies.rename {
            Some((from, to)) => rename_leaf(&jar_leaf, from, to),
            None => jar_leaf,
        };
        for path in &copies.paths {
            verify_member_copies(path, &jar_leaf, record).await?;
        }
        return Ok(());
    }
    let renamed;
    let record = match &copies.rename {
        Some((from, to)) => {
            renamed = rename_record_files(record, from, to);
            &renamed
        }
        None => record,
    };
    verify_every_copy(&copies.paths, record).await
}

/// Whether `rest` (what follows a matched `from` prefix) starts a new name
/// component: a classifier (`-`) or an extension (`.` not followed by a
/// digit, so `lib-1.0` + `.1.jar` is a different version).
fn whole_component(rest: &str) -> bool {
    rest.starts_with('-')
        || rest
            .strip_prefix('.')
            .is_some_and(|ext| !ext.is_empty() && !ext.starts_with(|c: char| c.is_ascii_digit()))
}

/// `name` re-prefixed `to` when it starts with the whole component `from`.
fn rename_leaf(name: &str, from: &str, to: &str) -> String {
    match name.strip_prefix(from).filter(|rest| whole_component(rest)) {
        Some(rest) => format!("{to}{rest}"),
        None => name.to_string(),
    }
}

/// `record` with every file key whose name starts with the whole component
/// `from` — followed by `-` (a classifier) or by a `.` that opens an
/// extension, not a version continuation (`lib-1.0` + `.jar`, never
/// `lib-1.0` + `.1.jar`) — re-prefixed `to`; other keys are kept as they
/// are (and so still verify as-is).
fn rename_record_files(record: &PatchRecord, from: &str, to: &str) -> PatchRecord {
    let mut renamed = record.clone();
    renamed.files = record
        .files
        .iter()
        .map(|(key, info)| {
            // An API key's `package/` prefix is kept around the renamed name.
            let (prefix, name) = match key.strip_prefix("package/") {
                Some(name) => ("package/", name),
                None => ("", key.as_str()),
            };
            (
                format!("{prefix}{}", rename_leaf(name, from, to)),
                info.clone(),
            )
        })
        .collect();
    renamed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::{PatchFileInfo, PatchRecord};
    use std::collections::HashMap;

    fn record_with_one_file(after_hash: &str) -> PatchRecord {
        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash: "aaaa".to_string(),
                after_hash: after_hash.to_string(),
            },
        );
        PatchRecord {
            uuid: "u".to_string(),
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            files,
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    #[tokio::test]
    async fn applied_when_all_files_match_after_hash() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let patched = b"patched-content";
        let hash = compute_git_sha256_from_bytes(patched);
        tokio::fs::write(pkg_dir.path().join("index.js"), patched)
            .await
            .unwrap();

        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert("pkg:npm/x@1.0.0".to_string(), record_with_one_file(&hash));

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/x@1.0.0".to_string(), pkg_dir.path().to_path_buf());

        let out = applied_patches(&manifest, &paths).await;
        assert_eq!(out.applied, vec!["pkg:npm/x@1.0.0".to_string()]);
        assert!(out.failed.is_empty());
    }

    /// Two nested copies of one `name@version`: `(dir, bytes)` each.
    async fn two_copies(a: &[u8], b: &[u8]) -> (tempfile::TempDir, Vec<PathBuf>) {
        let root = tempfile::tempdir().unwrap();
        let mut paths = Vec::new();
        for (i, bytes) in [a, b].into_iter().enumerate() {
            let dir = root.path().join(format!("copy{i}"));
            tokio::fs::create_dir_all(&dir).await.unwrap();
            tokio::fs::write(dir.join("index.js"), bytes).await.unwrap();
            paths.push(dir);
        }
        (root, paths)
    }

    /// Regression (#516): an installed-tree record verifies only when EVERY
    /// copy does, whichever copy the crawler met first; the unpatched
    /// copy's tag is reported.
    #[tokio::test]
    async fn every_installed_copy_must_verify() {
        let patched = b"patched-content";
        let pristine = b"pristine-content";
        let hash = compute_git_sha256_from_bytes(patched);
        let mut record = record_with_one_file(&hash);
        record.files.get_mut("index.js").unwrap().before_hash =
            compute_git_sha256_from_bytes(pristine);
        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert("pkg:npm/x@1.0.0".to_string(), record);

        for (a, b) in [(&patched[..], &pristine[..]), (&pristine[..], &patched[..])] {
            let (_root, paths) = two_copies(a, b).await;
            let copies = HashMap::from([("pkg:npm/x@1.0.0".to_string(), paths)]);
            let out = applied_patches_with_copies(&manifest, &copies, None).await;
            assert!(
                out.applied.is_empty(),
                "a pristine copy must block attestation"
            );
            assert_eq!(out.failed[0].reason, "not_applied");
        }

        let (_root, paths) = two_copies(patched, patched).await;
        let copies = HashMap::from([("pkg:npm/x@1.0.0".to_string(), paths)]);
        let out = applied_patches_with_copies(&manifest, &copies, None).await;
        assert_eq!(out.applied, vec!["pkg:npm/x@1.0.0".to_string()]);
        assert!(out.failed.is_empty());
    }

    /// An empty copy list is `package_not_found`, never a vacuous pass.
    #[tokio::test]
    async fn empty_copy_list_is_package_not_found() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record_with_one_file("deadbeef"),
        );
        let copies = HashMap::from([("pkg:npm/x@1.0.0".to_string(), Vec::new())]);
        let out = applied_patches_with_copies(&manifest, &copies, None).await;
        assert!(out.applied.is_empty());
        assert_eq!(out.failed[0].reason, "package_not_found");
    }

    #[tokio::test]
    async fn missing_path_falls_into_failed() {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record_with_one_file("deadbeef"),
        );

        let paths: HashMap<String, PathBuf> = HashMap::new();
        let out = applied_patches(&manifest, &paths).await;
        assert!(out.applied.is_empty());
        assert_eq!(out.failed.len(), 1);
        assert_eq!(out.failed[0].reason, "package_not_found");
    }

    #[tokio::test]
    async fn hash_mismatch_falls_into_failed() {
        let pkg_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(pkg_dir.path().join("index.js"), b"not the right content")
            .await
            .unwrap();

        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record_with_one_file(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
        );

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/x@1.0.0".to_string(), pkg_dir.path().to_path_buf());

        let out = applied_patches(&manifest, &paths).await;
        assert!(out.applied.is_empty());
        assert_eq!(out.failed[0].reason, "hash_mismatch");
    }

    #[tokio::test]
    async fn missing_file_falls_into_failed() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record_with_one_file(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
        );

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/x@1.0.0".to_string(), pkg_dir.path().to_path_buf());

        let out = applied_patches(&manifest, &paths).await;
        assert_eq!(out.failed[0].reason, "file_not_found");
    }

    #[tokio::test]
    async fn partial_apply_still_fails() {
        // Two files in the patch: only one is patched on disk → patch
        // is not "fully" applied → reported as failed (not_applied for
        // the second file).
        let pkg_dir = tempfile::tempdir().unwrap();
        let patched_a = b"AAA";
        let hash_a = compute_git_sha256_from_bytes(patched_a);
        let original_b = b"original-b";
        let before_b = compute_git_sha256_from_bytes(original_b);

        tokio::fs::write(pkg_dir.path().join("a.js"), patched_a)
            .await
            .unwrap();
        tokio::fs::write(pkg_dir.path().join("b.js"), original_b)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "a.js".to_string(),
            PatchFileInfo {
                before_hash: "aaaa".to_string(),
                after_hash: hash_a,
            },
        );
        files.insert(
            "b.js".to_string(),
            PatchFileInfo {
                before_hash: before_b,
                after_hash: "deadbeef".to_string(),
            },
        );

        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            PatchRecord {
                uuid: "u".to_string(),
                exported_at: String::new(),
                files,
                vulnerabilities: HashMap::new(),
                description: String::new(),
                license: String::new(),
                tier: String::new(),
            },
        );

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/x@1.0.0".to_string(), pkg_dir.path().to_path_buf());

        let out = applied_patches(&manifest, &paths).await;
        assert!(out.applied.is_empty());
        assert_eq!(out.failed[0].reason, "not_applied");
    }

    // ── Edge-case + degenerate-input coverage ─────────────────────

    /// `VerifyOutcome::default()` is the empty outcome — defaulting
    /// is used by the CLI's `--no-verify` path.
    #[test]
    fn outcome_default_is_empty() {
        let o = VerifyOutcome::default();
        assert!(o.applied.is_empty());
        assert!(o.failed.is_empty());
        assert!(o.vendored.is_empty());
        assert!(o.vendored_out_of_sync.is_empty());
    }

    /// `FailedPatch` equality + clone for downstream consumers
    /// (the CLI emits these in `--json` warnings).
    #[test]
    fn failed_patch_value_semantics() {
        let a = FailedPatch {
            purl: "pkg:npm/x@1".to_string(),
            reason: "hash_mismatch".to_string(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    /// Empty manifest → empty outcome. No iteration, no panic.
    #[tokio::test]
    async fn empty_manifest_returns_empty_outcome() {
        let manifest = PatchManifest::new();
        let paths: HashMap<String, PathBuf> = HashMap::new();
        let out = applied_patches(&manifest, &paths).await;
        assert!(out.applied.is_empty());
        assert!(out.failed.is_empty());
    }

    /// A patch with `files = {}` must NOT be treated as applied.
    /// Verification requires positive on-disk evidence before a patch
    /// is attested as `not_affected`; a zero-file record offers nothing
    /// to hash, so it is omitted with reason `no_files`. Attesting it as
    /// "fixed" would be an evidence-free claim, contradicting the
    /// module's "omit when unconfirmed" contract. (The `--no-verify`
    /// path, which trusts the manifest wholesale, is unaffected — it
    /// never calls this function.)
    #[tokio::test]
    async fn patch_record_with_zero_files_is_not_applied() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/empty@1.0.0".to_string(),
            PatchRecord {
                uuid: "u".to_string(),
                exported_at: String::new(),
                files: HashMap::new(),
                vulnerabilities: HashMap::new(),
                description: String::new(),
                license: String::new(),
                tier: String::new(),
            },
        );

        let mut paths = HashMap::new();
        paths.insert(
            "pkg:npm/empty@1.0.0".to_string(),
            pkg_dir.path().to_path_buf(),
        );

        let out = applied_patches(&manifest, &paths).await;
        assert!(
            out.applied.is_empty(),
            "a zero-file patch must not be attested as applied"
        );
        assert_eq!(out.failed.len(), 1);
        assert_eq!(out.failed[0].purl, "pkg:npm/empty@1.0.0");
        assert_eq!(out.failed[0].reason, "no_files");
    }

    /// Extra `package_paths` entries that aren't in the manifest
    /// are ignored — we iterate manifest entries, not the map.
    #[tokio::test]
    async fn extra_package_paths_are_ignored() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let patched = b"patched";
        let hash = compute_git_sha256_from_bytes(patched);
        tokio::fs::write(pkg_dir.path().join("index.js"), patched)
            .await
            .unwrap();

        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert("pkg:npm/x@1.0.0".to_string(), record_with_one_file(&hash));

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/x@1.0.0".to_string(), pkg_dir.path().to_path_buf());
        // Stray entry not in the manifest.
        paths.insert(
            "pkg:npm/stray@9.9.9".to_string(),
            pkg_dir.path().to_path_buf(),
        );

        let out = applied_patches(&manifest, &paths).await;
        assert_eq!(out.applied.len(), 1);
        assert_eq!(out.applied[0], "pkg:npm/x@1.0.0");
        assert!(out.failed.is_empty());
    }

    /// Multi-file patch where the FIRST file fails — the iteration
    /// halts after the first failure (we don't keep going to
    /// surface every reason). Lock this in so future refactors
    /// don't accidentally start running the second file's check.
    ///
    /// The patch lists two files. `a.js` has the wrong content (no
    /// match for before_hash or after_hash); `b.js` is fine. Order
    /// is non-deterministic across HashMap iteration, so we only
    /// assert "one failure reason", not which one.
    #[tokio::test]
    async fn multi_file_first_failure_short_circuits() {
        let pkg_dir = tempfile::tempdir().unwrap();
        // a.js: corrupt
        tokio::fs::write(pkg_dir.path().join("a.js"), b"garbage")
            .await
            .unwrap();
        // b.js: at the right after_hash so it would pass.
        let patched_b = b"patched-b";
        let hash_b = compute_git_sha256_from_bytes(patched_b);
        tokio::fs::write(pkg_dir.path().join("b.js"), patched_b)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "a.js".to_string(),
            PatchFileInfo {
                before_hash: "aaaa".to_string(),
                after_hash: "deadbeef".to_string(),
            },
        );
        files.insert(
            "b.js".to_string(),
            PatchFileInfo {
                before_hash: "cccc".to_string(),
                after_hash: hash_b,
            },
        );

        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            PatchRecord {
                uuid: "u".to_string(),
                exported_at: String::new(),
                files,
                vulnerabilities: HashMap::new(),
                description: String::new(),
                license: String::new(),
                tier: String::new(),
            },
        );

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/x@1.0.0".to_string(), pkg_dir.path().to_path_buf());

        let out = applied_patches(&manifest, &paths).await;
        assert!(out.applied.is_empty());
        assert_eq!(out.failed.len(), 1, "first failure must short-circuit");
        // Reason depends on iteration order, but it MUST be one of
        // the two failure tags (not the success path).
        let reason = &out.failed[0].reason;
        assert!(
            matches!(reason.as_str(), "hash_mismatch" | "not_applied"),
            "unexpected reason: {reason}"
        );
    }

    /// A new-file patch (empty `beforeHash`) whose file exists on disk
    /// at the `afterHash` content counts as applied. `verify_file_patch`
    /// returns `AlreadyPatched` before its is-new-file `Ready` branch, so
    /// the created-and-applied case is not misreported as `not_applied`.
    #[tokio::test]
    async fn new_file_present_at_after_hash_is_applied() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let created = b"freshly-created-file";
        let hash = compute_git_sha256_from_bytes(created);
        tokio::fs::write(pkg_dir.path().join("new.js"), created)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "new.js".to_string(),
            PatchFileInfo {
                before_hash: String::new(), // new file
                after_hash: hash,
            },
        );

        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            PatchRecord {
                uuid: "u".to_string(),
                exported_at: String::new(),
                files,
                vulnerabilities: HashMap::new(),
                description: String::new(),
                license: String::new(),
                tier: String::new(),
            },
        );

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/x@1.0.0".to_string(), pkg_dir.path().to_path_buf());

        let out = applied_patches(&manifest, &paths).await;
        assert_eq!(out.applied, vec!["pkg:npm/x@1.0.0".to_string()]);
        assert!(out.failed.is_empty());
    }

    /// A new-file patch whose file is absent on disk is `not_applied`
    /// (the creation hasn't happened yet) — NOT `file_not_found`. The
    /// empty `beforeHash` routes through the `Ready` branch.
    #[tokio::test]
    async fn new_file_absent_is_not_applied() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let mut files = HashMap::new();
        files.insert(
            "new.js".to_string(),
            PatchFileInfo {
                before_hash: String::new(), // new file, not yet created
                after_hash: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    .to_string(),
            },
        );

        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            PatchRecord {
                uuid: "u".to_string(),
                exported_at: String::new(),
                files,
                vulnerabilities: HashMap::new(),
                description: String::new(),
                license: String::new(),
                tier: String::new(),
            },
        );

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/x@1.0.0".to_string(), pkg_dir.path().to_path_buf());

        let out = applied_patches(&manifest, &paths).await;
        assert!(out.applied.is_empty());
        assert_eq!(out.failed[0].reason, "not_applied");
    }

    /// A no-op patch where `beforeHash == afterHash` and the file is at
    /// that content is applied — `verify_file_patch` checks `afterHash`
    /// first, so it never mistakes the file for the un-patched `Ready`
    /// state.
    #[tokio::test]
    async fn noop_patch_before_equals_after_is_applied() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let content = b"unchanged-content";
        let hash = compute_git_sha256_from_bytes(content);
        tokio::fs::write(pkg_dir.path().join("index.js"), content)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash: hash.clone(),
                after_hash: hash,
            },
        );

        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            PatchRecord {
                uuid: "u".to_string(),
                exported_at: String::new(),
                files,
                vulnerabilities: HashMap::new(),
                description: String::new(),
                license: String::new(),
                tier: String::new(),
            },
        );

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/x@1.0.0".to_string(), pkg_dir.path().to_path_buf());

        let out = applied_patches(&manifest, &paths).await;
        assert_eq!(out.applied, vec!["pkg:npm/x@1.0.0".to_string()]);
        assert!(out.failed.is_empty());
    }

    /// A multi-file patch where EVERY file is at its `afterHash` is
    /// applied — the loop must run to completion (no early `Ok`) and
    /// bucket the PURL into `applied`.
    #[tokio::test]
    async fn multi_file_all_patched_is_applied() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let a = b"patched-a";
        let b = b"patched-b";
        let hash_a = compute_git_sha256_from_bytes(a);
        let hash_b = compute_git_sha256_from_bytes(b);
        tokio::fs::write(pkg_dir.path().join("a.js"), a)
            .await
            .unwrap();
        tokio::fs::write(pkg_dir.path().join("b.js"), b)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "a.js".to_string(),
            PatchFileInfo {
                before_hash: "aaaa".to_string(),
                after_hash: hash_a,
            },
        );
        files.insert(
            "b.js".to_string(),
            PatchFileInfo {
                before_hash: "bbbb".to_string(),
                after_hash: hash_b,
            },
        );

        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            PatchRecord {
                uuid: "u".to_string(),
                exported_at: String::new(),
                files,
                vulnerabilities: HashMap::new(),
                description: String::new(),
                license: String::new(),
                tier: String::new(),
            },
        );

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/x@1.0.0".to_string(), pkg_dir.path().to_path_buf());

        let out = applied_patches(&manifest, &paths).await;
        assert_eq!(out.applied, vec!["pkg:npm/x@1.0.0".to_string()]);
        assert!(out.failed.is_empty());
    }

    /// A manifest with both an applied PURL and a failing PURL splits
    /// cleanly across the two buckets. Order is HashMap-nondeterministic,
    /// so we assert membership, not index.
    #[tokio::test]
    async fn mixed_manifest_splits_into_both_buckets() {
        let ok_dir = tempfile::tempdir().unwrap();
        let patched = b"patched-content";
        let hash = compute_git_sha256_from_bytes(patched);
        tokio::fs::write(ok_dir.path().join("index.js"), patched)
            .await
            .unwrap();

        // Failing package: file present but at the wrong content.
        let bad_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(bad_dir.path().join("index.js"), b"wrong")
            .await
            .unwrap();

        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert("pkg:npm/ok@1.0.0".to_string(), record_with_one_file(&hash));
        manifest.patches.insert(
            "pkg:npm/bad@1.0.0".to_string(),
            record_with_one_file(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
        );

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/ok@1.0.0".to_string(), ok_dir.path().to_path_buf());
        paths.insert(
            "pkg:npm/bad@1.0.0".to_string(),
            bad_dir.path().to_path_buf(),
        );

        let out = applied_patches(&manifest, &paths).await;
        assert_eq!(out.applied, vec!["pkg:npm/ok@1.0.0".to_string()]);
        assert_eq!(out.failed.len(), 1);
        assert_eq!(out.failed[0].purl, "pkg:npm/bad@1.0.0");
        assert_eq!(out.failed[0].reason, "hash_mismatch");
    }

    /// SECURITY: a path-escaping manifest key (`../evil.js`) must NEVER
    /// be attested as applied — even when the out-of-tree file it points
    /// at happens to hash to the record's `afterHash`. `verify_file_patch`
    /// fail-closes on the `is_safe_relative_subpath` guard *before* reading
    /// anything, so a poisoned manifest cannot launder an arbitrary
    /// on-disk file into a `not_affected` VEX attestation.
    #[tokio::test]
    async fn path_escaping_key_is_never_applied() {
        let root = tempfile::tempdir().unwrap();
        let pkg_dir = root.path().join("pkg");
        tokio::fs::create_dir(&pkg_dir).await.unwrap();

        // An out-of-tree file whose content matches the after_hash we
        // will claim. If the guard were missing, verification would read
        // this and wrongly report the patch as applied.
        let out_of_tree = b"out-of-tree-content";
        let hash = compute_git_sha256_from_bytes(out_of_tree);
        tokio::fs::write(root.path().join("evil.js"), out_of_tree)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "../evil.js".to_string(),
            PatchFileInfo {
                before_hash: "aaaa".to_string(),
                after_hash: hash, // matches the out-of-tree file
            },
        );

        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            PatchRecord {
                uuid: "u".to_string(),
                exported_at: String::new(),
                files,
                vulnerabilities: HashMap::new(),
                description: String::new(),
                license: String::new(),
                tier: String::new(),
            },
        );

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/x@1.0.0".to_string(), pkg_dir.clone());

        let out = applied_patches(&manifest, &paths).await;
        assert!(
            out.applied.is_empty(),
            "a path-escaping key must never be attested as applied"
        );
        assert_eq!(out.failed.len(), 1);
        assert_eq!(out.failed[0].reason, "file_not_found");
    }

    /// A directory sitting where the manifest expects a file is reported
    /// as `file_not_found`, not applied — `verify_file_patch` rejects
    /// non-regular files (the hashing step refuses to read a directory).
    #[tokio::test]
    async fn directory_at_file_path_is_not_applied() {
        let pkg_dir = tempfile::tempdir().unwrap();
        // Create a directory named "index.js" where a file is expected.
        tokio::fs::create_dir(pkg_dir.path().join("index.js"))
            .await
            .unwrap();

        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            record_with_one_file(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
        );

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/x@1.0.0".to_string(), pkg_dir.path().to_path_buf());

        let out = applied_patches(&manifest, &paths).await;
        assert!(out.applied.is_empty());
        assert_eq!(out.failed.len(), 1);
        assert_eq!(out.failed[0].reason, "file_not_found");
    }

    /// Two independently failing PURLs each produce exactly one
    /// `FailedPatch` — the failed bucket accumulates across PURLs (one
    /// failure per PURL, not collapsed or duplicated).
    #[tokio::test]
    async fn multiple_failing_purls_each_recorded() {
        // bad1: file present at wrong content → hash_mismatch.
        let bad1 = tempfile::tempdir().unwrap();
        tokio::fs::write(bad1.path().join("index.js"), b"wrong")
            .await
            .unwrap();
        // bad2: file absent → file_not_found.
        let bad2 = tempfile::tempdir().unwrap();

        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/bad1@1.0.0".to_string(),
            record_with_one_file(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
        );
        manifest.patches.insert(
            "pkg:npm/bad2@1.0.0".to_string(),
            record_with_one_file(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
        );

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/bad1@1.0.0".to_string(), bad1.path().to_path_buf());
        paths.insert("pkg:npm/bad2@1.0.0".to_string(), bad2.path().to_path_buf());

        let out = applied_patches(&manifest, &paths).await;
        assert!(out.applied.is_empty());
        assert_eq!(out.failed.len(), 2, "one FailedPatch per failing PURL");

        let mut reasons: Vec<&str> = out.failed.iter().map(|f| f.reason.as_str()).collect();
        reasons.sort_unstable();
        assert_eq!(reasons, vec!["file_not_found", "hash_mismatch"]);
    }

    /// At most ONE `FailedPatch` is recorded per PURL even when several
    /// files would fail — `verify_patch_record` returns on the first
    /// failure. Two distinct failing files, single failure recorded.
    #[tokio::test]
    async fn at_most_one_failure_recorded_per_purl() {
        let pkg_dir = tempfile::tempdir().unwrap();
        // a.js: hash mismatch (neither before nor after).
        tokio::fs::write(pkg_dir.path().join("a.js"), b"garbage")
            .await
            .unwrap();
        // b.js: absent → would be file_not_found.

        let mut files = HashMap::new();
        files.insert(
            "a.js".to_string(),
            PatchFileInfo {
                before_hash: "aaaa".to_string(),
                after_hash: "deadbeef".to_string(),
            },
        );
        files.insert(
            "b.js".to_string(),
            PatchFileInfo {
                before_hash: "bbbb".to_string(),
                after_hash: "deadbeef".to_string(),
            },
        );

        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/x@1.0.0".to_string(),
            PatchRecord {
                uuid: "u".to_string(),
                exported_at: String::new(),
                files,
                vulnerabilities: HashMap::new(),
                description: String::new(),
                license: String::new(),
                tier: String::new(),
            },
        );

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/x@1.0.0".to_string(), pkg_dir.path().to_path_buf());

        let out = applied_patches(&manifest, &paths).await;
        assert!(out.applied.is_empty());
        assert_eq!(
            out.failed.len(),
            1,
            "one FailedPatch per PURL, not per file"
        );
        assert!(
            matches!(
                out.failed[0].reason.as_str(),
                "hash_mismatch" | "file_not_found"
            ),
            "unexpected reason: {}",
            out.failed[0].reason
        );
    }

    // ── Vendored-patch awareness (`applied_patches_with_vendor`) ──

    use crate::vendor::state::{VendorArtifact, VendorEntry};

    /// Canonical-grammar patch UUID — `verify_vendored_patch_record`
    /// validates the uuid path level, so vendor fixtures must use a real
    /// uuid (unlike the `"u"` shorthand of the installed-tree tests).
    const VUUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    fn vendor_entry(purl: &str, rel_path: &str) -> VendorEntry {
        VendorEntry {
            ecosystem: "cargo".to_string(),
            base_purl: purl.to_string(),
            uuid: VUUID.to_string(),
            artifact: VendorArtifact {
                yarn_berry10c0: None,
                path: rel_path.to_string(),
                sha256: String::new(),
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            wiring: Vec::new(),
            lock: None,
            took_over_go_patches: false,
            detached: false,
            record: None,
            flavor: None,
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
        }
    }

    /// `applied_patches` must be exactly `applied_patches_with_vendor(.., None)`
    /// on a mixed fixture (one applied, one failed) — the wrapper carries the
    /// pre-vendor contract verbatim, with an empty `vendored` set.
    #[tokio::test]
    async fn wrapper_equals_with_vendor_none() {
        let ok_dir = tempfile::tempdir().unwrap();
        let patched = b"patched-content";
        let hash = compute_git_sha256_from_bytes(patched);
        tokio::fs::write(ok_dir.path().join("index.js"), patched)
            .await
            .unwrap();

        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert("pkg:npm/ok@1.0.0".to_string(), record_with_one_file(&hash));
        manifest.patches.insert(
            "pkg:npm/missing@2.0.0".to_string(),
            record_with_one_file("deadbeef"),
        );

        let mut paths = HashMap::new();
        paths.insert("pkg:npm/ok@1.0.0".to_string(), ok_dir.path().to_path_buf());

        let a = applied_patches(&manifest, &paths).await;
        let b = applied_patches_with_vendor(&manifest, &paths, None).await;
        assert_eq!(a.applied, b.applied);
        assert_eq!(a.failed, b.failed);
        assert!(a.vendored.is_empty());
        assert!(b.vendored.is_empty());
    }

    /// Happy path: a vendor-state entry + healthy vendored dir attests the
    /// PURL with the installed tree entirely ABSENT (`package_paths` empty —
    /// the post-vendor `node_modules`-less checkout). The PURL lands in BOTH
    /// `applied` and `vendored`.
    #[tokio::test]
    async fn vendored_dir_attests_without_installed_tree() {
        let root = tempfile::tempdir().unwrap();
        let purl = "pkg:cargo/serde@1.0.0";
        let rel = format!(".socket/vendor/cargo/{VUUID}/serde-1.0.0");
        let patched = b"patched-content";
        let hash = compute_git_sha256_from_bytes(patched);
        let dir = root.path().join(&rel);
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("index.js"), patched)
            .await
            .unwrap();

        let mut rec = record_with_one_file(&hash);
        rec.uuid = VUUID.to_string();
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(purl.to_string(), rec);

        let mut entries = HashMap::new();
        entries.insert(purl.to_string(), vendor_entry(purl, &rel));
        let ctx = VendorContext {
            project_root: root.path().to_path_buf(),
            entries,
            go_patches: HashMap::new(),
            hosted: HashMap::new(),
        };

        let paths: HashMap<String, PathBuf> = HashMap::new(); // no installed tree
        let out = applied_patches_with_vendor(&manifest, &paths, Some(&ctx)).await;
        assert_eq!(out.applied, vec![purl.to_string()]);
        assert_eq!(out.vendored, vec![purl.to_string()]);
        assert!(out.failed.is_empty());
        assert!(
            out.vendored_out_of_sync.is_empty(),
            "an ABSENT installed tree is the expected post-vendor state — no drift flag"
        );
    }

    /// A vendored Maven entry's Gradle `files-2.1` copy is a pristine
    /// sibling the vendored build never reads (exclusiveContent on the
    /// committed repository), never `vendored_out_of_sync`; a pristine
    /// `~/.m2` copy still is.
    #[tokio::test]
    async fn vendored_gradle_cache_copy_is_not_out_of_sync() {
        let root = tempfile::tempdir().unwrap();
        let purl = "pkg:maven/com.example/lib@1.0";
        let rel = format!(".socket/vendor/maven/{VUUID}/lib-1.0");
        let patched = b"patched-content";
        let dir = root.path().join(&rel);
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("index.js"), patched)
            .await
            .unwrap();
        let mut rec = record_with_one_file(&compute_git_sha256_from_bytes(patched));
        rec.uuid = VUUID.to_string();
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(purl.to_string(), rec);
        let ctx = VendorContext {
            project_root: root.path().to_path_buf(),
            entries: HashMap::from([(purl.to_string(), vendor_entry(purl, &rel))]),
            go_patches: HashMap::new(),
            hosted: HashMap::new(),
        };
        let version = root
            .path()
            .join("home/.gradle/caches/modules-2/files-2.1/com.example/lib/1.0");
        let hash_dir = version.join("a".repeat(40));
        tokio::fs::create_dir_all(&hash_dir).await.unwrap();
        tokio::fs::write(hash_dir.join("index.js"), b"pristine")
            .await
            .unwrap();
        let copies = HashMap::from([(purl.to_string(), vec![version.clone()])]);
        let out = applied_patches_with_copies(&manifest, &copies, Some(&ctx)).await;
        assert_eq!(out.vendored, vec![purl.to_string()]);
        assert!(out.vendored_out_of_sync.is_empty(), "{out:?}");

        let m2 = root.path().join("home/.m2/repository/com/example/lib/1.0");
        tokio::fs::create_dir_all(&m2).await.unwrap();
        tokio::fs::write(m2.join("index.js"), b"pristine")
            .await
            .unwrap();
        let copies = HashMap::from([(purl.to_string(), vec![version, m2])]);
        let out = applied_patches_with_copies(&manifest, &copies, Some(&ctx)).await;
        assert_eq!(out.vendored_out_of_sync, vec![purl.to_string()]);
    }

    /// A manifest PURL matches a vendor entry recorded under a different map
    /// key when `entry.base_purl` equals it (qualified-key manifests resolve
    /// to the base-PURL ledger entry).
    #[tokio::test]
    async fn vendor_entry_matched_by_base_purl() {
        let root = tempfile::tempdir().unwrap();
        let purl = "pkg:cargo/serde@1.0.0";
        let rel = format!(".socket/vendor/cargo/{VUUID}/serde-1.0.0");
        let patched = b"patched-content";
        let hash = compute_git_sha256_from_bytes(patched);
        let dir = root.path().join(&rel);
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("index.js"), patched)
            .await
            .unwrap();

        let mut rec = record_with_one_file(&hash);
        rec.uuid = VUUID.to_string();
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(purl.to_string(), rec);

        // Keyed by some other (qualified) string; base_purl carries the match.
        let mut entries = HashMap::new();
        entries.insert(
            "pkg:cargo/serde@1.0.0?qualifier=x".to_string(),
            vendor_entry(purl, &rel),
        );
        let ctx = VendorContext {
            project_root: root.path().to_path_buf(),
            entries,
            go_patches: HashMap::new(),
            hosted: HashMap::new(),
        };

        let out =
            applied_patches_with_vendor(&manifest, &HashMap::<String, PathBuf>::new(), Some(&ctx))
                .await;
        assert_eq!(out.applied, vec![purl.to_string()]);
        assert_eq!(out.vendored, vec![purl.to_string()]);
    }

    /// Precedence, healthy direction: the installed tree still holds the
    /// UN-patched bytes (expected after vendoring — the lockfile points at
    /// the vendored copy now) while the vendor artifact is healthy. The
    /// vendor path must win: applied + vendored, no `not_applied` failure.
    #[tokio::test]
    async fn healthy_vendor_beats_unpatched_installed_tree() {
        let root = tempfile::tempdir().unwrap();
        let purl = "pkg:cargo/serde@1.0.0";
        let rel = format!(".socket/vendor/cargo/{VUUID}/serde-1.0.0");
        let original = b"original-unpatched";
        let patched = b"patched-content";
        let before = compute_git_sha256_from_bytes(original);
        let after = compute_git_sha256_from_bytes(patched);

        // Vendored copy: patched.
        let vdir = root.path().join(&rel);
        tokio::fs::create_dir_all(&vdir).await.unwrap();
        tokio::fs::write(vdir.join("index.js"), patched)
            .await
            .unwrap();
        // Installed tree: still original.
        let installed = root.path().join("installed");
        tokio::fs::create_dir_all(&installed).await.unwrap();
        tokio::fs::write(installed.join("index.js"), original)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash: before,
                after_hash: after,
            },
        );
        let rec = PatchRecord {
            uuid: VUUID.to_string(),
            exported_at: String::new(),
            files,
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        };
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(purl.to_string(), rec);

        let mut entries = HashMap::new();
        entries.insert(purl.to_string(), vendor_entry(purl, &rel));
        let ctx = VendorContext {
            project_root: root.path().to_path_buf(),
            entries,
            go_patches: HashMap::new(),
            hosted: HashMap::new(),
        };
        let mut paths = HashMap::new();
        paths.insert(purl.to_string(), installed);

        let out = applied_patches_with_vendor(&manifest, &paths, Some(&ctx)).await;
        assert_eq!(
            out.applied,
            vec![purl.to_string()],
            "the unpatched installed tree must not block a healthy vendor attestation"
        );
        assert_eq!(out.vendored, vec![purl.to_string()]);
        assert!(out.failed.is_empty());
        // Disclosure: the live tree is present and pristine-unpatched — the
        // attestation stands (committed artifact is the product) but the
        // drift must be reported so the CLI can advise a re-install.
        assert_eq!(out.vendored_out_of_sync, vec![purl.to_string()]);
    }

    /// Drift disclosure covers EVERY installed copy: a first copy in sync
    /// must not hide an out-of-sync second one (#516).
    #[tokio::test]
    async fn vendored_drift_probe_checks_every_installed_copy() {
        let root = tempfile::tempdir().unwrap();
        let purl = "pkg:cargo/serde@1.0.0";
        let rel = format!(".socket/vendor/cargo/{VUUID}/serde-1.0.0");
        let original = b"original-unpatched";
        let patched = b"patched-content";
        let before = compute_git_sha256_from_bytes(original);
        let after = compute_git_sha256_from_bytes(patched);

        let vdir = root.path().join(&rel);
        tokio::fs::create_dir_all(&vdir).await.unwrap();
        tokio::fs::write(vdir.join("index.js"), patched)
            .await
            .unwrap();
        let mut installed = Vec::new();
        for (name, bytes) in [("in-sync", &patched[..]), ("drifted", &original[..])] {
            let dir = root.path().join(name);
            tokio::fs::create_dir_all(&dir).await.unwrap();
            tokio::fs::write(dir.join("index.js"), bytes).await.unwrap();
            installed.push(dir);
        }

        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash: before,
                after_hash: after,
            },
        );
        let rec = PatchRecord {
            uuid: VUUID.to_string(),
            exported_at: String::new(),
            files,
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        };
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(purl.to_string(), rec);

        let mut entries = HashMap::new();
        entries.insert(purl.to_string(), vendor_entry(purl, &rel));
        let ctx = VendorContext {
            project_root: root.path().to_path_buf(),
            entries,
            go_patches: HashMap::new(),
            hosted: HashMap::new(),
        };
        let copies = HashMap::from([(purl.to_string(), installed)]);

        let out = applied_patches_with_copies(&manifest, &copies, Some(&ctx)).await;
        assert_eq!(out.applied, vec![purl.to_string()]);
        assert_eq!(out.vendored, vec![purl.to_string()]);
        assert_eq!(out.vendored_out_of_sync, vec![purl.to_string()]);
    }

    /// Go vendored: the crawler's module-cache `M@v` is pristine by
    /// construction (immutable, go.sum-verified; the directory `replace`
    /// builds the committed copy), so it is never reported out of sync —
    /// every developer machine that ran `vendor` has it.
    #[tokio::test]
    async fn golang_pristine_module_cache_copy_is_not_out_of_sync() {
        let root = tempfile::tempdir().unwrap();
        let purl = "pkg:golang/github.com/foo/bar@v1.4.2";
        let rel = format!(".socket/vendor/golang/{VUUID}/github.com/foo/bar@v1.4.2");
        let patched = b"package bar // patched\n";
        let vdir = root.path().join(&rel);
        tokio::fs::create_dir_all(&vdir).await.unwrap();
        tokio::fs::write(vdir.join("index.js"), patched)
            .await
            .unwrap();
        let cache = root.path().join("gomodcache/github.com/foo/bar@v1.4.2");
        tokio::fs::create_dir_all(&cache).await.unwrap();
        tokio::fs::write(cache.join("index.js"), b"package bar // pristine\n")
            .await
            .unwrap();

        let mut rec = record_with_one_file(&compute_git_sha256_from_bytes(patched));
        rec.uuid = VUUID.to_string();
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(purl.to_string(), rec);
        let mut entries = HashMap::new();
        entries.insert(purl.to_string(), vendor_entry(purl, &rel));
        let ctx = VendorContext {
            project_root: root.path().to_path_buf(),
            entries,
            go_patches: HashMap::new(),
            hosted: HashMap::new(),
        };
        let mut paths = HashMap::new();
        paths.insert(purl.to_string(), cache);

        let out = applied_patches_with_vendor(&manifest, &paths, Some(&ctx)).await;
        assert_eq!(out.applied, vec![purl.to_string()]);
        assert_eq!(out.vendored, vec![purl.to_string()]);
        assert!(
            out.vendored_out_of_sync.is_empty(),
            "the pristine module cache is not drift: {:?}",
            out.vendored_out_of_sync
        );
    }

    /// Disclosure probe, tampered direction: the vendor artifact is healthy
    /// (attest + vendored) while the installed tree is present with bytes
    /// matching NEITHER `beforeHash` nor `afterHash`. The verdict stands but
    /// the purl is flagged `vendored_out_of_sync` — exactly like the
    /// pristine-unpatched case, since either way the live tree is running
    /// different bytes than the attested artifact.
    #[tokio::test]
    async fn tampered_installed_tree_flagged_out_of_sync_but_attested() {
        let root = tempfile::tempdir().unwrap();
        let purl = "pkg:cargo/serde@1.0.0";
        let rel = format!(".socket/vendor/cargo/{VUUID}/serde-1.0.0");
        let patched = b"patched-content";
        let hash = compute_git_sha256_from_bytes(patched);

        // Vendored copy: healthy.
        let vdir = root.path().join(&rel);
        tokio::fs::create_dir_all(&vdir).await.unwrap();
        tokio::fs::write(vdir.join("index.js"), patched)
            .await
            .unwrap();
        // Installed tree: tampered (neither before nor after content).
        let installed = root.path().join("installed");
        tokio::fs::create_dir_all(&installed).await.unwrap();
        tokio::fs::write(installed.join("index.js"), b"tampered live bytes")
            .await
            .unwrap();

        let mut rec = record_with_one_file(&hash);
        rec.uuid = VUUID.to_string();
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(purl.to_string(), rec);

        let mut entries = HashMap::new();
        entries.insert(purl.to_string(), vendor_entry(purl, &rel));
        let ctx = VendorContext {
            project_root: root.path().to_path_buf(),
            entries,
            go_patches: HashMap::new(),
            hosted: HashMap::new(),
        };
        let mut paths = HashMap::new();
        paths.insert(purl.to_string(), installed);

        let out = applied_patches_with_vendor(&manifest, &paths, Some(&ctx)).await;
        assert_eq!(
            out.applied,
            vec![purl.to_string()],
            "a tampered LIVE tree must not block the committed-artifact attestation"
        );
        assert_eq!(out.vendored, vec![purl.to_string()]);
        assert!(out.failed.is_empty());
        assert_eq!(out.vendored_out_of_sync, vec![purl.to_string()]);
    }

    /// Precedence, fail-closed direction: a TAMPERED vendor artifact fails
    /// with `vendor_hash_mismatch` even though the installed tree happens to
    /// look patched — a patched-looking tree must not launder a tampered
    /// committed artifact into an attestation.
    #[tokio::test]
    async fn tampered_vendor_not_laundered_by_patched_installed_tree() {
        let root = tempfile::tempdir().unwrap();
        let purl = "pkg:cargo/serde@1.0.0";
        let rel = format!(".socket/vendor/cargo/{VUUID}/serde-1.0.0");
        let patched = b"patched-content";
        let hash = compute_git_sha256_from_bytes(patched);

        // Vendored copy: tampered.
        let vdir = root.path().join(&rel);
        tokio::fs::create_dir_all(&vdir).await.unwrap();
        tokio::fs::write(vdir.join("index.js"), b"tampered")
            .await
            .unwrap();
        // Installed tree: at afterHash (would verify if consulted).
        let installed = root.path().join("installed");
        tokio::fs::create_dir_all(&installed).await.unwrap();
        tokio::fs::write(installed.join("index.js"), patched)
            .await
            .unwrap();

        let mut rec = record_with_one_file(&hash);
        rec.uuid = VUUID.to_string();
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(purl.to_string(), rec);

        let mut entries = HashMap::new();
        entries.insert(purl.to_string(), vendor_entry(purl, &rel));
        let ctx = VendorContext {
            project_root: root.path().to_path_buf(),
            entries,
            go_patches: HashMap::new(),
            hosted: HashMap::new(),
        };
        let mut paths = HashMap::new();
        paths.insert(purl.to_string(), installed);

        let out = applied_patches_with_vendor(&manifest, &paths, Some(&ctx)).await;
        assert!(
            out.applied.is_empty(),
            "a tampered vendor artifact must never be attested"
        );
        assert!(out.vendored.is_empty());
        assert_eq!(out.failed.len(), 1);
        assert_eq!(out.failed[0].reason, "vendor_hash_mismatch");
    }

    /// The `go_patches` map verifies the redirect copy dir with the normal
    /// dir-hash check: success → `applied` (NOT `vendored`); a stale/
    /// unpatched copy → failed. No installed-tree fallback either way.
    #[tokio::test]
    async fn go_patches_copy_dir_verifies_as_applied_not_vendored() {
        let root = tempfile::tempdir().unwrap();
        let purl = "pkg:golang/github.com/foo/bar@v1.4.2";
        let patched = b"patched-go-source";
        let hash = compute_git_sha256_from_bytes(patched);
        let copy_dir = root
            .path()
            .join(".socket/go-patches/github.com/foo/bar@v1.4.2");
        tokio::fs::create_dir_all(&copy_dir).await.unwrap();
        tokio::fs::write(copy_dir.join("index.js"), patched)
            .await
            .unwrap();

        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert(purl.to_string(), record_with_one_file(&hash));

        let mut go_patches = HashMap::new();
        go_patches.insert(purl.to_string(), copy_dir.clone());
        let ctx = VendorContext {
            project_root: root.path().to_path_buf(),
            entries: HashMap::new(),
            go_patches,
            hosted: HashMap::new(),
        };

        // No installed tree (module cache absent) — the redirect copy is
        // the consumed bytes.
        let out =
            applied_patches_with_vendor(&manifest, &HashMap::<String, PathBuf>::new(), Some(&ctx))
                .await;
        assert_eq!(out.applied, vec![purl.to_string()]);
        assert!(
            out.vendored.is_empty(),
            "go-patches redirects are applied, not vendored"
        );
        assert!(out.failed.is_empty());

        // Tamper the copy dir → failed with the dir-hash reason, never
        // attested.
        tokio::fs::write(copy_dir.join("index.js"), b"tampered")
            .await
            .unwrap();
        let out =
            applied_patches_with_vendor(&manifest, &HashMap::<String, PathBuf>::new(), Some(&ctx))
                .await;
        assert!(out.applied.is_empty());
        assert_eq!(out.failed.len(), 1);
        assert_eq!(out.failed[0].reason, "hash_mismatch");
    }

    /// A package dir holding `index.js` with `bytes`.
    async fn package_dir(root: &Path, rel: &str, bytes: &[u8]) -> PathBuf {
        let dir = root.join(rel);
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("index.js"), bytes).await.unwrap();
        dir
    }

    fn hosted_ctx(purl: &str, copies: HostedCopies) -> VendorContext {
        VendorContext {
            hosted: [(purl.to_string(), copies)].into_iter().collect(),
            ..Default::default()
        }
    }

    /// A hosted entry REPLACES the crawler's representative: a pristine
    /// sibling in `package_paths` (the original Go module beside its
    /// replacement) is never judged — an empty copy list is
    /// `package_not_found` (the lockfile basis's to excuse), a consumed copy
    /// that verifies attests.
    #[tokio::test]
    async fn hosted_copies_replace_the_pristine_sibling() {
        let root = tempfile::tempdir().unwrap();
        let purl = "pkg:golang/github.com/foo/bar@v1.4.2";
        let patched = b"patched";
        let pristine =
            package_dir(root.path(), "modcache/github.com/foo/bar@v1.4.2", b"orig").await;
        let replacement = package_dir(
            root.path(),
            "modcache/patch.socket.dev/gopatch/u@v1.4.2-socketpatch.1",
            patched,
        )
        .await;
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            purl.to_string(),
            record_with_one_file(&compute_git_sha256_from_bytes(patched)),
        );
        let paths: HashMap<String, PathBuf> = [(purl.to_string(), pristine)].into_iter().collect();

        // Without the hosted entry the pristine original fails the patch.
        let out = applied_patches_with_vendor(&manifest, &paths, None).await;
        assert_eq!(out.failed[0].reason, "hash_mismatch");

        let none = hosted_ctx(purl, HostedCopies::default());
        let out = applied_patches_with_vendor(&manifest, &paths, Some(&none)).await;
        assert!(out.applied.is_empty());
        assert_eq!(out.failed[0].reason, "package_not_found");

        let consumed = hosted_ctx(
            purl,
            HostedCopies {
                paths: vec![replacement],
                rename: None,
            },
        );
        let out = applied_patches_with_vendor(&manifest, &paths, Some(&consumed)).await;
        assert_eq!(out.applied, vec![purl.to_string()]);
        assert!(out.vendored.is_empty() && out.failed.is_empty());
    }

    /// Shared-location copies: EVERY listed copy must verify — a patched
    /// root `node_modules` copy must not attest a pristine nested one some
    /// dependent still loads.
    #[tokio::test]
    async fn every_hosted_copy_must_verify() {
        let root = tempfile::tempdir().unwrap();
        let purl = "pkg:npm/x@1.0.0";
        let patched = b"patched";
        let top = package_dir(root.path(), "node_modules/x", patched).await;
        let nested = package_dir(root.path(), "node_modules/y/node_modules/x", b"orig").await;
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            purl.to_string(),
            record_with_one_file(&compute_git_sha256_from_bytes(patched)),
        );
        let ctx = hosted_ctx(
            purl,
            HostedCopies {
                paths: vec![top.clone(), nested.clone()],
                rename: None,
            },
        );
        let out =
            applied_patches_with_vendor(&manifest, &HashMap::<String, PathBuf>::new(), Some(&ctx))
                .await;
        assert!(out.applied.is_empty());
        assert_eq!(out.failed[0].reason, "hash_mismatch");

        tokio::fs::write(nested.join("index.js"), patched)
            .await
            .unwrap();
        let out =
            applied_patches_with_vendor(&manifest, &HashMap::<String, PathBuf>::new(), Some(&ctx))
                .await;
        assert_eq!(out.applied, vec![purl.to_string()]);
    }

    /// Maven's suffixed hosted version renames the artifact files: the
    /// record's `<a>-<base>…` keys are verified as `<a>-<suffixed>…` —
    /// whole components only (`lib-1.0` never re-prefixes `lib-1.0.1.jar`).
    #[tokio::test]
    async fn hosted_copies_verify_renamed_maven_artifacts() {
        let root = tempfile::tempdir().unwrap();
        let purl = "pkg:maven/org.example/lib@1.0";
        let patched = b"patched-jar";
        let dir = root.path().join("lib/1.0-socket.abcdef12");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("lib-1.0-socket.abcdef12.jar"), patched)
            .await
            .unwrap();
        let mut record = record_with_one_file(&compute_git_sha256_from_bytes(patched));
        record.files = [(
            "lib-1.0.jar".to_string(),
            record.files.remove("index.js").unwrap(),
        )]
        .into_iter()
        .collect();
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(purl.to_string(), record.clone());
        let ctx = hosted_ctx(
            purl,
            HostedCopies {
                paths: vec![dir.clone()],
                rename: Some(("lib-1.0".into(), "lib-1.0-socket.abcdef12".into())),
            },
        );
        let out =
            applied_patches_with_vendor(&manifest, &HashMap::<String, PathBuf>::new(), Some(&ctx))
                .await;
        assert_eq!(out.applied, vec![purl.to_string()], "{:?}", out.failed);

        let renamed = rename_record_files(&record, "lib-1.0", "lib-1.0-socket.abcdef12");
        assert!(renamed.files.contains_key("lib-1.0-socket.abcdef12.jar"));
        let mut odd = record.clone();
        odd.files.insert(
            "lib-1.0.1.jar".to_string(),
            odd.files["lib-1.0.jar"].clone(),
        );
        let renamed = rename_record_files(&odd, "lib-1.0", "lib-1.0-socket.abcdef12");
        assert!(
            renamed.files.contains_key("lib-1.0.1.jar"),
            "not a whole component"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_vlt_link_to_the_vendored_dir_is_in_sync_under_the_manifest_exemption() {
        use sha2::Digest;
        use std::collections::BTreeMap;
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let purl = "pkg:npm/a@1.0.0";
        let rel = format!(".socket/vendor/npm/{VUUID}/a-1.0.0/node_modules/a");
        let dir = root.join(&rel);
        tokio::fs::create_dir_all(dir.join("node_modules"))
            .await
            .unwrap();
        let blob: &[u8] = b"{\"name\":\"a\",\"devDependencies\":{\"t\":\"1\"}}";
        let stripped: &[u8] = b"{\"name\":\"a\"}";
        let index: &[u8] = b"patched";
        tokio::fs::write(dir.join("package.json"), stripped)
            .await
            .unwrap();
        tokio::fs::write(dir.join("index.js"), index).await.unwrap();
        let mut rec = record_with_one_file(&compute_git_sha256_from_bytes(index));
        rec.uuid = VUUID.to_string();
        rec.files.insert(
            "package.json".to_string(),
            crate::manifest::schema::PatchFileInfo {
                before_hash: "b".repeat(64),
                after_hash: compute_git_sha256_from_bytes(blob),
            },
        );
        let mut entry = vendor_entry(purl, &rel);
        entry.ecosystem = "npm".to_string();
        entry.flavor = Some("vlt".to_string());
        entry.artifact.file_inventory = Some(BTreeMap::from([
            (
                "index.js".to_string(),
                hex::encode(sha2::Sha256::digest(index)),
            ),
            (
                "package.json".to_string(),
                hex::encode(sha2::Sha256::digest(stripped)),
            ),
        ]));
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(purl.to_string(), rec);
        let ctx = VendorContext {
            project_root: root.to_path_buf(),
            entries: HashMap::from([(purl.to_string(), entry)]),
            go_patches: HashMap::new(),
            hosted: HashMap::new(),
        };
        let link = root.join("node_modules/a");
        tokio::fs::create_dir_all(root.join("node_modules"))
            .await
            .unwrap();
        tokio::fs::symlink(&dir, &link).await.unwrap();
        let paths = HashMap::from([(purl.to_string(), link.clone())]);
        let out = applied_patches_with_vendor(&manifest, &paths, Some(&ctx)).await;
        assert_eq!(out.vendored, vec![purl.to_string()], "{:?}", out.failed);
        assert!(
            out.vendored_out_of_sync.is_empty(),
            "the link IS the artifact"
        );

        let copy = root.join("copy");
        tokio::fs::create_dir_all(&copy).await.unwrap();
        tokio::fs::write(copy.join("package.json"), stripped)
            .await
            .unwrap();
        tokio::fs::write(copy.join("index.js"), index)
            .await
            .unwrap();
        let paths = HashMap::from([(purl.to_string(), copy.clone())]);
        let out = applied_patches_with_vendor(&manifest, &paths, Some(&ctx)).await;
        assert!(out.vendored_out_of_sync.is_empty(), "exempt package.json");

        tokio::fs::write(copy.join("index.js"), b"pristine")
            .await
            .unwrap();
        let out = applied_patches_with_vendor(&manifest, &paths, Some(&ctx)).await;
        assert_eq!(out.vendored_out_of_sync, vec![purl.to_string()]);
    }

    // ── judge_installed_record ≡ verify_patch_record + evidence scan ──

    /// The CLI stale-install probes' positive-evidence scan as it was
    /// (per-file `verify_file_patch`), the oracle for the one-pass judge.
    async fn stale_positive_evidence_oracle(pkg_path: &Path, record: &PatchRecord) -> bool {
        for (file_name, info) in &record.files {
            let result = verify_file_patch(pkg_path, file_name, info).await;
            if matches!(
                result.status,
                VerifyStatus::Ready | VerifyStatus::HashMismatch
            ) && result.current_hash.is_some()
            {
                return true;
            }
        }
        false
    }

    #[tokio::test]
    async fn judge_installed_record_matches_verify_and_evidence_scan() {
        use crate::crawlers::oracle_support::{fifo, mkdir, write, Rng};

        let patched = compute_git_sha256_from_bytes(b"patched");
        let upstream = compute_git_sha256_from_bytes(b"upstream");
        let (mut seen_patched, mut seen_stale) = (0, 0);
        for seed in 0..200u64 {
            let mut rng = Rng::new(seed);
            let dir = tempfile::tempdir().unwrap();
            let mut files = HashMap::new();
            for i in 0..rng.below(4) {
                let name = match rng.below(10) {
                    0 => "../escape.js".to_string(),
                    1 => format!("./lib/f{i}.js"),
                    2 => format!("/abs{i}.js"),
                    _ => format!("lib/f{i}.js"),
                };
                let path = dir.path().join(normalize_file_path_for_test(&name));
                match rng.below(8) {
                    0 => {}
                    1 => mkdir(&path),
                    2 => fifo(&path),
                    3 => write(&path, "upstream"),
                    4 => write(&path, "something else"),
                    _ => write(&path, "patched"),
                }
                let before_hash = if rng.chance(20) {
                    String::new()
                } else {
                    upstream.clone()
                };
                files.insert(
                    name,
                    PatchFileInfo {
                        before_hash,
                        after_hash: patched.clone(),
                    },
                );
            }
            let record = PatchRecord {
                files,
                ..record_with_one_file(&patched)
            };
            let judged = judge_installed_record(dir.path(), &record).await;
            let verified = verify_patch_record(dir.path(), &record).await.is_ok();
            assert_eq!(judged.patched, verified, "seed {seed}: patched");
            // On EVERY seed, verified ones included: `stale_evidence` is
            // the only surviving pin on the CLI probe's old rule (its
            // caller is now a `#[cfg(test)]` view of this judge), and a
            // judge that set it alongside `patched` would change the
            // gem/python warning text with nothing to catch it.
            assert_eq!(
                judged.stale_evidence,
                stale_positive_evidence_oracle(dir.path(), &record).await,
                "seed {seed}: evidence"
            );
            seen_patched += usize::from(judged.patched);
            seen_stale += usize::from(judged.stale_evidence);
        }
        assert!(
            seen_patched > 10 && seen_stale > 10,
            "{seen_patched}/{seen_stale}"
        );
    }

    // ── Maven / Gradle copy sets ────────────────────────────────────

    fn stored_jar(members: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write as _;
        let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, bytes) in members {
            out.start_file(*name, opts).unwrap();
            out.write_all(bytes).unwrap();
        }
        out.finish().unwrap().into_inner()
    }

    fn sha1_hex(bytes: &[u8]) -> String {
        use sha1::Digest as _;
        hex::encode(sha1::Sha1::digest(bytes))
    }

    fn maven_record(files: &[(&str, &[u8], &[u8])]) -> PatchRecord {
        let mut record = record_with_one_file("unused");
        record.files = files
            .iter()
            .map(|(k, before, after)| {
                (
                    k.to_string(),
                    PatchFileInfo {
                        before_hash: compute_git_sha256_from_bytes(before),
                        after_hash: compute_git_sha256_from_bytes(after),
                    },
                )
            })
            .collect();
        record
    }

    /// A Gradle version dir holding the patched jar in one hash dir and a
    /// pristine re-download in another, plus a patched `~/.m2` copy: the
    /// copy set fails as a whole and names the unpatched copy — no
    /// statement while any consumed copy is pristine.
    #[tokio::test]
    async fn maven_copy_set_with_one_pristine_copy_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let purl = "pkg:maven/com.example/lib@1.0";
        let record = maven_record(&[("package/lib-1.0.pom", b"<pristine/>", b"<patched/>")]);
        let m2 = tmp.path().join("m2/com/example/lib/1.0");
        std::fs::create_dir_all(&m2).unwrap();
        std::fs::write(m2.join("lib-1.0.pom"), b"<patched/>").unwrap();
        let version = tmp
            .path()
            .join(".gradle/caches/modules-2/files-2.1/com.example/lib/1.0");
        for dir in [sha1_hex(b"<pristine/>"), sha1_hex(b"<pristine again/>")] {
            std::fs::create_dir_all(version.join(&dir)).unwrap();
        }
        std::fs::write(
            version.join(sha1_hex(b"<pristine/>")).join("lib-1.0.pom"),
            b"<patched/>",
        )
        .unwrap();
        let stale = version.join(sha1_hex(b"<pristine again/>"));
        std::fs::write(stale.join("lib-1.0.pom"), b"<pristine/>").unwrap();

        let mut manifest = PatchManifest::new();
        manifest.patches.insert(purl.to_string(), record);
        let copies = HashMap::from([(purl.to_string(), vec![m2.clone(), version.clone()])]);
        let out = applied_patches_with_copies(&manifest, &copies, None).await;
        assert!(out.applied.is_empty(), "{out:?}");
        assert_eq!(out.failed[0].reason, "not_applied");
        assert_eq!(out.unpatched_copies, [(purl.to_string(), version.clone())]);

        // Patch the re-download too: every copy verifies.
        std::fs::write(stale.join("lib-1.0.pom"), b"<patched/>").unwrap();
        let out = applied_patches_with_copies(&manifest, &copies, None).await;
        assert_eq!(out.applied, [purl.to_string()]);
        assert!(out.unpatched_copies.is_empty());

        // A non-Maven purl also needs every copy (#516), but its failing
        // copies are not listed in `unpatched_copies`.
        let npm = "pkg:npm/x@1.0.0";
        let good = tempfile::tempdir().unwrap();
        std::fs::write(good.path().join("index.js"), b"patched").unwrap();
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            npm.to_string(),
            record_with_one_file(&compute_git_sha256_from_bytes(b"patched")),
        );
        let copies = HashMap::from([(
            npm.to_string(),
            vec![good.path().to_path_buf(), tmp.path().join("absent")],
        )]);
        let out = applied_patches_with_copies(&manifest, &copies, None).await;
        assert!(out.applied.is_empty(), "{out:?}");
        assert_eq!(out.failed[0].reason, "file_not_found");
        assert!(out.unpatched_copies.is_empty());
    }

    /// A member-keyed record verifies against the jar's members, in every
    /// hash dir holding the jar.
    #[tokio::test]
    async fn maven_member_record_verifies_every_jar_copy() {
        let tmp = tempfile::tempdir().unwrap();
        let purl = "pkg:maven/com.example/lib@1.0";
        let record = maven_record(&[("META-INF/NOTICE.txt", b"pristine", b"patched")]);
        let pristine = stored_jar(&[("META-INF/NOTICE.txt", b"pristine")]);
        let patched = stored_jar(&[("META-INF/NOTICE.txt", b"patched")]);
        let version = tmp
            .path()
            .join(".gradle/caches/modules-2/files-2.1/com.example/lib/1.0");
        let dir = version.join(sha1_hex(&pristine));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("lib-1.0.jar"), &patched).unwrap();
        assert_eq!(
            verify_patch_record_for(purl, &version, &record).await,
            Ok(())
        );
        // A second (pristine) hash dir of the same jar fails the set.
        let again = version.join("1".repeat(40));
        std::fs::create_dir_all(&again).unwrap();
        std::fs::write(again.join("lib-1.0.jar"), &pristine).unwrap();
        assert_eq!(
            verify_patch_record_for(purl, &version, &record).await,
            Err("not_applied".to_string())
        );
        // No jar at all.
        assert_eq!(
            verify_patch_record_for(purl, tmp.path(), &record).await,
            Err("file_not_found".to_string())
        );
    }

    /// Hosted: a member-keyed record is checked in the jar under its
    /// SUFFIXED name, in a Gradle version dir of the suffixed version.
    #[tokio::test]
    async fn hosted_member_record_verifies_under_suffixed_leaf() {
        let tmp = tempfile::tempdir().unwrap();
        let purl = "pkg:maven/com.example/lib@1.0";
        let record = maven_record(&[("META-INF/NOTICE.txt", b"pristine", b"patched")]);
        let patched = stored_jar(&[("META-INF/NOTICE.txt", b"patched")]);
        let version = tmp
            .path()
            .join(".gradle/caches/modules-2/files-2.1/com.example/lib/1.0-socket.0123abcd");
        let dir = version.join(sha1_hex(&patched));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("lib-1.0-socket.0123abcd.jar"), &patched).unwrap();
        let copies = HostedCopies {
            paths: vec![version.clone()],
            rename: Some(("lib-1.0".to_string(), "lib-1.0-socket.0123abcd".to_string())),
        };
        assert_eq!(verify_hosted_copies(purl, &copies, &record).await, Ok(()));
        // The base-named jar is never what a hosted build reads.
        std::fs::rename(
            dir.join("lib-1.0-socket.0123abcd.jar"),
            dir.join("lib-1.0.jar"),
        )
        .unwrap();
        assert_eq!(
            verify_hosted_copies(purl, &copies, &record).await,
            Err("file_not_found".to_string())
        );
    }

    /// Where a (safe) record key lands under the package dir; unsafe keys
    /// land somewhere harmless inside the tempdir.
    fn normalize_file_path_for_test(name: &str) -> String {
        crate::patch::apply::normalize_file_path(name)
            .trim_start_matches(['/', '.'])
            .to_string()
    }
}
