//! Project-local Go `replace`-redirect engine (local mode only).
//!
//! Unlike cargo (which patches crates in place wherever the crawler finds
//! them), the Go module cache is shared, read-only and checksum-verified, so
//! in-place patching fails `go.sum` verification at build time. Instead, this
//! materialises a project-local **patched copy** of
//! each module under `<root>/.socket/go-patches/<module>@<version>/` and points
//! the build at it with a `replace` directive in `<root>/go.mod`:
//!
//! ```text
//! replace github.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2
//! ```
//!
//! Patches become project-scoped, the module cache stays pristine (so
//! `go mod verify` keeps passing and other projects are unaffected), and removal
//! is clean (drop the directive → the build falls back to the cache). A
//! local-path `replace` target is **not** `go.sum` content-verified, so the
//! patched bytes build cleanly under the default `-mod=readonly` (validated
//! empirically — see project memory).
//!
//! The copy is produced by **delegating to the hardened
//! [`apply_package_patch`] pipeline** pointed at the fresh copy, reusing all the
//! verify → package/diff/blob → atomic-write machinery unchanged.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::manifest::schema::{PatchFileInfo, PatchManifest};
use crate::patch::apply::{
    apply_package_patch, normalize_file_path, ApplyResult, MismatchPolicy, PatchSources,
    VerifyResult, VerifyStatus,
};
use crate::patch::file_hash::compute_file_git_sha256;
use crate::utils::purl::{build_golang_purl, parse_golang_purl, strip_purl_qualifiers};

use super::copy_tree::{fresh_copy, remove_tree};
use super::go_mod_edit::{
    self, expected_replace_path, read_replace_entries, read_required_versions, replace_target_path,
    ReplaceOwner, GO_PATCHES_DIR,
};
use super::path_safety;

/// A discrepancy between the committed redirect artifacts and the manifest,
/// reported by [`verify_go_redirect_state`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drift {
    /// No patched-copy directory exists for an in-scope PURL.
    MissingCopy { purl: String },
    /// A patched file in the copy does not hash to its manifest `afterHash`
    /// (`found` is `None` when the file is missing/unreadable).
    StaleCopy {
        purl: String,
        file: String,
        expected: String,
        found: Option<String>,
    },
    /// No managed `replace` directive exists for an in-scope PURL.
    MissingReplace { purl: String },
    /// A socket-owned `replace` directive exists but pins a different
    /// version / points at a different copy than the manifest desires. Go keys
    /// `replace` by module path **and version**: a directive pinned to the
    /// wrong version is silently ignored and the build links the UNPATCHED
    /// module, while the copy-hash checks still pass.
    WrongReplacePath {
        purl: String,
        expected: String,
        found: Option<String>,
    },
    /// A socket-owned `replace` directive exists with no desired PURL.
    OrphanReplace { module: String },
    /// `go.mod`'s `require` set resolves this module to a version that does NOT
    /// match the patched version, so the version-pinned `replace` is unused and
    /// the build silently links the UNPATCHED module.
    ResolvedVersionMismatch {
        purl: String,
        patched_version: String,
        required_version: String,
    },
}

impl std::fmt::Display for Drift {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Drift::MissingCopy { purl } => write!(f, "missing patched copy for {purl}"),
            Drift::StaleCopy {
                purl,
                file,
                expected,
                found,
            } => write!(
                f,
                "stale copy for {purl}: {file} expected {expected}, found {}",
                found.as_deref().unwrap_or("<missing>")
            ),
            Drift::MissingReplace { purl } => write!(f, "missing go.mod `replace` for {purl}"),
            Drift::WrongReplacePath {
                purl,
                expected,
                found,
            } => write!(
                f,
                "go.mod `replace` for {purl} points at {} but should be {expected} \
                 — go would ignore it and link the UNPATCHED module",
                found.as_deref().unwrap_or("<none>")
            ),
            Drift::OrphanReplace { module } => write!(
                f,
                "orphan go.mod `replace` for `{module}` (no patch in manifest)"
            ),
            Drift::ResolvedVersionMismatch {
                purl,
                patched_version,
                required_version,
            } => write!(
                f,
                "{purl}: patched version {patched_version} is not the required version \
                 (go.mod requires {required_version}) — go would link the UNPATCHED module"
            ),
        }
    }
}

/// The project-relative copy dir for a module under `base_rel` (the copy base:
/// [`GO_PATCHES_DIR`] for apply, `<GO_VENDOR_DIR>/<uuid>` for vendor).
/// `module` carries the real (decoded) module path with `/`-separators, so the
/// on-disk layout mirrors the module cache (`github.com/foo/bar@v1.4.2`).
fn copy_dir_for(project_root: &Path, base_rel: &str, module: &str, version: &str) -> PathBuf {
    project_root
        .join(base_rel)
        .join(format!("{module}@{version}"))
}

/// SECURITY: the `module`+`version` key the on-disk copy dir
/// (`<base_rel>/<module>@<version>/`) and the `replace` target path, so a
/// tampered manifest PURL must not be able to make them escape the copy base.
/// A `..`/`.` segment, an absolute path, or a backslash/NUL would otherwise let
/// `apply` copy + write the patched tree (or `rollback` delete a tree) at an
/// arbitrary filesystem location outside the project.
///
/// Unlike a cargo crate name, a Go module path legitimately contains `/`
/// separators (`github.com/foo/bar`), so it is validated **per segment**
/// (see [`path_safety::is_safe_multi_segment`]); a version is a single
/// segment. Reject fail-closed before any disk access.
///
/// `pub` (not `pub(crate)`): the CLI's VEX go-patches synthesis keys the
/// same copy-dir path from the same untrusted `go.mod` coordinates and must
/// apply this exact guard rather than a drift-prone mirror.
pub fn are_safe_redirect_coords(module: &str, version: &str) -> bool {
    path_safety::is_safe_multi_segment(module) && path_safety::is_safe_single_segment(version)
}

/// Materialise a project-local patched copy and wire up the `replace` redirect.
///
/// * `pristine_src` — the pristine module-cache source dir (the crawler's
///   `pkg_path`, case-encoded on disk). It is copied, never mutated.
/// * `module` / `version` — the **decoded** module path + version (from the
///   PURL); they key both the copy dir and the `replace` directive.
/// * `base_rel` — the project-relative copy base ([`GO_PATCHES_DIR`] for
///   apply's redirect, `<GO_VENDOR_DIR>/<uuid>` for the vendor backend).
#[allow(clippy::too_many_arguments)]
pub async fn apply_go_redirect(
    purl: &str,
    module: &str,
    version: &str,
    pristine_src: &Path,
    project_root: &Path,
    base_rel: &str,
    files: &HashMap<String, PatchFileInfo>,
    sources: &PatchSources<'_>,
    uuid: Option<&str>,
    dry_run: bool,
    policy: MismatchPolicy,
) -> ApplyResult {
    // SECURITY: refuse coordinates that would escape the copy base.
    // A `..`/separator-laden `module`/`version` (a tampered manifest PURL) would
    // otherwise make `fresh_copy` + the apply pipeline write the patched tree to
    // an arbitrary location. Fail-closed before any disk access.
    if !are_safe_redirect_coords(module, version) {
        return synthesized_result(
            purl,
            Path::new(""),
            Vec::new(),
            false,
            Some(format!(
                "refusing go redirect for unsafe coordinates `{module}`/`{version}` \
                 (a `..` segment, absolute path, or separator would escape {base_rel}/)"
            )),
        );
    }

    let copy_dir = copy_dir_for(project_root, base_rel, module, version);

    // A redirect with no files to patch is meaningless: no-op success, no
    // go.mod edit.
    if files.is_empty() {
        return synthesized_result(purl, &copy_dir, Vec::new(), true, None);
    }

    if dry_run {
        // Verify (read-only) against the pristine source for an accurate
        // "would patch" report, without creating the copy or editing go.mod.
        let mut result =
            apply_package_patch(purl, pristine_src, files, sources, uuid, true, policy).await;
        result.package_path = copy_dir.display().to_string();
        result.sidecar = None; // a replace copy is not the cache (no go.sum advisory)
        return result;
    }

    // Hot path: already in sync → touch nothing, so the build's source
    // fingerprint stays stable across repeated applies (the guard re-runs apply
    // on most "deps changed" builds).
    if redirect_in_sync(&copy_dir, files, project_root, module, version, base_rel).await {
        let verified = files.keys().map(|f| already_patched_verify(f)).collect();
        return synthesized_result(purl, &copy_dir, verified, true, None);
    }

    // Fresh copy pristine → copy_dir.
    if let Err(e) = fresh_copy(pristine_src, &copy_dir, None).await {
        return synthesized_result(
            purl,
            &copy_dir,
            Vec::new(),
            false,
            Some(format!("failed to copy pristine source: {e}")),
        );
    }

    // A `replace` target must be a valid module: it needs a go.mod declaring the
    // module path. Pre-modules packages have none in their extracted cache dir
    // (validated: `gopkg.in/inf.v0`), so synthesize Go's own minimal form.
    if let Err(e) = ensure_module_go_mod(&copy_dir, module).await {
        let _ = remove_tree(&copy_dir).await;
        return synthesized_result(
            purl,
            &copy_dir,
            Vec::new(),
            false,
            Some(format!("failed to synthesize go.mod for the copy: {e}")),
        );
    }

    // Delegate to the hardened pipeline, pointed at the copy.
    let mut result =
        apply_package_patch(purl, &copy_dir, files, sources, uuid, false, policy).await;
    result.package_path = copy_dir.display().to_string();
    // The golang sidecar advisory ("go mod verify will fail against go.sum")
    // is about in-cache patching; a `replace` copy bypasses go.sum entirely, so
    // the advisory does not apply here — drop it.
    result.sidecar = None;

    if !result.success {
        // Don't leave a half-built copy that verify/reconcile would misjudge.
        let _ = remove_tree(&copy_dir).await;
        return result;
    }

    // Wire up the `replace` directive. Load-bearing: without it the build won't
    // redirect to the copy, so a failure here fails the apply.
    if let Err(e) =
        go_mod_edit::ensure_replace_entry(project_root, module, version, base_rel, false).await
    {
        result.success = false;
        result.error = Some(format!("failed to update go.mod: {e}"));
        return result;
    }

    result
}

/// Drop `owner`'s managed `replace` directive + the patched copy under
/// `base_rel` for a golang PURL.
pub async fn remove_go_redirect(
    purl: &str,
    project_root: &Path,
    base_rel: &str,
    owner: ReplaceOwner,
    dry_run: bool,
) -> Result<(), std::io::Error> {
    let (module, version) = parse_golang_purl(purl).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("not a golang purl: {purl}"),
        )
    })?;

    // SECURITY: the copy dir is `<base_rel>/<module>@<version>/` and is about
    // to be `remove_tree`d. Unsafe coordinates (`..` segment / separator /
    // absolute) would target a tree outside the project for deletion — refuse.
    if !are_safe_redirect_coords(module, version) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing to remove go redirect for unsafe coordinates: {purl}"),
        ));
    }

    go_mod_edit::drop_replace_entry(project_root, module, owner, dry_run)
        .await
        .map_err(std::io::Error::other)?;

    if !dry_run {
        let copy_dir = copy_dir_for(project_root, base_rel, module, version);
        let _ = remove_tree(&copy_dir).await; // ignore NotFound
    }
    Ok(())
}

/// Prune **go-patches-owned** `replace` directives + copy dirs no longer in
/// `desired` (patches dropped from the manifest). Returns the removed PURLs.
/// Vendor-owned directives and `.socket/vendor/` copies are never touched —
/// they are reconciled by the vendor command against its own state.
pub async fn reconcile_go_redirects(
    project_root: &Path,
    desired: &HashSet<String>,
    dry_run: bool,
) -> Vec<String> {
    let desired_modules: HashSet<&str> = desired
        .iter()
        .filter_map(|p| parse_golang_purl(p).map(|(m, _)| m))
        .collect();

    let mut removed: Vec<String> = Vec::new();

    // (a) Orphan go-patches-owned `replace` directives (module no longer patched).
    for entry in read_replace_entries(project_root).await {
        if entry.owner == Some(ReplaceOwner::GoPatches)
            && !desired_modules.contains(entry.module.as_str())
        {
            let _ = go_mod_edit::drop_replace_entry(
                project_root,
                &entry.module,
                ReplaceOwner::GoPatches,
                dry_run,
            )
            .await;
            if let Some(v) = &entry.version {
                let purl = build_golang_purl(&entry.module, v);
                if !removed.contains(&purl) {
                    removed.push(purl);
                }
            }
        }
    }

    // (b) Orphan copy dirs not referenced by a desired PURL (catches copies left
    // behind by a hand-deleted directive or a version bump). A desired manifest
    // key may carry `?qualifiers`/`#subpath` (raw API PURL), while the PURL
    // reconstructed from the copy dir is the canonical base — compare bases, or
    // a qualified key's freshly applied copy is pruned as an orphan.
    let desired_bases: HashSet<&str> = desired.iter().map(|p| strip_purl_qualifiers(p)).collect();
    for (purl, dir) in collect_copy_modules(&project_root.join(GO_PATCHES_DIR)).await {
        if !desired_bases.contains(purl.as_str()) {
            if !dry_run {
                let _ = remove_tree(&dir).await;
            }
            if !removed.contains(&purl) {
                removed.push(purl);
            }
        }
    }

    removed
}

/// Registry-independent verification for `apply --check` (CI / GitHub-App
/// auditing + the build-time guard probe). Reads **only** the manifest, the
/// committed copies, and `go.mod` — never the module cache, no network — so it
/// works on a fresh clone / airgapped CI.
///
/// Version cross-check limitation: the resolved-version comparison uses
/// `go.mod`'s `require` directives. After `go mod tidy` these list the selected
/// version of every module that provides an imported package (direct *and*
/// `// indirect`), so the common cases are covered. A patched module that is
/// **transitive-only and absent from `require`** cannot be version-checked here
/// (full MVS needs the toolchain); such a patch falling stale relies on the
/// build-time guard (which runs where `go` is present) for eventual detection.
pub async fn verify_go_redirect_state(
    project_root: &Path,
    manifest: &PatchManifest,
    desired: &HashSet<String>,
) -> Result<(), Vec<Drift>> {
    let mut drifts = Vec::new();
    let entries = read_replace_entries(project_root).await;
    // Required versions from go.mod (None ⇒ no go.mod ⇒ skip the version
    // cross-check). Read once, project-local, offline.
    let required = read_required_versions(project_root).await;
    let desired_modules: HashSet<&str> = desired
        .iter()
        .filter_map(|p| parse_golang_purl(p).map(|(m, _)| m))
        .collect();

    for purl in desired {
        let Some((module, version)) = parse_golang_purl(purl) else {
            continue;
        };
        let Some(record) = manifest.patches.get(purl) else {
            continue;
        };

        // SECURITY: skip coordinates that would resolve the copy dir outside
        // `.socket/go-patches/` (a tampered manifest); never stat/hash files
        // outside the project tree during an audit. Mirrors the apply guard.
        if !are_safe_redirect_coords(module, version) {
            continue;
        }

        // A vendor-owned `replace` outranks the go-patches redirect: the module
        // is managed by `socket-patch vendor`, so this audit must not demand a
        // go-patches copy/directive for it (that would report MissingCopy/
        // WrongReplacePath drift for every vendored module).
        if entries
            .iter()
            .any(|e| e.module == module && e.owner == Some(ReplaceOwner::Vendor))
        {
            continue;
        }

        // go.mod `require` cross-check: if the graph resolves this module to a
        // version that is NOT the patched one, the version-pinned `replace` is
        // unused and the build links the unpatched module — a silent-stale hole
        // the copy/directive checks below can't see. (A module absent from
        // `require` is harmless — it isn't built — so only flag a
        // present-but-different resolution.)
        if let Some(req) = required.as_ref().and_then(|r| r.get(module)) {
            if req != version {
                drifts.push(Drift::ResolvedVersionMismatch {
                    purl: purl.clone(),
                    patched_version: version.to_string(),
                    required_version: req.clone(),
                });
            }
        }

        let copy_dir = copy_dir_for(project_root, GO_PATCHES_DIR, module, version);
        if tokio::fs::metadata(&copy_dir).await.is_err() {
            drifts.push(Drift::MissingCopy { purl: purl.clone() });
        } else {
            for (file_name, info) in &record.files {
                let path = copy_dir.join(normalize_file_path(file_name));
                match compute_file_git_sha256(&path).await {
                    Ok(h) if h == info.after_hash => {}
                    Ok(h) => drifts.push(Drift::StaleCopy {
                        purl: purl.clone(),
                        file: file_name.clone(),
                        expected: info.after_hash.clone(),
                        found: Some(h),
                    }),
                    Err(_) => drifts.push(Drift::StaleCopy {
                        purl: purl.clone(),
                        file: file_name.clone(),
                        expected: info.after_hash.clone(),
                        found: None,
                    }),
                }
            }
        }

        // The socket-owned `replace` must exist AND pin THIS version's copy. Go
        // keys `replace` by module + version, so a socket directive pinned to
        // another version (an aborted/partial apply, a bad merge, a hand-edit)
        // is silently ignored while the copy-hash checks above pass.
        let expected = expected_replace_path(module, version);
        let socket = entries
            .iter()
            .find(|e| e.module == module && e.owner == Some(ReplaceOwner::GoPatches));
        match socket {
            Some(e)
                if e.path.as_deref() == Some(expected.as_str())
                    && e.version.as_deref() == Some(version) => {}
            Some(e) => drifts.push(Drift::WrongReplacePath {
                purl: purl.clone(),
                expected,
                found: e.path.clone(),
            }),
            None => drifts.push(Drift::MissingReplace { purl: purl.clone() }),
        }
    }

    for entry in &entries {
        if entry.owner == Some(ReplaceOwner::GoPatches)
            && !desired_modules.contains(entry.module.as_str())
        {
            drifts.push(Drift::OrphanReplace {
                module: entry.module.clone(),
            });
        }
    }

    if drifts.is_empty() {
        Ok(())
    } else {
        Err(drifts)
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// True if the copy exists, every patched file in it already hashes to its
/// `afterHash`, and a socket-owned `replace` pins this version's copy.
async fn redirect_in_sync(
    copy_dir: &Path,
    files: &HashMap<String, PatchFileInfo>,
    project_root: &Path,
    module: &str,
    version: &str,
    base_rel: &str,
) -> bool {
    if tokio::fs::metadata(copy_dir).await.is_err() {
        return false;
    }
    for (file_name, info) in files {
        let path = copy_dir.join(normalize_file_path(file_name));
        match compute_file_git_sha256(&path).await {
            Ok(h) if h == info.after_hash => {}
            _ => return false,
        }
    }
    let expected = replace_target_path(base_rel, module, version);
    read_replace_entries(project_root).await.iter().any(|e| {
        e.module == module
            && e.socket_owned()
            && e.path.as_deref() == Some(expected.as_str())
            && e.version.as_deref() == Some(version)
    })
}

/// Synthesize Go's minimal `go.mod` (`module <path>`) in the copy iff it has
/// none — required for a `replace` target derived from a pre-modules package.
///
/// The copy under `.socket/go-patches/` is a *committed artifact* that the build
/// redirects to, so its `go.mod` is committed to the repo. Write it atomically
/// (stage + fsync + rename) rather than with a bare truncating `fs::write`: a
/// crash / power loss / `ENOSPC` mid-write would otherwise commit a torn or
/// empty `go.mod`. A reader (a concurrent `go build`, or the file landing in a
/// commit) then only ever sees the complete file, never a half-written one.
pub(crate) async fn ensure_module_go_mod(copy_dir: &Path, module: &str) -> std::io::Result<()> {
    let go_mod = copy_dir.join("go.mod");
    if tokio::fs::metadata(&go_mod).await.is_ok() {
        return Ok(());
    }
    atomic_write(&go_mod, format!("module {module}\n").as_bytes()).await
}

/// Atomically commit `content` to `path` via stage + fsync + rename, so a
/// reader/recovering process only ever sees the complete old or complete
/// new bytes of a synthesized `go.mod`. Delegates to the crate-wide
/// hardened writer.
async fn atomic_write(path: &Path, content: &[u8]) -> std::io::Result<()> {
    crate::utils::fs::atomic_write_bytes(path, content).await
}

fn synthesized_result(
    package_key: &str,
    copy_dir: &Path,
    files_verified: Vec<VerifyResult>,
    success: bool,
    error: Option<String>,
) -> ApplyResult {
    ApplyResult {
        package_key: package_key.to_string(),
        package_path: copy_dir.display().to_string(),
        success,
        files_verified,
        files_patched: Vec::new(),
        applied_via: HashMap::new(),
        error,
        sidecar: None,
    }
}

fn already_patched_verify(file: &str) -> VerifyResult {
    VerifyResult {
        file: file.to_string(),
        status: VerifyStatus::AlreadyPatched,
        message: None,
        current_hash: None,
        expected_hash: None,
        target_hash: None,
    }
}

/// Recursively find every patched-copy module dir under `go_patches_root`,
/// returning `(purl, dir)`. A module dir is identified by an `@` in its final
/// path component (`github.com/foo/bar@v1.4.2`); recursion stops there (the
/// module's own contents are not scanned). Returns empty if the root is absent.
async fn collect_copy_modules(go_patches_root: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    collect_copy_modules_inner(go_patches_root, String::new(), &mut out).await;
    out
}

fn collect_copy_modules_inner<'a>(
    dir: &'a Path,
    prefix: String,
    out: &'a mut Vec<(String, PathBuf)>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> {
    Box::pin(async move {
        let mut rd = match tokio::fs::read_dir(dir).await {
            Ok(rd) => rd,
            Err(_) => return,
        };
        while let Ok(Some(entry)) = rd.next_entry().await {
            if !entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(at) = name.rfind('@') {
                // `<name_before_@>` is the module's final path segment.
                let leaf = &name[..at];
                let version = &name[at + 1..];
                let module = if prefix.is_empty() {
                    leaf.to_string()
                } else {
                    format!("{prefix}/{leaf}")
                };
                if !module.is_empty() && !version.is_empty() {
                    out.push((build_golang_purl(&module, version), entry.path()));
                }
                // Do not recurse into a module dir.
            } else {
                let child_prefix = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}/{name}")
                };
                collect_copy_modules_inner(&entry.path(), child_prefix, out).await;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use std::collections::HashMap;

    const PRISTINE: &[u8] = b"package bar\n\nfunc Hello() string { return \"hi\" }\n";
    const PATCHED: &[u8] = b"package bar\n\nfunc Hello() string { return \"patched\" }\n";
    const MODULE: &str = "github.com/foo/bar";
    const VERSION: &str = "v1.4.2";
    const PURL: &str = "pkg:golang/github.com/foo/bar@v1.4.2";

    fn git_sha(bytes: &[u8]) -> String {
        compute_git_sha256_from_bytes(bytes)
    }

    /// Build a pristine module-cache-style dir (with go.mod) and a blobs dir
    /// carrying the patched bytes. Returns (tmp, blobs, pristine, files, after).
    async fn fixture() -> (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        HashMap<String, PatchFileInfo>,
        String,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();

        let pristine = root.join("cache/github.com/foo/bar@v1.4.2");
        tokio::fs::create_dir_all(&pristine).await.unwrap();
        tokio::fs::write(pristine.join("bar.go"), PRISTINE)
            .await
            .unwrap();
        tokio::fs::write(
            pristine.join("go.mod"),
            "module github.com/foo/bar\n\ngo 1.21\n",
        )
        .await
        .unwrap();

        let before = git_sha(PRISTINE);
        let after = git_sha(PATCHED);

        let blobs = root.join(".socket/blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        tokio::fs::write(blobs.join(&after), PATCHED).await.unwrap();

        let mut files = HashMap::new();
        files.insert(
            "package/bar.go".to_string(),
            PatchFileInfo {
                before_hash: before,
                after_hash: after.clone(),
            },
        );

        // The project root needs a go.mod for the replace directive.
        tokio::fs::write(
            root.join("go.mod"),
            "module example.com/app\n\ngo 1.21\n\nrequire github.com/foo/bar v1.4.2\n",
        )
        .await
        .unwrap();

        (dir, blobs, pristine, files, after)
    }

    fn manifest_with(files: &HashMap<String, PatchFileInfo>) -> PatchManifest {
        let mut m = PatchManifest::new();
        m.patches.insert(
            PURL.to_string(),
            crate::manifest::schema::PatchRecord {
                uuid: "u".into(),
                exported_at: "t".into(),
                files: files.clone(),
                vulnerabilities: HashMap::new(),
                description: String::new(),
                license: String::new(),
                tier: String::new(),
            },
        );
        m
    }

    #[tokio::test]
    async fn test_apply_redirect_happy_path() {
        let (dir, blobs, pristine, files, after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);

        let result = apply_go_redirect(
            PURL,
            MODULE,
            VERSION,
            &pristine,
            root,
            GO_PATCHES_DIR,
            &files,
            &sources,
            None,
            false,
            MismatchPolicy::Warn,
        )
        .await;
        assert!(result.success, "apply failed: {:?}", result.error);
        assert!(
            result.sidecar.is_none(),
            "replace copy must not emit a sidecar"
        );

        // Copy exists with patched bytes + a go.mod.
        let copy = root.join(".socket/go-patches/github.com/foo/bar@v1.4.2");
        let body = tokio::fs::read(copy.join("bar.go")).await.unwrap();
        assert_eq!(body, PATCHED);
        assert_eq!(git_sha(&body), after);
        assert!(copy.join("go.mod").exists());

        // Module cache pristine untouched.
        assert_eq!(
            tokio::fs::read(pristine.join("bar.go")).await.unwrap(),
            PRISTINE
        );

        // go.mod replace points at the copy.
        let entries = read_replace_entries(root).await;
        let e = entries.iter().find(|e| e.module == MODULE).unwrap();
        assert!(e.socket_owned());
        assert_eq!(
            e.path.as_deref(),
            Some("./.socket/go-patches/github.com/foo/bar@v1.4.2")
        );
        assert_eq!(e.version.as_deref(), Some(VERSION));
    }

    #[tokio::test]
    async fn test_apply_is_idempotent_byte_for_byte() {
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        apply_go_redirect(
            PURL,
            MODULE,
            VERSION,
            &pristine,
            root,
            GO_PATCHES_DIR,
            &files,
            &sources,
            None,
            false,
            MismatchPolicy::Warn,
        )
        .await;

        let copy = root.join(".socket/go-patches/github.com/foo/bar@v1.4.2/bar.go");
        let gomod = root.join("go.mod");
        let body1 = tokio::fs::read(&copy).await.unwrap();
        let mod1 = tokio::fs::read_to_string(&gomod).await.unwrap();

        let result = apply_go_redirect(
            PURL,
            MODULE,
            VERSION,
            &pristine,
            root,
            GO_PATCHES_DIR,
            &files,
            &sources,
            None,
            false,
            MismatchPolicy::Warn,
        )
        .await;
        assert!(result.success);
        assert!(
            result.files_patched.is_empty(),
            "in-sync resync patches nothing"
        );
        assert_eq!(
            tokio::fs::read(&copy).await.unwrap(),
            body1,
            "copy unchanged"
        );
        assert_eq!(
            tokio::fs::read_to_string(&gomod).await.unwrap(),
            mod1,
            "go.mod unchanged"
        );
    }

    #[tokio::test]
    async fn test_drift_triggers_rebuild() {
        let (dir, blobs, pristine, files, after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        apply_go_redirect(
            PURL,
            MODULE,
            VERSION,
            &pristine,
            root,
            GO_PATCHES_DIR,
            &files,
            &sources,
            None,
            false,
            MismatchPolicy::Warn,
        )
        .await;

        let copy = root.join(".socket/go-patches/github.com/foo/bar@v1.4.2/bar.go");
        tokio::fs::write(&copy, b"corrupted").await.unwrap();

        let result = apply_go_redirect(
            PURL,
            MODULE,
            VERSION,
            &pristine,
            root,
            GO_PATCHES_DIR,
            &files,
            &sources,
            None,
            false,
            MismatchPolicy::Warn,
        )
        .await;
        assert!(result.success);
        assert_eq!(git_sha(&tokio::fs::read(&copy).await.unwrap()), after);
    }

    #[tokio::test]
    async fn test_dry_run_writes_nothing() {
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        let pristine_gomod = tokio::fs::read_to_string(root.join("go.mod"))
            .await
            .unwrap();
        let sources = PatchSources::blobs_only(&blobs);
        let result = apply_go_redirect(
            PURL,
            MODULE,
            VERSION,
            &pristine,
            root,
            GO_PATCHES_DIR,
            &files,
            &sources,
            None,
            true,
            MismatchPolicy::Warn,
        )
        .await;
        assert!(result.success);
        assert!(!root
            .join(".socket/go-patches/github.com/foo/bar@v1.4.2")
            .exists());
        // go.mod unchanged (no replace added).
        assert_eq!(
            tokio::fs::read_to_string(root.join("go.mod"))
                .await
                .unwrap(),
            pristine_gomod
        );
    }

    #[tokio::test]
    async fn test_partial_failure_rolls_back_copy() {
        let (dir, _blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        let empty = root.join(".socket/empty-blobs");
        tokio::fs::create_dir_all(&empty).await.unwrap();
        let sources = PatchSources::blobs_only(&empty);

        let result = apply_go_redirect(
            PURL,
            MODULE,
            VERSION,
            &pristine,
            root,
            GO_PATCHES_DIR,
            &files,
            &sources,
            None,
            false,
            MismatchPolicy::Warn,
        )
        .await;
        assert!(!result.success);
        assert!(
            !root
                .join(".socket/go-patches/github.com/foo/bar@v1.4.2")
                .exists(),
            "half-built copy must be rolled back"
        );
        // No replace directive written.
        assert!(read_replace_entries(root).await.is_empty());
    }

    #[tokio::test]
    async fn test_synthesizes_go_mod_for_pre_modules_package() {
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        // Simulate a pre-modules package: remove the go.mod from the pristine src.
        tokio::fs::remove_file(pristine.join("go.mod"))
            .await
            .unwrap();
        let sources = PatchSources::blobs_only(&blobs);

        let result = apply_go_redirect(
            PURL,
            MODULE,
            VERSION,
            &pristine,
            root,
            GO_PATCHES_DIR,
            &files,
            &sources,
            None,
            false,
            MismatchPolicy::Warn,
        )
        .await;
        assert!(result.success, "apply failed: {:?}", result.error);
        let synthesized = root.join(".socket/go-patches/github.com/foo/bar@v1.4.2/go.mod");
        assert_eq!(
            tokio::fs::read_to_string(&synthesized).await.unwrap(),
            "module github.com/foo/bar\n"
        );
    }

    #[tokio::test]
    async fn test_synthesized_go_mod_is_atomic_no_litter() {
        // The synthesized go.mod must be committed atomically: after apply the
        // copy dir holds the real go.mod with the full `module …` line and NO
        // leftover `.socket-stage-*` sibling (a torn/empty go.mod or a stage-file
        // litter would be exactly the corruption the atomic writer prevents).
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        // Pre-modules package → synthesis path is exercised.
        tokio::fs::remove_file(pristine.join("go.mod"))
            .await
            .unwrap();
        let sources = PatchSources::blobs_only(&blobs);

        let result = apply_go_redirect(
            PURL,
            MODULE,
            VERSION,
            &pristine,
            root,
            GO_PATCHES_DIR,
            &files,
            &sources,
            None,
            false,
            MismatchPolicy::Warn,
        )
        .await;
        assert!(result.success, "apply failed: {:?}", result.error);

        let copy = root.join(".socket/go-patches/github.com/foo/bar@v1.4.2");
        assert_eq!(
            tokio::fs::read_to_string(copy.join("go.mod"))
                .await
                .unwrap(),
            "module github.com/foo/bar\n",
            "synthesized go.mod must be the complete module line, never torn/empty"
        );
        // No stage-file litter anywhere in the copy dir.
        let mut rd = tokio::fs::read_dir(&copy).await.unwrap();
        while let Ok(Some(e)) = rd.next_entry().await {
            let name = e.file_name().to_string_lossy().into_owned();
            assert!(
                !name.starts_with(".socket-stage-"),
                "stage file must be renamed away, found litter: {name}"
            );
        }
    }

    #[tokio::test]
    async fn test_remove_drops_directive_and_copy() {
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        apply_go_redirect(
            PURL,
            MODULE,
            VERSION,
            &pristine,
            root,
            GO_PATCHES_DIR,
            &files,
            &sources,
            None,
            false,
            MismatchPolicy::Warn,
        )
        .await;

        remove_go_redirect(PURL, root, GO_PATCHES_DIR, ReplaceOwner::GoPatches, false)
            .await
            .unwrap();
        assert!(!root
            .join(".socket/go-patches/github.com/foo/bar@v1.4.2")
            .exists());
        assert!(read_replace_entries(root).await.is_empty());
        // The require directive (not socket-owned) survives.
        assert!(tokio::fs::read_to_string(root.join("go.mod"))
            .await
            .unwrap()
            .contains("require github.com/foo/bar v1.4.2"));
    }

    #[tokio::test]
    async fn test_reconcile_prunes_orphan() {
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        apply_go_redirect(
            PURL,
            MODULE,
            VERSION,
            &pristine,
            root,
            GO_PATCHES_DIR,
            &files,
            &sources,
            None,
            false,
            MismatchPolicy::Warn,
        )
        .await;

        let desired: HashSet<String> = HashSet::new();
        let removed = reconcile_go_redirects(root, &desired, false).await;
        assert!(removed.contains(&PURL.to_string()));
        assert!(!root
            .join(".socket/go-patches/github.com/foo/bar@v1.4.2")
            .exists());
        assert!(read_replace_entries(root).await.is_empty());
    }

    #[tokio::test]
    async fn test_reconcile_keeps_desired_and_user_replaces() {
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        apply_go_redirect(
            PURL,
            MODULE,
            VERSION,
            &pristine,
            root,
            GO_PATCHES_DIR,
            &files,
            &sources,
            None,
            false,
            MismatchPolicy::Warn,
        )
        .await;
        // Add a user-authored replace.
        let mut body = tokio::fs::read_to_string(root.join("go.mod"))
            .await
            .unwrap();
        body.push_str("replace example.com/other v1.0.0 => ../other-fork\n");
        tokio::fs::write(root.join("go.mod"), body).await.unwrap();

        let desired: HashSet<String> = [PURL.to_string()].into_iter().collect();
        let removed = reconcile_go_redirects(root, &desired, false).await;
        assert!(removed.is_empty());
        let entries = read_replace_entries(root).await;
        assert!(entries
            .iter()
            .any(|e| e.module == MODULE && e.socket_owned()));
        assert!(entries
            .iter()
            .any(|e| e.module == "example.com/other" && !e.socket_owned()));
    }

    #[tokio::test]
    async fn test_verify_state_drift_kinds() {
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        apply_go_redirect(
            PURL,
            MODULE,
            VERSION,
            &pristine,
            root,
            GO_PATCHES_DIR,
            &files,
            &sources,
            None,
            false,
            MismatchPolicy::Warn,
        )
        .await;

        let manifest = manifest_with(&files);
        let desired: HashSet<String> = [PURL.to_string()].into_iter().collect();

        // Clean → Ok. Registry-independence: delete the pristine source first.
        tokio::fs::remove_dir_all(&pristine).await.unwrap();
        assert!(verify_go_redirect_state(root, &manifest, &desired)
            .await
            .is_ok());

        // Corrupt a file → StaleCopy.
        let copy = root.join(".socket/go-patches/github.com/foo/bar@v1.4.2/bar.go");
        tokio::fs::write(&copy, b"x").await.unwrap();
        let drifts = verify_go_redirect_state(root, &manifest, &desired)
            .await
            .unwrap_err();
        assert!(drifts.iter().any(|d| matches!(d, Drift::StaleCopy { .. })));

        // Delete the copy → MissingCopy (directive still present).
        tokio::fs::remove_dir_all(root.join(".socket/go-patches/github.com/foo/bar@v1.4.2"))
            .await
            .unwrap();
        let drifts = verify_go_redirect_state(root, &manifest, &desired)
            .await
            .unwrap_err();
        assert!(drifts
            .iter()
            .any(|d| matches!(d, Drift::MissingCopy { .. })));
        assert!(!drifts
            .iter()
            .any(|d| matches!(d, Drift::MissingReplace { .. })));
    }

    #[tokio::test]
    async fn test_verify_flags_missing_replace() {
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        apply_go_redirect(
            PURL,
            MODULE,
            VERSION,
            &pristine,
            root,
            GO_PATCHES_DIR,
            &files,
            &sources,
            None,
            false,
            MismatchPolicy::Warn,
        )
        .await;
        // Drop the directive but keep the copy.
        go_mod_edit::drop_replace_entry(root, MODULE, ReplaceOwner::GoPatches, false)
            .await
            .unwrap();

        let manifest = manifest_with(&files);
        let desired: HashSet<String> = [PURL.to_string()].into_iter().collect();
        let drifts = verify_go_redirect_state(root, &manifest, &desired)
            .await
            .unwrap_err();
        assert!(drifts
            .iter()
            .any(|d| matches!(d, Drift::MissingReplace { .. })));
    }

    #[tokio::test]
    async fn test_verify_flags_wrong_replace_version() {
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        apply_go_redirect(
            PURL,
            MODULE,
            VERSION,
            &pristine,
            root,
            GO_PATCHES_DIR,
            &files,
            &sources,
            None,
            false,
            MismatchPolicy::Warn,
        )
        .await;

        let manifest = manifest_with(&files);
        let desired: HashSet<String> = [PURL.to_string()].into_iter().collect();
        assert!(verify_go_redirect_state(root, &manifest, &desired)
            .await
            .is_ok());

        // Repin the socket-owned replace at a DIFFERENT version while the copy
        // stays byte-correct. Go keys replace by module+version, so this
        // silently links the unpatched module — verify must flag it.
        go_mod_edit::ensure_replace_entry(root, MODULE, "v9.9.9", GO_PATCHES_DIR, false)
            .await
            .unwrap();
        // ensure_replace refreshed our entry to v9.9.9; the v1.4.2 copy is now orphaned by directive.
        let drifts = verify_go_redirect_state(root, &manifest, &desired)
            .await
            .unwrap_err();
        assert!(
            drifts
                .iter()
                .any(|d| matches!(d, Drift::WrongReplacePath { .. })),
            "stale replace version must be flagged: {drifts:?}"
        );
    }

    #[tokio::test]
    async fn test_verify_flags_resolved_version_mismatch() {
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        apply_go_redirect(
            PURL,
            MODULE,
            VERSION,
            &pristine,
            root,
            GO_PATCHES_DIR,
            &files,
            &sources,
            None,
            false,
            MismatchPolicy::Warn,
        )
        .await;

        let manifest = manifest_with(&files);
        let desired: HashSet<String> = [PURL.to_string()].into_iter().collect();
        assert!(verify_go_redirect_state(root, &manifest, &desired)
            .await
            .is_ok());

        // go.mod requires a DIFFERENT version → the v1.4.2 patch is unused.
        tokio::fs::write(
            root.join("go.mod"),
            "module example.com/app\n\ngo 1.21\n\nrequire github.com/foo/bar v1.5.0\n\nreplace github.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2\n",
        )
        .await
        .unwrap();
        let drifts = verify_go_redirect_state(root, &manifest, &desired)
            .await
            .unwrap_err();
        assert!(drifts
            .iter()
            .any(|d| matches!(d, Drift::ResolvedVersionMismatch { .. })));
    }

    #[tokio::test]
    async fn test_verify_orphan_replace() {
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        apply_go_redirect(
            PURL,
            MODULE,
            VERSION,
            &pristine,
            root,
            GO_PATCHES_DIR,
            &files,
            &sources,
            None,
            false,
            MismatchPolicy::Warn,
        )
        .await;

        // Empty desired + empty manifest → the live directive is an orphan.
        let manifest = PatchManifest::new();
        let desired: HashSet<String> = HashSet::new();
        let drifts = verify_go_redirect_state(root, &manifest, &desired)
            .await
            .unwrap_err();
        assert!(drifts
            .iter()
            .any(|d| matches!(d, Drift::OrphanReplace { .. })));
    }

    #[tokio::test]
    async fn test_empty_files_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        tokio::fs::write(root.join("go.mod"), "module m\n\ngo 1.21\n")
            .await
            .unwrap();
        let blobs = root.join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        let sources = PatchSources::blobs_only(&blobs);
        let files = HashMap::new();
        let result = apply_go_redirect(
            PURL,
            MODULE,
            VERSION,
            root,
            root,
            GO_PATCHES_DIR,
            &files,
            &sources,
            None,
            false,
            MismatchPolicy::Warn,
        )
        .await;
        assert!(result.success);
        assert!(read_replace_entries(root).await.is_empty());
    }

    // ── filesystem-safety: coordinate traversal ──────────────────────────

    #[test]
    fn test_safe_redirect_coords() {
        // Legitimate multi-segment module + semver-ish version.
        assert!(are_safe_redirect_coords("github.com/foo/bar", "v1.4.2"));
        assert!(are_safe_redirect_coords("gopkg.in/inf.v0", "v0.9.1"));
        assert!(are_safe_redirect_coords(
            "github.com/foo/bar/v2",
            "v2.0.0-20210101000000-abcdef123456"
        ));
        // Traversal / escape attempts in the module.
        assert!(!are_safe_redirect_coords("../../../etc", "v1.0.0"));
        assert!(!are_safe_redirect_coords(
            "github.com/../../../etc",
            "v1.0.0"
        ));
        assert!(!are_safe_redirect_coords("/abs/path", "v1.0.0"));
        assert!(!are_safe_redirect_coords("github.com//bar", "v1.0.0")); // empty segment
        assert!(!are_safe_redirect_coords("foo/./bar", "v1.0.0"));
        assert!(!are_safe_redirect_coords("foo\\bar", "v1.0.0"));
        assert!(!are_safe_redirect_coords("", "v1.0.0"));
        // Traversal / separators in the version.
        assert!(!are_safe_redirect_coords(
            "github.com/foo/bar",
            "../../../evil"
        ));
        assert!(!are_safe_redirect_coords("github.com/foo/bar", "v1/0/0"));
        assert!(!are_safe_redirect_coords("github.com/foo/bar", ".."));
        assert!(!are_safe_redirect_coords("github.com/foo/bar", ""));
    }

    /// SECURITY regression: a leading drive-letter segment (`C:/evil`) passes
    /// the per-segment checks (it is not `.`/`..`, has no `\` and no leading
    /// `/`), but on Windows `Path::join` REPLACES the base path when handed an
    /// absolute path — so a tampered `pkg:golang/C:/evil@v1.0.0` would resolve
    /// the copy dir to `C:\evil@v1.0.0` and `fresh_copy`/`remove_tree` would
    /// write/delete there, outside `.socket/go-patches/`. A real Go module
    /// path element / version never contains `:` (letters, digits, `-._~`
    /// only), so rejecting it is fail-closed on every platform.
    #[test]
    fn test_safe_redirect_coords_reject_windows_drive() {
        assert!(!are_safe_redirect_coords("C:/evil", "v1.0.0"));
        assert!(!are_safe_redirect_coords("c:/evil", "v1.0.0"));
        assert!(!are_safe_redirect_coords("C:", "v1.0.0"));
        assert!(!are_safe_redirect_coords("github.com/foo/bar", "C:evil"));
    }

    /// A manifest key may carry `?qualifiers` / `#subpath` (the keys are raw
    /// API PURLs; `parse_golang_purl` strips both, which is why apply and
    /// verify tolerate them). Reconcile must compare desired PURLs by their
    /// canonical base — not raw string equality — or the just-applied copy of
    /// a qualified key is "pruned" as an orphan while its socket-owned
    /// `replace` survives (the module is still desired), leaving go.mod
    /// pointing at a deleted directory.
    #[tokio::test]
    async fn test_reconcile_keeps_qualified_desired_purl() {
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        let qualified = "pkg:golang/github.com/foo/bar@v1.4.2?type=module";
        // The CLI keys the copy off the parsed (qualifier-stripped) coords.
        let (module, version) = parse_golang_purl(qualified).unwrap();
        let result = apply_go_redirect(
            qualified,
            module,
            version,
            &pristine,
            root,
            GO_PATCHES_DIR,
            &files,
            &sources,
            None,
            false,
            MismatchPolicy::Warn,
        )
        .await;
        assert!(result.success, "apply failed: {:?}", result.error);

        let desired: HashSet<String> = [qualified.to_string()].into_iter().collect();
        let removed = reconcile_go_redirects(root, &desired, false).await;
        assert!(
            removed.is_empty(),
            "a desired (qualified) redirect must not be pruned: {removed:?}"
        );
        assert!(
            root.join(".socket/go-patches/github.com/foo/bar@v1.4.2")
                .exists(),
            "copy of a desired patch must survive reconcile"
        );
        assert!(
            read_replace_entries(root)
                .await
                .iter()
                .any(|e| e.module == MODULE && e.socket_owned()),
            "socket-owned replace must survive"
        );
    }

    /// SECURITY regression: a tampered manifest PURL with `..` in the module path
    /// must NOT let `apply` copy + write the patched tree outside
    /// `.socket/go-patches/`. Without the guard `copy_dir_for` would resolve to
    /// `<project>/.socket/go-patches/../../../escape@v1.0.0` and `fresh_copy`
    /// would materialise it there.
    #[tokio::test]
    async fn test_apply_rejects_traversal_module() {
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        let escaped = root.parent().unwrap().join("escape@v1.0.0");
        let _ = remove_tree(&escaped).await; // clear any stale copy

        let result = apply_go_redirect(
            "pkg:golang/../../../escape@v1.0.0",
            "../../../escape",
            "v1.0.0",
            &pristine,
            root,
            GO_PATCHES_DIR,
            &files,
            &sources,
            None,
            false,
            MismatchPolicy::Warn,
        )
        .await;

        assert!(!result.success, "traversal coordinates must be refused");
        assert!(
            result.error.as_deref().unwrap_or("").contains("unsafe"),
            "error should explain the refusal: {:?}",
            result.error
        );
        assert!(
            !escaped.exists(),
            "no copy may be written outside .socket/go-patches/ (found {})",
            escaped.display()
        );
        // go.mod was never touched (no replace directive added).
        assert!(read_replace_entries(root).await.is_empty());
        let _ = remove_tree(&escaped).await;
    }

    /// A `version` carrying a separator is equally rejected (it keys the copy dir
    /// and the `replace` path).
    #[tokio::test]
    async fn test_apply_rejects_traversal_version() {
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        let gomod_before = tokio::fs::read_to_string(root.join("go.mod"))
            .await
            .unwrap();
        let sources = PatchSources::blobs_only(&blobs);
        let result = apply_go_redirect(
            "pkg:golang/github.com/foo/bar@../../../evil",
            MODULE,
            "../../../evil",
            &pristine,
            root,
            GO_PATCHES_DIR,
            &files,
            &sources,
            None,
            false,
            MismatchPolicy::Warn,
        )
        .await;
        assert!(!result.success);
        // go.mod is byte-unchanged.
        assert_eq!(
            tokio::fs::read_to_string(root.join("go.mod"))
                .await
                .unwrap(),
            gomod_before
        );
    }

    /// SECURITY regression: `remove` must refuse unsafe coordinates rather than
    /// `remove_tree` a directory outside the project.
    #[tokio::test]
    async fn test_remove_rejects_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        tokio::fs::write(root.join("go.mod"), "module m\n\ngo 1.21\n")
            .await
            .unwrap();
        // A precious directory that is a sibling of the project root.
        let precious = root.parent().unwrap().join("precious@v1.0.0");
        tokio::fs::create_dir_all(&precious).await.unwrap();
        tokio::fs::write(precious.join("keep.txt"), b"keep")
            .await
            .unwrap();

        let err = remove_go_redirect(
            "pkg:golang/../../../precious@v1.0.0",
            root,
            GO_PATCHES_DIR,
            ReplaceOwner::GoPatches,
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            precious.exists() && precious.join("keep.txt").exists(),
            "remove must not delete a tree outside the project"
        );
        tokio::fs::remove_dir_all(&precious).await.unwrap();
    }

    /// SECURITY regression: an audit must not stat/hash files outside the tree
    /// for an unsafe coordinate — it is skipped, not chased through `..`.
    #[tokio::test]
    async fn test_verify_skips_unsafe_coords() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        tokio::fs::write(root.join("go.mod"), "module m\n\ngo 1.21\n")
            .await
            .unwrap();

        let unsafe_purl = "pkg:golang/../../../escape@v1.0.0";
        let mut manifest = PatchManifest::new();
        let mut files = HashMap::new();
        files.insert(
            "package/x.go".to_string(),
            PatchFileInfo {
                before_hash: "b".into(),
                after_hash: "a".into(),
            },
        );
        manifest.patches.insert(
            unsafe_purl.to_string(),
            crate::manifest::schema::PatchRecord {
                uuid: "u".into(),
                exported_at: "t".into(),
                files,
                vulnerabilities: HashMap::new(),
                description: String::new(),
                license: String::new(),
                tier: String::new(),
            },
        );
        let desired: HashSet<String> = [unsafe_purl.to_string()].into_iter().collect();
        // The unsafe coord is silently skipped → no drift (and no escape-stat).
        assert!(verify_go_redirect_state(root, &manifest, &desired)
            .await
            .is_ok());
    }

    #[test]
    fn test_collect_copy_modules_reconstructs_nested_purl() {
        // Pure-ish check of the path→PURL reconstruction via build_golang_purl.
        assert_eq!(
            build_golang_purl("github.com/foo/bar", "v1.4.2"),
            "pkg:golang/github.com/foo/bar@v1.4.2"
        );
    }
}
