//! Project-local cargo `[patch]`-redirect engine (local mode only).
//!
//! Instead of patching crates in place in the shared registry (the `--global`
//! path, still served by [`crate::patch::sidecars::cargo`]), this materialises
//! a project-local **patched copy** of each crate under
//! `<root>/.socket/cargo-patches/<name>-<version>/` and points cargo at it with
//! a `[patch.crates-io]` entry in `<root>/.cargo/config.toml`. Patches become
//! project-scoped, the `.cargo-checksum.json` rewrite disappears (a `[patch]`
//! path-dep is not checksum-verified), and removal is clean (drop the entry →
//! cargo falls back to the pristine registry).
//!
//! The copy is produced by **delegating to the hardened
//! [`apply_package_patch`] pipeline** pointed at the fresh copy, so all the
//! verify → package/diff/blob → atomic-write machinery is reused unchanged.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::manifest::schema::{PatchFileInfo, PatchManifest};
use crate::patch::apply::{
    apply_package_patch, normalize_file_path, ApplyResult, PatchSources, VerifyResult, VerifyStatus,
};
use crate::patch::file_hash::compute_file_git_sha256;
use crate::utils::purl::{build_cargo_purl, parse_cargo_purl};

use super::cargo_config::{self, expected_patch_path, CARGO_PATCHES_DIR};

/// A discrepancy between the committed redirect artifacts and the manifest,
/// reported by [`verify_cargo_redirect_state`].
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
    /// No managed `[patch.crates-io]` entry exists for an in-scope PURL.
    MissingEntry { purl: String },
    /// A socket-owned `[patch.crates-io]` entry exists with no desired PURL.
    OrphanEntry { name: String },
    /// `Cargo.lock` resolved this crate to version(s) that do NOT include the
    /// patched version, so cargo's `[patch]` (keyed by name+version) is unused
    /// and the build silently links the UNPATCHED registry crate.
    ResolvedVersionMismatch {
        purl: String,
        patched_version: String,
        locked_versions: Vec<String>,
    },
}

impl std::fmt::Display for Drift {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Drift::MissingCopy { purl } => {
                write!(f, "missing patched copy for {purl}")
            }
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
            Drift::MissingEntry { purl } => {
                write!(f, "missing [patch.crates-io] entry for {purl}")
            }
            Drift::OrphanEntry { name } => {
                write!(
                    f,
                    "orphan [patch.crates-io] entry `{name}` (no patch in manifest)"
                )
            }
            Drift::ResolvedVersionMismatch {
                purl,
                patched_version,
                locked_versions,
            } => write!(
                f,
                "{purl}: patched version {patched_version} is not the resolved version \
                 (Cargo.lock has {}) — cargo would link the UNPATCHED crate",
                locked_versions.join(", ")
            ),
        }
    }
}

/// Parse `<root>/Cargo.lock` into `name -> {resolved versions}`. Returns `None`
/// when the lockfile is absent/unreadable (the version cross-check is then
/// skipped — e.g. libraries that don't commit a lockfile). Reads only the
/// project lockfile: no registry, no network.
async fn read_locked_versions(project_root: &Path) -> Option<HashMap<String, HashSet<String>>> {
    let content = tokio::fs::read_to_string(project_root.join("Cargo.lock"))
        .await
        .ok()?;
    let doc = content.parse::<toml_edit::DocumentMut>().ok()?;
    let pkgs = doc.get("package")?.as_array_of_tables()?;
    let mut map: HashMap<String, HashSet<String>> = HashMap::new();
    for t in pkgs.iter() {
        let name = t.get("name").and_then(|i| i.as_str());
        let ver = t.get("version").and_then(|i| i.as_str());
        if let (Some(n), Some(v)) = (name, ver) {
            map.entry(n.to_string()).or_default().insert(v.to_string());
        }
    }
    Some(map)
}

/// True if a crate is vendored under `<project_root>/vendor/` (in either the
/// `<name>-<version>/` or bare `<name>/` layout the cargo crawler probes).
/// Vendored crates are patched in place, so they are excluded from redirect
/// verification.
async fn is_vendored(project_root: &Path, name: &str, version: &str) -> bool {
    let vendor = project_root.join("vendor");
    for candidate in [vendor.join(format!("{name}-{version}")), vendor.join(name)] {
        if tokio::fs::metadata(&candidate)
            .await
            .map(|m| m.is_dir())
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

/// The project-relative copy dir for a crate.
fn copy_dir_for(project_root: &Path, name: &str, version: &str) -> PathBuf {
    project_root
        .join(CARGO_PATCHES_DIR)
        .join(format!("{name}-{version}"))
}

/// Materialise a project-local patched copy and wire up the `[patch]` redirect.
///
/// * `pristine_src` — the pristine registry/vendor source dir (the crawler's
///   `pkg_path`). It is copied, never mutated.
/// * `project_root` — the consumer project (`args.common.cwd`).
///
/// `dry_run` writes nothing (it verifies against `pristine_src` for an accurate
/// report). `force` is forwarded to [`apply_package_patch`].
#[allow(clippy::too_many_arguments)]
pub async fn apply_cargo_redirect(
    purl: &str,
    name: &str,
    version: &str,
    pristine_src: &Path,
    project_root: &Path,
    files: &HashMap<String, PatchFileInfo>,
    sources: &PatchSources<'_>,
    uuid: Option<&str>,
    dry_run: bool,
    force: bool,
) -> ApplyResult {
    let copy_dir = copy_dir_for(project_root, name, version);

    // A redirect with no files to patch is meaningless: no-op success, no
    // config write.
    if files.is_empty() {
        return synthesized_result(purl, &copy_dir, Vec::new(), true, None);
    }

    if dry_run {
        // Verify (read-only) against the pristine source — apply_package_patch
        // never writes when dry_run — for an accurate "would patch" report,
        // without creating the copy or editing config.
        let mut result =
            apply_package_patch(purl, pristine_src, files, sources, uuid, true, force).await;
        result.package_path = copy_dir.display().to_string();
        return result;
    }

    // Hot path: already in sync → touch nothing, so cargo's source fingerprint
    // stays stable across repeated applies (the guard re-runs apply on most
    // "deps changed" builds).
    if redirect_in_sync(&copy_dir, files, project_root, name, version).await {
        let verified = files.keys().map(|f| already_patched_verify(f)).collect();
        return synthesized_result(purl, &copy_dir, verified, true, None);
    }

    // Fresh copy pristine → copy_dir, excluding any `.cargo-checksum.json`.
    if let Err(e) = fresh_copy_excluding_checksum(pristine_src, &copy_dir).await {
        return synthesized_result(
            purl,
            &copy_dir,
            Vec::new(),
            false,
            Some(format!("failed to copy pristine source: {e}")),
        );
    }

    // Delegate to the hardened pipeline, pointed at the copy.
    let mut result = apply_package_patch(purl, &copy_dir, files, sources, uuid, false, force).await;
    result.package_path = copy_dir.display().to_string();

    if !result.success {
        // Don't leave a half-built copy that verify/reconcile would misjudge.
        let _ = remove_tree(&copy_dir).await;
        return result;
    }

    // A path-dep copy must never carry a checksum sidecar (its presence would
    // make dispatch_fixup rewrite it). The fresh copy excluded it; enforce the
    // invariant defensively.
    let _ = tokio::fs::remove_file(copy_dir.join(".cargo-checksum.json")).await;
    debug_assert!(
        result.sidecar.is_none(),
        "redirect copy must not produce a cargo sidecar"
    );

    // Wire up the [patch.crates-io] entry. This is load-bearing: without it
    // cargo won't redirect to the copy, so a failure here fails the apply.
    if let Err(e) = cargo_config::ensure_patch_entry(project_root, name, version, false).await {
        result.success = false;
        result.error = Some(format!("failed to update .cargo/config.toml: {e}"));
        return result;
    }
    // [env] SOCKET_PATCH_ROOT is only needed by the runtime hook; best-effort.
    let _ = cargo_config::ensure_env_root(project_root, false).await;

    result
}

/// Drop the managed `[patch]` entry + patched copy for a cargo PURL. Removes
/// only *patch* state — never the `[env] SOCKET_PATCH_ROOT` setup state (that
/// is owned by `setup` / `setup --remove`), so a `rollback` leaves the guard
/// wiring intact.
pub async fn remove_cargo_redirect(
    purl: &str,
    project_root: &Path,
    dry_run: bool,
) -> Result<(), std::io::Error> {
    let (name, version) = parse_cargo_purl(purl).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("not a cargo purl: {purl}"),
        )
    })?;

    cargo_config::drop_patch_entry(project_root, name, dry_run)
        .await
        .map_err(std::io::Error::other)?;

    if !dry_run {
        let copy_dir = copy_dir_for(project_root, name, version);
        let _ = remove_tree(&copy_dir).await; // ignore NotFound
    }
    // NOTE: `[env] SOCKET_PATCH_ROOT` is intentionally left in place — it is
    // setup state, removed only by `setup --remove`, not by a patch rollback.
    Ok(())
}

/// Prune socket-owned `[patch]` entries + copy dirs that are no longer in
/// `desired` (patches dropped from the manifest). Returns the removed PURLs.
pub async fn reconcile_cargo_redirects(
    project_root: &Path,
    desired: &HashSet<String>,
    dry_run: bool,
) -> Vec<String> {
    let desired_names: HashSet<&str> = desired
        .iter()
        .filter_map(|p| parse_cargo_purl(p).map(|(n, _)| n))
        .collect();

    let mut removed: Vec<String> = Vec::new();

    // (a) Orphan socket-owned [patch.crates-io] entries.
    let entries = cargo_config::read_patch_entries(project_root).await;
    for (name, info) in &entries {
        if info.socket_owned && !desired_names.contains(name.as_str()) {
            let _ = cargo_config::drop_patch_entry(project_root, name, dry_run).await;
            if let Some(purl) = purl_from_entry_path(info.path.as_deref()) {
                if !removed.contains(&purl) {
                    removed.push(purl);
                }
            }
        }
    }

    // (b) Orphan copy dirs not referenced by a desired PURL.
    let copies_root = project_root.join(CARGO_PATCHES_DIR);
    if let Ok(mut rd) = tokio::fs::read_dir(&copies_root).await {
        while let Ok(Some(entry)) = rd.next_entry().await {
            if !entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let dir_name = entry.file_name().to_string_lossy().to_string();
            if let Some(purl) = purl_from_dir_name(&dir_name) {
                if !desired.contains(&purl) {
                    if !dry_run {
                        let _ = remove_tree(&entry.path()).await;
                    }
                    if !removed.contains(&purl) {
                        removed.push(purl);
                    }
                }
            }
        }
    }

    // NOTE: `[env] SOCKET_PATCH_ROOT` is intentionally NOT dropped here — it is
    // setup state (owned by `setup` / `setup --remove`), independent of whether
    // any redirects currently remain.

    removed
}

/// Registry-independent verification for `apply --check` (CI / GitHub-App
/// auditing). Reads **only** the manifest, the committed copies, and
/// `.cargo/config.toml` — never the registry, no network, no `pristine_src` —
/// so it works on a fresh clone / airgapped CI where the registry crate isn't
/// extracted but the copies are present.
pub async fn verify_cargo_redirect_state(
    project_root: &Path,
    manifest: &PatchManifest,
    desired: &HashSet<String>,
) -> Result<(), Vec<Drift>> {
    let mut drifts = Vec::new();
    let entries = cargo_config::read_patch_entries(project_root).await;
    // Resolved versions from Cargo.lock (None ⇒ no lockfile ⇒ skip the version
    // cross-check). Read once, project-local, offline.
    let locked = read_locked_versions(project_root).await;
    let desired_names: HashSet<&str> = desired
        .iter()
        .filter_map(|p| parse_cargo_purl(p).map(|(n, _)| n))
        .collect();

    for purl in desired {
        let Some((name, version)) = parse_cargo_purl(purl) else {
            continue;
        };
        let Some(record) = manifest.patches.get(purl) else {
            continue;
        };
        // Vendored crates are patched in place, not redirected, so they have
        // no copy/entry by design — skip them. The crawler stores vendored
        // crates under `<root>/vendor/` in either `<name>-<version>/` or bare
        // `<name>/` layout; check both. The `vendor/` dir is committed, so this
        // stays registry- and network-independent.
        if is_vendored(project_root, name, version).await {
            continue;
        }

        // Cargo.lock cross-check: if the crate resolved to version(s) that do
        // NOT include the patched version, cargo's `[patch]` is unused and the
        // build links the unpatched crate — a silent-stale hole the copy/entry
        // checks below can't see. (A crate absent from the lock is harmless —
        // it isn't built — so we only flag a present-but-different resolution.)
        if let Some(versions) = locked.as_ref().and_then(|l| l.get(name)) {
            if !versions.contains(version) {
                let mut locked_versions: Vec<String> = versions.iter().cloned().collect();
                locked_versions.sort();
                drifts.push(Drift::ResolvedVersionMismatch {
                    purl: purl.clone(),
                    patched_version: version.to_string(),
                    locked_versions,
                });
            }
        }

        let copy_dir = copy_dir_for(project_root, name, version);

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

        match entries.get(name) {
            Some(info) if info.socket_owned => {}
            _ => drifts.push(Drift::MissingEntry { purl: purl.clone() }),
        }
    }

    for (name, info) in &entries {
        if info.socket_owned && !desired_names.contains(name.as_str()) {
            drifts.push(Drift::OrphanEntry { name: name.clone() });
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
/// `afterHash`, and the config entry points at the expected copy path.
async fn redirect_in_sync(
    copy_dir: &Path,
    files: &HashMap<String, PatchFileInfo>,
    project_root: &Path,
    name: &str,
    version: &str,
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
    let entries = cargo_config::read_patch_entries(project_root).await;
    match entries.get(name) {
        Some(info) => info.path.as_deref() == Some(expected_patch_path(name, version).as_str()),
        None => false,
    }
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

fn purl_from_entry_path(path: Option<&str>) -> Option<String> {
    let norm = path?.replace('\\', "/");
    let dir_name = norm.rsplit('/').next()?;
    purl_from_dir_name(dir_name)
}

fn purl_from_dir_name(dir_name: &str) -> Option<String> {
    let (name, version) = crate::crawlers::CargoCrawler::parse_dir_name_version(dir_name)?;
    Some(build_cargo_purl(&name, &version))
}

fn to_io<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Fresh-copy `src` → `dst`, removing `dst` first and excluding any
/// `.cargo-checksum.json` at any level. Runs on the blocking pool (registry
/// sources are bounded, <10 MB unpacked). Directories are created fresh
/// (writable `0o755`) rather than mirroring the registry's read-only modes, so
/// the copy can be patched and later removed without a chmod dance.
async fn fresh_copy_excluding_checksum(src: &Path, dst: &Path) -> std::io::Result<()> {
    let src = src.to_path_buf();
    let dst = dst.to_path_buf();
    tokio::task::spawn_blocking(move || {
        force_remove_dir_all(&dst)?;
        std::fs::create_dir_all(&dst)?;
        for entry in walkdir::WalkDir::new(&src).follow_links(false) {
            let entry = entry.map_err(to_io)?;
            let rel = entry.path().strip_prefix(&src).map_err(to_io)?;
            if rel.as_os_str().is_empty() {
                continue;
            }
            if entry.file_name() == ".cargo-checksum.json" {
                continue;
            }
            let target = dst.join(rel);
            let ft = entry.file_type();
            if ft.is_dir() {
                std::fs::create_dir_all(&target)?;
            } else if ft.is_file() {
                if let Some(p) = target.parent() {
                    std::fs::create_dir_all(p)?;
                }
                std::fs::copy(entry.path(), &target)?;
            }
            // Symlinks / specials: crates.io registry sources contain none, so
            // skip them rather than risk copying a dangling link.
        }
        Ok(())
    })
    .await
    .map_err(|e| std::io::Error::other(e.to_string()))?
}

/// Recursively remove a tree, retrying once after relaxing perms (a previously
/// patched copy may carry read-only file modes restored from the registry).
fn force_remove_dir_all(dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                for entry in walkdir::WalkDir::new(dir).into_iter().flatten() {
                    let mode = if entry.file_type().is_dir() {
                        0o755
                    } else {
                        0o644
                    };
                    let _ = std::fs::set_permissions(
                        entry.path(),
                        std::fs::Permissions::from_mode(mode),
                    );
                }
            }
            std::fs::remove_dir_all(dir)
        }
    }
}

async fn remove_tree(dir: &Path) -> std::io::Result<()> {
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || force_remove_dir_all(&dir))
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use std::collections::HashMap;

    const PRISTINE: &[u8] = b"pub fn cfg() {}\n";
    const PATCHED: &[u8] = b"pub fn cfg() { /* patched */ }\n";

    fn git_sha(bytes: &[u8]) -> String {
        compute_git_sha256_from_bytes(bytes)
    }

    /// Build a pristine registry-style crate dir with a checksum sidecar and a
    /// blobs dir carrying the patched bytes. Returns (project_root, blobs_dir,
    /// pristine_src, files, after_hash).
    async fn fixture() -> (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        HashMap<String, PatchFileInfo>,
        String,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();

        // Pristine source dir (simulating an extracted registry crate).
        let pristine = root.join("registry/cfg-if-1.0.0");
        tokio::fs::create_dir_all(pristine.join("src"))
            .await
            .unwrap();
        tokio::fs::write(pristine.join("src/lib.rs"), PRISTINE)
            .await
            .unwrap();
        tokio::fs::write(
            pristine.join("Cargo.toml"),
            "[package]\nname=\"cfg-if\"\nversion=\"1.0.0\"\n",
        )
        .await
        .unwrap();
        tokio::fs::write(pristine.join(".cargo-checksum.json"), "{\"files\":{}}")
            .await
            .unwrap();

        let before = git_sha(PRISTINE);
        let after = git_sha(PATCHED);

        // Blobs dir with the patched content keyed by afterHash.
        let blobs = root.join(".socket/blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        tokio::fs::write(blobs.join(&after), PATCHED).await.unwrap();

        let mut files = HashMap::new();
        files.insert(
            "package/src/lib.rs".to_string(),
            PatchFileInfo {
                before_hash: before,
                after_hash: after.clone(),
            },
        );

        (dir, blobs, pristine, files, after)
    }

    #[tokio::test]
    async fn test_apply_redirect_happy_path() {
        let (dir, blobs, pristine, files, after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);

        let result = apply_cargo_redirect(
            "pkg:cargo/cfg-if@1.0.0",
            "cfg-if",
            "1.0.0",
            &pristine,
            root,
            &files,
            &sources,
            None,
            false,
            false,
        )
        .await;
        assert!(result.success, "apply failed: {:?}", result.error);
        assert!(
            result.sidecar.is_none(),
            "redirect copy must not emit a sidecar"
        );

        // Copy exists with patched bytes and NO checksum sidecar.
        let copy = root.join(".socket/cargo-patches/cfg-if-1.0.0");
        let lib = tokio::fs::read(copy.join("src/lib.rs")).await.unwrap();
        assert_eq!(lib, PATCHED);
        assert!(!copy.join(".cargo-checksum.json").exists());

        // Registry pristine is untouched.
        let reg = tokio::fs::read(pristine.join("src/lib.rs")).await.unwrap();
        assert_eq!(reg, PRISTINE);

        // Config entry points at the copy.
        let entries = cargo_config::read_patch_entries(root).await;
        assert_eq!(
            entries["cfg-if"].path.as_deref(),
            Some(".socket/cargo-patches/cfg-if-1.0.0")
        );
        assert_eq!(git_sha(&lib), after);
    }

    #[tokio::test]
    async fn test_apply_is_idempotent_byte_for_byte() {
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        let args = ("pkg:cargo/cfg-if@1.0.0", "cfg-if", "1.0.0");

        apply_cargo_redirect(
            args.0, args.1, args.2, &pristine, root, &files, &sources, None, false, false,
        )
        .await;
        let copy = root.join(".socket/cargo-patches/cfg-if-1.0.0/src/lib.rs");
        let cfg = root.join(".cargo/config.toml");
        let lib1 = tokio::fs::read(&copy).await.unwrap();
        let cfg1 = tokio::fs::read_to_string(&cfg).await.unwrap();

        // Second apply must hit the in-sync short-circuit: no rewrite.
        let result = apply_cargo_redirect(
            args.0, args.1, args.2, &pristine, root, &files, &sources, None, false, false,
        )
        .await;
        assert!(result.success);
        // The synthesized in-sync result reports AlreadyPatched, patches nothing.
        assert!(result.files_patched.is_empty());
        let lib2 = tokio::fs::read(&copy).await.unwrap();
        let cfg2 = tokio::fs::read_to_string(&cfg).await.unwrap();
        assert_eq!(lib1, lib2, "copy bytes must be unchanged on resync");
        assert_eq!(cfg1, cfg2, "config must be unchanged on resync");
    }

    #[tokio::test]
    async fn test_drift_triggers_rebuild() {
        let (dir, blobs, pristine, files, after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        apply_cargo_redirect(
            "pkg:cargo/cfg-if@1.0.0",
            "cfg-if",
            "1.0.0",
            &pristine,
            root,
            &files,
            &sources,
            None,
            false,
            false,
        )
        .await;

        // Corrupt the copy.
        let copy = root.join(".socket/cargo-patches/cfg-if-1.0.0/src/lib.rs");
        tokio::fs::write(&copy, b"corrupted").await.unwrap();

        // Re-apply repairs it.
        let result = apply_cargo_redirect(
            "pkg:cargo/cfg-if@1.0.0",
            "cfg-if",
            "1.0.0",
            &pristine,
            root,
            &files,
            &sources,
            None,
            false,
            false,
        )
        .await;
        assert!(result.success);
        assert_eq!(git_sha(&tokio::fs::read(&copy).await.unwrap()), after);
    }

    #[tokio::test]
    async fn test_dry_run_writes_nothing() {
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        let result = apply_cargo_redirect(
            "pkg:cargo/cfg-if@1.0.0",
            "cfg-if",
            "1.0.0",
            &pristine,
            root,
            &files,
            &sources,
            None,
            true,
            false,
        )
        .await;
        assert!(result.success);
        assert!(!root.join(".socket/cargo-patches/cfg-if-1.0.0").exists());
        assert!(!root.join(".cargo/config.toml").exists());
    }

    #[tokio::test]
    async fn test_partial_failure_rolls_back_copy() {
        let (dir, _blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        // Empty blobs dir → the blob read fails mid-apply.
        let empty_blobs = root.join(".socket/empty-blobs");
        tokio::fs::create_dir_all(&empty_blobs).await.unwrap();
        let sources = PatchSources::blobs_only(&empty_blobs);

        let result = apply_cargo_redirect(
            "pkg:cargo/cfg-if@1.0.0",
            "cfg-if",
            "1.0.0",
            &pristine,
            root,
            &files,
            &sources,
            None,
            false,
            false,
        )
        .await;
        assert!(!result.success);
        assert!(
            !root.join(".socket/cargo-patches/cfg-if-1.0.0").exists(),
            "half-built copy must be rolled back"
        );
        // No config entry was written.
        assert!(cargo_config::read_patch_entries(root).await.is_empty());
    }

    #[tokio::test]
    async fn test_remove_drops_entry_and_copy() {
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        apply_cargo_redirect(
            "pkg:cargo/cfg-if@1.0.0",
            "cfg-if",
            "1.0.0",
            &pristine,
            root,
            &files,
            &sources,
            None,
            false,
            false,
        )
        .await;

        // apply wired the [env] root.
        assert!(cargo_config::env_root_present(root).await);

        remove_cargo_redirect("pkg:cargo/cfg-if@1.0.0", root, false)
            .await
            .unwrap();
        assert!(!root.join(".socket/cargo-patches/cfg-if-1.0.0").exists());
        assert!(!cargo_config::read_patch_entries(root)
            .await
            .contains_key("cfg-if"));
        // Rollback removes patch state only — the [env] setup state survives.
        assert!(
            cargo_config::env_root_present(root).await,
            "rollback must NOT remove [env] SOCKET_PATCH_ROOT (setup state)"
        );
    }

    #[tokio::test]
    async fn test_reconcile_prunes_orphan() {
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        apply_cargo_redirect(
            "pkg:cargo/cfg-if@1.0.0",
            "cfg-if",
            "1.0.0",
            &pristine,
            root,
            &files,
            &sources,
            None,
            false,
            false,
        )
        .await;

        // Desired set no longer contains cfg-if → it's an orphan.
        let desired: HashSet<String> = HashSet::new();
        let removed = reconcile_cargo_redirects(root, &desired, false).await;
        assert!(removed.contains(&"pkg:cargo/cfg-if@1.0.0".to_string()));
        assert!(!root.join(".socket/cargo-patches/cfg-if-1.0.0").exists());
        assert!(cargo_config::read_patch_entries(root).await.is_empty());
        // Even when the last redirect is pruned, [env] (setup state) survives.
        assert!(
            cargo_config::env_root_present(root).await,
            "reconcile must NOT remove [env] SOCKET_PATCH_ROOT (setup state)"
        );
    }

    #[tokio::test]
    async fn test_reconcile_keeps_desired_and_user_entries() {
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        apply_cargo_redirect(
            "pkg:cargo/cfg-if@1.0.0",
            "cfg-if",
            "1.0.0",
            &pristine,
            root,
            &files,
            &sources,
            None,
            false,
            false,
        )
        .await;
        // Add a user-authored entry directly.
        let cfg = root.join(".cargo/config.toml");
        let mut body = tokio::fs::read_to_string(&cfg).await.unwrap();
        body.push_str("mine = { git = \"https://example.com/m.git\" }\n");
        // Insert the user entry into the existing [patch.crates-io] table.
        let body = body.replace(
            "[patch.crates-io]\n",
            "[patch.crates-io]\nmine = { git = \"https://example.com/m.git\" }\n",
        );
        tokio::fs::write(&cfg, body).await.unwrap();

        let desired: HashSet<String> = ["pkg:cargo/cfg-if@1.0.0".to_string()].into_iter().collect();
        let removed = reconcile_cargo_redirects(root, &desired, false).await;
        assert!(removed.is_empty());
        let entries = cargo_config::read_patch_entries(root).await;
        assert!(entries.contains_key("cfg-if"));
        assert!(entries.contains_key("mine"));
    }

    #[tokio::test]
    async fn test_verify_state_drift_kinds() {
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        apply_cargo_redirect(
            "pkg:cargo/cfg-if@1.0.0",
            "cfg-if",
            "1.0.0",
            &pristine,
            root,
            &files,
            &sources,
            None,
            false,
            false,
        )
        .await;

        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:cargo/cfg-if@1.0.0".to_string(),
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
        let desired: HashSet<String> = ["pkg:cargo/cfg-if@1.0.0".to_string()].into_iter().collect();

        // Clean → Ok. Registry-independence: delete the pristine source first.
        tokio::fs::remove_dir_all(&pristine).await.unwrap();
        assert!(verify_cargo_redirect_state(root, &manifest, &desired)
            .await
            .is_ok());

        // Corrupt a file → StaleCopy.
        let copy = root.join(".socket/cargo-patches/cfg-if-1.0.0/src/lib.rs");
        tokio::fs::write(&copy, b"x").await.unwrap();
        let drifts = verify_cargo_redirect_state(root, &manifest, &desired)
            .await
            .unwrap_err();
        assert!(drifts.iter().any(|d| matches!(d, Drift::StaleCopy { .. })));

        // Delete the copy → MissingCopy (the config entry is still present).
        tokio::fs::remove_dir_all(root.join(".socket/cargo-patches/cfg-if-1.0.0"))
            .await
            .unwrap();
        let drifts = verify_cargo_redirect_state(root, &manifest, &desired)
            .await
            .unwrap_err();
        assert!(drifts
            .iter()
            .any(|d| matches!(d, Drift::MissingCopy { .. })));
        assert!(!drifts
            .iter()
            .any(|d| matches!(d, Drift::MissingEntry { .. })));

        // Now drop the config entry too → MissingEntry.
        cargo_config::drop_patch_entry(root, "cfg-if", false)
            .await
            .unwrap();
        let drifts = verify_cargo_redirect_state(root, &manifest, &desired)
            .await
            .unwrap_err();
        assert!(drifts
            .iter()
            .any(|d| matches!(d, Drift::MissingEntry { .. })));
    }

    #[tokio::test]
    async fn test_verify_flags_resolved_version_mismatch() {
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        apply_cargo_redirect(
            "pkg:cargo/cfg-if@1.0.0",
            "cfg-if",
            "1.0.0",
            &pristine,
            root,
            &files,
            &sources,
            None,
            false,
            false,
        )
        .await;

        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:cargo/cfg-if@1.0.0".to_string(),
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
        let desired: HashSet<String> = ["pkg:cargo/cfg-if@1.0.0".to_string()].into_iter().collect();

        // Cargo.lock resolves cfg-if to 1.0.1 — the 1.0.0 patch is unused, so
        // cargo would link the UNPATCHED crate → drift, even though the copy is
        // byte-correct for the 1.0.0 entry.
        tokio::fs::write(
            root.join("Cargo.lock"),
            "[[package]]\nname = \"cfg-if\"\nversion = \"1.0.1\"\n",
        )
        .await
        .unwrap();
        let drifts = verify_cargo_redirect_state(root, &manifest, &desired)
            .await
            .unwrap_err();
        assert!(drifts
            .iter()
            .any(|d| matches!(d, Drift::ResolvedVersionMismatch { .. })));

        // Lock resolves the patched version 1.0.0 → no mismatch (clean).
        tokio::fs::write(
            root.join("Cargo.lock"),
            "[[package]]\nname = \"cfg-if\"\nversion = \"1.0.0\"\n",
        )
        .await
        .unwrap();
        assert!(verify_cargo_redirect_state(root, &manifest, &desired)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_verify_orphan_entry() {
        let (dir, blobs, pristine, files, _after) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        apply_cargo_redirect(
            "pkg:cargo/cfg-if@1.0.0",
            "cfg-if",
            "1.0.0",
            &pristine,
            root,
            &files,
            &sources,
            None,
            false,
            false,
        )
        .await;

        // Empty desired set + empty manifest → the live entry is an orphan.
        let manifest = PatchManifest::new();
        let desired: HashSet<String> = HashSet::new();
        let drifts = verify_cargo_redirect_state(root, &manifest, &desired)
            .await
            .unwrap_err();
        assert!(drifts
            .iter()
            .any(|d| matches!(d, Drift::OrphanEntry { .. })));
    }

    #[tokio::test]
    async fn test_empty_files_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let blobs = root.join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        let sources = PatchSources::blobs_only(&blobs);
        let files = HashMap::new();
        let result = apply_cargo_redirect(
            "pkg:cargo/x@1.0.0",
            "x",
            "1.0.0",
            root,
            root,
            &files,
            &sources,
            None,
            false,
            false,
        )
        .await;
        assert!(result.success);
        assert!(!root.join(".cargo/config.toml").exists());
    }
}
