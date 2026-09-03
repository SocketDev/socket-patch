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

use super::lock_inventory::{LockIntegrity, LockfileEntry};

/// The default npm registry; override with `SOCKET_NPM_REGISTRY` (the
/// enterprise-mirror / test escape hatch — `.npmrc` parsing is out of
/// scope, but lock-recorded `resolved` URLs already carry custom hosts).
pub const DEFAULT_NPM_REGISTRY: &str = "https://registry.npmjs.org";

/// Whole-package caps — wider than `patch/package.rs`'s patch-archive caps
/// because these are full upstream packages, but still bounded so a
/// poisoned lockfile cannot turn the fetch into a disk/memory bomb.
const MAX_DOWNLOAD_BYTES: u64 = 128 * 1024 * 1024;
const MAX_TOTAL_DECOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ENTRY_BYTES: u64 = 128 * 1024 * 1024;
const MAX_ENTRIES: usize = 60_000;

/// A fetched, verified, extracted package. The tempdir lives exactly as
/// long as this value — callers must hold it until the vendor pipeline has
/// finished staging from [`FetchedPackage::dir`].
#[derive(Debug)]
pub struct FetchedPackage {
    dir: PathBuf,
    /// Where the bytes came from (surfaced in the fetch warning event).
    pub url: String,
    _tmp: tempfile::TempDir,
}

impl FetchedPackage {
    /// The extracted package root (`package.json` at the top for npm).
    pub fn dir(&self) -> &Path {
        &self.dir
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

/// Traversal-guarded zip extraction. `strip_first` mirrors the tar
/// behavior (composer dist zips carry a variable top dir; wheels carry
/// content at the root).
///
/// `pub(crate)` so the composer service-download path can extract a downloaded
/// dist zip into the vendor copy dir (`strip_first` = drop the top-level dir).
pub(crate) fn extract_zip(bytes: &[u8], dest: &Path, strip_first: bool) -> Result<(), String> {
    use std::io::Read as _;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| format!("unreadable zip: {e}"))?;
    if archive.len() > MAX_ENTRIES {
        return Err(format!("zip exceeds {MAX_ENTRIES} entries"));
    }
    let mut total: u64 = 0;
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| format!("unreadable zip entry: {e}"))?;
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
            return Err(format!(
                "zip entry `{}` escapes the extraction dir — refusing the artifact",
                raw.display()
            ));
        }
        let declared = file.size();
        if declared > MAX_ENTRY_BYTES {
            return Err(format!(
                "zip entry `{rel_str}` is {declared} bytes (cap {MAX_ENTRY_BYTES})"
            ));
        }
        total += declared;
        if total > MAX_TOTAL_DECOMPRESSED_BYTES {
            return Err(format!(
                "zip decompresses past the {MAX_TOTAL_DECOMPRESSED_BYTES}-byte cap"
            ));
        }
        let target = dest.join(&rel);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        let mut out = std::fs::File::create(&target)
            .map_err(|e| format!("cannot create {}: {e}", target.display()))?;
        // The declared size is header data a crafted zip can understate (the
        // zip crate does not bound an entry's read by it), so hold the caps
        // against the ACTUAL decompressed bytes too: read at most declared+1
        // and refuse on any mismatch.
        let copied = std::io::copy(&mut (&mut file).take(declared + 1), &mut out)
            .map_err(|e| format!("cannot extract `{rel_str}`: {e}"))?;
        if copied != declared {
            return Err(format!(
                "zip entry `{rel_str}` decompresses to {copied} bytes but declares {declared} \
                 — refusing the artifact"
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let exec = file.unix_mode().is_some_and(|m| m & 0o111 != 0);
            let perms = if exec { 0o755 } else { 0o644 };
            let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(perms));
        }
    }
    Ok(())
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
    extract_zip(&bytes, &dir, strip_first).map_err(FetchError::Failed)?;
    if tokio::fs::metadata(dir.join("composer.json"))
        .await
        .is_err()
    {
        return Err(FetchError::Failed(format!(
            "fetched dist for {}@{} carries no composer.json",
            entry.name, entry.version
        )));
    }
    Ok(FetchedPackage {
        dir,
        url,
        _tmp: tmp,
    })
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
    extract_gem_data(&bytes, &dir).map_err(FetchError::Failed)?;
    Ok(FetchedPackage {
        dir,
        url,
        _tmp: tmp,
    })
}

/// Pure-python wheels recorded by uv.lock (URL + sha256): the unzipped
/// wheel IS a site-packages layout (package dirs + `.dist-info/RECORD` at
/// the root), which is exactly the shape the pypi vendor backend stages
/// from.
async fn fetch_pypi(
    entry: &LockfileEntry,
    client: &reqwest::Client,
) -> Result<FetchedPackage, FetchError> {
    let Some(url) = entry.resolved.clone() else {
        return Err(FetchError::Unverifiable(format!(
            "the lockfile records no platform-independent wheel URL for {}@{} (only uv.lock \
             carries fetchable wheel resolutions today)",
            entry.name, entry.version
        )));
    };
    let bytes = download(client, &url).await.map_err(FetchError::Failed)?;
    verify_integrity(&bytes, &entry.integrity)?;
    let tmp = tempfile::tempdir()
        .map_err(|e| FetchError::Failed(format!("cannot create fetch tempdir: {e}")))?;
    let dir = tmp.path().join("site-packages");
    extract_zip(&bytes, &dir, /*strip_first=*/ false).map_err(FetchError::Failed)?;
    Ok(FetchedPackage {
        dir,
        url,
        _tmp: tmp,
    })
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
    extract_tgz(&bytes, &dir).map_err(FetchError::Failed)?;
    if tokio::fs::metadata(dir.join("Cargo.toml")).await.is_err() {
        return Err(FetchError::Failed(format!(
            "fetched .crate for {}@{} carries no Cargo.toml — not a crate",
            entry.name, entry.version
        )));
    }
    Ok(FetchedPackage {
        dir,
        url,
        _tmp: tmp,
    })
}

/// Default Go module proxy; `SOCKET_GOPROXY` wins, else the standard
/// `GOPROXY` env (first element that isn't `direct`/`off`).
pub const DEFAULT_GOPROXY: &str = "https://proxy.golang.org";

fn goproxy_base() -> String {
    if let Ok(v) = std::env::var("SOCKET_GOPROXY") {
        let v = v.trim_end_matches('/').to_string();
        if !v.is_empty() {
            return v;
        }
    }
    if let Ok(v) = std::env::var("GOPROXY") {
        // GOPROXY is a comma- OR pipe-separated list (go help goproxy).
        for part in v.split([',', '|']) {
            let part = part.trim().trim_end_matches('/');
            if !part.is_empty() && part != "direct" && part != "off" {
                return part.to_string();
            }
        }
    }
    DEFAULT_GOPROXY.to_string()
}

/// go.sum's `h1:` dirhash over a module zip: sha256 of the sorted
/// `"{sha256hex(content)}  {entry name}\n"` lines, base64-encoded
/// (golang.org/x/mod/sumdb/dirhash Hash1/HashZip). Computed in memory
/// BEFORE extraction.
///
/// Runs in the ecosystem-agnostic service-download path whenever the
/// service reports a `dirhashH1`.
fn go_h1_of_zip(bytes: &[u8]) -> Result<String, String> {
    use std::io::Read as _;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| format!("unreadable module zip: {e}"))?;
    if archive.len() > MAX_ENTRIES {
        return Err(format!("module zip exceeds {MAX_ENTRIES} entries"));
    }
    let mut files: Vec<(String, String)> = Vec::new();
    let mut total: u64 = 0;
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
        if file.size() > MAX_ENTRY_BYTES {
            return Err(format!(
                "module zip entry `{name}` is {} bytes (cap {MAX_ENTRY_BYTES})",
                file.size()
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
        files.push((name, hex::encode(hasher.finalize())));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h = Sha256::new();
    for (name, content_hex) in &files {
        h.update(format!("{content_hex}  {name}\n").as_bytes());
    }
    Ok(format!(
        "h1:{}",
        base64::engine::general_purpose::STANDARD.encode(h.finalize())
    ))
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
    use std::io::Read as _;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| format!("unreadable module zip: {e}"))?;
    if archive.len() > MAX_ENTRIES {
        return Err(format!("module zip exceeds {MAX_ENTRIES} entries"));
    }
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
        let target = dest.join(rel);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        let mut out = std::fs::File::create(&target)
            .map_err(|e| format!("cannot create {}: {e}", target.display()))?;
        // Hold the caps against the ACTUAL decompressed bytes too — the
        // declared size is header data a crafted zip can understate.
        let copied = std::io::copy(&mut (&mut file).take(declared + 1), &mut out)
            .map_err(|e| format!("cannot extract `{rel}`: {e}"))?;
        if copied != declared {
            return Err(format!(
                "module zip entry `{name}` decompresses to {copied} bytes but declares \
                 {declared} — refusing the artifact"
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let exec = file.unix_mode().is_some_and(|m| m & 0o111 != 0);
            let perms = if exec { 0o755 } else { 0o644 };
            let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(perms));
        }
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
    let url = entry.resolved.clone().unwrap_or_else(|| {
        format!(
            "{}/{}/@v/{}.zip",
            goproxy_base(),
            encode_module_path(&entry.name),
            encode_module_path(&entry.version)
        )
    });
    let bytes = download(client, &url).await.map_err(FetchError::Failed)?;
    let actual = go_h1_of_zip(&bytes).map_err(FetchError::Failed)?;
    if &actual != expected {
        return Err(FetchError::Failed(format!(
            "go.sum dirhash mismatch: lockfile records {expected}, the fetched module zip \
             hashes to {actual}"
        )));
    }
    let tmp = tempfile::tempdir()
        .map_err(|e| FetchError::Failed(format!("cannot create fetch tempdir: {e}")))?;
    let dir = tmp.path().join("module");
    let prefix = format!("{}@{}/", entry.name, entry.version);
    extract_zip_with_prefix(&bytes, &dir, &prefix).map_err(FetchError::Failed)?;
    Ok(FetchedPackage {
        dir,
        url,
        _tmp: tmp,
    })
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
    extract_tgz(&bytes, &dir).map_err(FetchError::Failed)?;
    if tokio::fs::metadata(dir.join("package.json")).await.is_err() {
        return Err(FetchError::Failed(format!(
            "fetched tarball for {}@{} carries no package.json — not an npm package",
            entry.name, entry.version
        )));
    }
    Ok(FetchedPackage {
        dir,
        url,
        _tmp: tmp,
    })
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
    extract_tgz(&bytes, &dir).map_err(FetchError::Failed)?;
    Ok(FetchedPackage {
        dir,
        url: format!("file:{}", tgz_path.display()),
        _tmp: tmp,
    })
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
    extract_tar_gz(bytes, dest, /*strip_first=*/ true)
}

/// Like [`extract_tgz`] but keeps entry paths verbatim (gem `data.tar.gz`
/// archives carry package content at the root, no prefix dir).
fn extract_tgz_no_strip(bytes: &[u8], dest: &Path) -> Result<(), String> {
    extract_tar_gz(bytes, dest, /*strip_first=*/ false)
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
        return extract_tgz_no_strip(&buf, dest);
    }
    Err("the .gem carries no data.tar.gz".to_string())
}

fn extract_tar_gz(bytes: &[u8], dest: &Path, strip_first: bool) -> Result<(), String> {
    use std::io::Read as _;
    let gz = flate2::read::GzDecoder::new(bytes).take(MAX_TOTAL_DECOMPRESSED_BYTES);
    let mut archive = tar::Archive::new(gz);
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
        let target = dest.join(&rel);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        let mut out = std::fs::File::create(&target)
            .map_err(|e| format!("cannot create {}: {e}", target.display()))?;
        std::io::copy(&mut entry, &mut out)
            .map_err(|e| format!("cannot extract `{rel_str}`: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = entry.header().mode().unwrap_or(0o644);
            let perms = if mode & 0o111 != 0 { 0o755 } else { 0o644 };
            let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(perms));
        }
    }
    Ok(())
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
        assert!(fetched.dir().join("package.json").is_file());
        assert_eq!(
            std::fs::read(fetched.dir().join("index.js")).unwrap(),
            b"module.exports = 1;\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(fetched.dir().join("bin/cli.js"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o111, 0o111, "exec bit preserved");
        }
        // The tempdir dies with the holder.
        let dir = fetched.dir().to_path_buf();
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
        assert!(fetched.dir().join("package.json").is_file());

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
        assert!(staged.dir().join("package.json").is_file());

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
            name: "left-pad".into(),
            version: "1.3.0".into(),
            purl: "pkg:cargo/left-pad@1.3.0".into(),
            resolved: Some(format!("{}/left-pad/left-pad-1.3.0.crate", mock.uri())),
            integrity: LockIntegrity::Sha256Hex(sha),
        };
        let fetched = fetch_and_stage(&entry, &build_registry_client())
            .await
            .unwrap();
        assert!(fetched.dir().join("Cargo.toml").is_file());
        assert!(fetched.dir().join("src/lib.rs").is_file());

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
            name: "github.com/x/y".into(),
            version: "v1.0.0".into(),
            purl: "pkg:golang/github.com/x/y@v1.0.0".into(),
            resolved: Some(format!("{}/github.com/x/y/@v/v1.0.0.zip", mock.uri())),
            integrity: LockIntegrity::GoH1(expected),
        };
        let fetched = fetch_and_stage(&entry, &build_registry_client())
            .await
            .unwrap();
        assert!(fetched.dir().join("go.mod").is_file());
        assert!(fetched.dir().join("a/b.go").is_file());

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
            name: "monolog/monolog".into(),
            version: "3.5.0".into(),
            purl: "pkg:composer/monolog/monolog@3.5.0".into(),
            resolved: Some(format!("{}/zipball/abc123", mock.uri())),
            integrity: LockIntegrity::Sha1Hex(sha1),
        };
        let fetched = fetch_and_stage(&entry, &build_registry_client())
            .await
            .unwrap();
        assert!(fetched.dir().join("composer.json").is_file());
        assert!(fetched.dir().join("src/Logger.php").is_file());

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
            name: "acme/flat".into(),
            version: "1.0.0".into(),
            purl: "pkg:composer/acme/flat@1.0.0".into(),
            resolved: Some(format!("{}/dists/acme-flat-1.0.0.zip", mock.uri())),
            integrity: LockIntegrity::Sha1Hex(sha1),
        };
        let fetched = fetch_and_stage(&entry, &build_registry_client())
            .await
            .expect("a flat-layout dist is a genuine, integrity-verified artifact");
        assert!(fetched.dir().join("composer.json").is_file());
        assert!(
            fetched.dir().join("src/Flat.php").is_file(),
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
            fetched.dir().join("lib/rails.rb").is_file(),
            "data.tar.gz content extracts at the root (no strip)"
        );
        assert!(fetched.dir().join("README.md").is_file());
        // The staged leaf must be the canonical `{name}-{version}`:
        // vendor_gem's platform-suffix guard refuses any other leaf
        // (`platform_gem_unsupported`), which killed lockfile auto-fetch
        // when this dir was named `gem`.
        assert_eq!(
            fetched.dir().file_name().unwrap().to_string_lossy(),
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
        assert!(fetched.dir().join("requests/__init__.py").is_file());
        assert!(fetched
            .dir()
            .join("requests-2.28.0.dist-info/RECORD")
            .is_file());

        // No recorded wheel URL (poetry/requirements) → Unverifiable.
        let entry = LockfileEntry {
            resolved: None,
            integrity: LockIntegrity::Sha256Hex("0".repeat(64)),
            ..entry
        };
        match fetch_and_stage(&entry, &build_registry_client()).await {
            Err(FetchError::Unverifiable(msg)) => assert!(msg.contains("wheel"), "{msg}"),
            other => panic!("expected Unverifiable, got {other:?}"),
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
        let piped = goproxy_base();
        std::env::set_var("GOPROXY", "off|https://mirror.example/,direct");
        let mixed = goproxy_base();
        match saved {
            Some(v) => std::env::set_var("GOPROXY", v),
            None => std::env::remove_var("GOPROXY"),
        }
        match saved_socket {
            Some(v) => std::env::set_var("SOCKET_GOPROXY", v),
            None => std::env::remove_var("SOCKET_GOPROXY"),
        }
        assert_eq!(piped, "https://athens.example");
        assert_eq!(mixed, "https://mirror.example");
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
        let entry = LockfileEntry {
            ecosystem: "pypi",
            name: "requests".into(),
            version: "2.28.0".into(),
            purl: "pkg:pypi/requests@2.28.0".into(),
            resolved: None,
            integrity: LockIntegrity::Sha256Hex("0".repeat(64)),
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
        assert!(fetched.dir().join("Cargo.toml").is_file());
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
        assert!(fetched.dir().join("go.mod").is_file());
    }

    #[test]
    #[serial_test::serial]
    fn goproxy_base_env_precedence() {
        let saved_socket = std::env::var("SOCKET_GOPROXY").ok();
        let saved = std::env::var("GOPROXY").ok();

        // SOCKET_GOPROXY wins over GOPROXY (trailing slash trimmed).
        std::env::set_var("SOCKET_GOPROXY", "https://socket.example/");
        std::env::set_var("GOPROXY", "https://ignored.example");
        let socket_wins = goproxy_base();
        // An EMPTY SOCKET_GOPROXY falls through to GOPROXY.
        std::env::set_var("SOCKET_GOPROXY", "");
        std::env::set_var("GOPROXY", "https://fallback.example");
        let empty_falls_through = goproxy_base();
        // Neither set → the default proxy.
        std::env::remove_var("SOCKET_GOPROXY");
        std::env::remove_var("GOPROXY");
        let neither = goproxy_base();
        // A GOPROXY of only direct/off parts is unusable → the default.
        std::env::set_var("GOPROXY", "direct,off");
        let all_unusable = goproxy_base();

        match saved_socket {
            Some(v) => std::env::set_var("SOCKET_GOPROXY", v),
            None => std::env::remove_var("SOCKET_GOPROXY"),
        }
        match saved {
            Some(v) => std::env::set_var("GOPROXY", v),
            None => std::env::remove_var("GOPROXY"),
        }
        assert_eq!(socket_wins, "https://socket.example");
        assert_eq!(empty_falls_through, "https://fallback.example");
        assert_eq!(neither, DEFAULT_GOPROXY);
        assert_eq!(all_unusable, DEFAULT_GOPROXY);
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
        assert!(!tmp.path().join("m@v1/d").exists(), "dir entry must not materialize");

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

    #[test]
    fn verify_go_h1_accepts_matching_dirhash() {
        // The SUCCESS path is the golang service-download content verifier —
        // a round-trip against the module's own hasher must pass, and a
        // foreign h1 must name the mismatch.
        let zip_bytes = make_module_zip("m@v1/", &[("go.mod", b"module m\n")]);
        let h1 = go_h1_of_zip(&zip_bytes).unwrap();
        verify_go_h1(&zip_bytes, &h1).expect("a matching dirhash must verify");
        let err = verify_go_h1(&zip_bytes, "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
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
        let err =
            artifact_matches_integrity(b"x", "pkg", &LockIntegrity::GoH1("h1:x".into()))
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
