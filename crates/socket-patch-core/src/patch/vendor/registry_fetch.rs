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
use crate::patch::apply::is_safe_relative_subpath;

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
pub fn build_registry_client() -> reqwest::Client {
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
        #[cfg(feature = "cargo")]
        "cargo" => fetch_cargo(entry, client).await,
        #[cfg(feature = "golang")]
        "golang" => fetch_golang(entry, client).await,
        #[cfg(feature = "composer")]
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
fn extract_zip(bytes: &[u8], dest: &Path, strip_first: bool) -> Result<(), String> {
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
        if file.size() > MAX_ENTRY_BYTES {
            return Err(format!(
                "zip entry `{rel_str}` is {} bytes (cap {MAX_ENTRY_BYTES})",
                file.size()
            ));
        }
        total += file.size();
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
        std::io::copy(&mut file, &mut out)
            .map_err(|e| format!("cannot extract `{rel_str}`: {e}"))?;
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

/// Composer dist zips (packagist/GitHub zipballs): sha1-verified, variable
/// top dir stripped. The extracted dir plays the installed package dir.
#[cfg(feature = "composer")]
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
    extract_zip(&bytes, &dir, /*strip_first=*/ true).map_err(FetchError::Failed)?;
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
    let Some(url) = entry.resolved.clone() else {
        return Err(FetchError::Unverifiable(format!(
            "no download URL for {}@{}",
            entry.name, entry.version
        )));
    };
    let bytes = download(client, &url).await.map_err(FetchError::Failed)?;
    verify_integrity(&bytes, &entry.integrity)?;

    // Locate data.tar.gz inside the (uncompressed) outer tar.
    let mut archive = tar::Archive::new(bytes.as_slice());
    let mut data: Option<Vec<u8>> = None;
    for e in archive
        .entries()
        .map_err(|e| FetchError::Failed(format!("unreadable .gem: {e}")))?
    {
        use std::io::Read as _;
        let mut e = e.map_err(|err| FetchError::Failed(format!("unreadable .gem entry: {err}")))?;
        let is_data = e
            .path()
            .ok()
            .is_some_and(|p| p.as_os_str() == "data.tar.gz");
        if !is_data {
            continue;
        }
        if e.header().size().unwrap_or(u64::MAX) > MAX_DOWNLOAD_BYTES {
            return Err(FetchError::Failed(
                "data.tar.gz exceeds the size cap".into(),
            ));
        }
        let mut buf = Vec::new();
        e.read_to_end(&mut buf)
            .map_err(|err| FetchError::Failed(format!("cannot read data.tar.gz: {err}")))?;
        data = Some(buf);
        break;
    }
    let Some(data) = data else {
        return Err(FetchError::Failed(format!(
            "fetched .gem for {}@{} carries no data.tar.gz",
            entry.name, entry.version
        )));
    };
    let tmp = tempfile::tempdir()
        .map_err(|e| FetchError::Failed(format!("cannot create fetch tempdir: {e}")))?;
    let dir = tmp.path().join("gem");
    extract_tgz_no_strip(&data, &dir).map_err(FetchError::Failed)?;
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
            "the lockfile records no platform-independent wheel URL for {}@{} (only uv.lock              carries fetchable wheel resolutions today)",
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
#[cfg(feature = "cargo")]
pub const DEFAULT_CRATES_REGISTRY: &str = "https://static.crates.io/crates";

#[cfg(feature = "cargo")]
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
#[cfg(feature = "cargo")]
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
#[cfg(feature = "golang")]
pub const DEFAULT_GOPROXY: &str = "https://proxy.golang.org";

#[cfg(feature = "golang")]
fn goproxy_base() -> String {
    if let Ok(v) = std::env::var("SOCKET_GOPROXY") {
        let v = v.trim_end_matches('/').to_string();
        if !v.is_empty() {
            return v;
        }
    }
    if let Ok(v) = std::env::var("GOPROXY") {
        for part in v.split(',') {
            let part = part.trim().trim_end_matches('/');
            if !part.is_empty() && part != "direct" && part != "off" {
                return part.to_string();
            }
        }
    }
    DEFAULT_GOPROXY.to_string()
}

/// Go's module-path case encoding for proxy URLs: an uppercase letter `X`
/// becomes `!x` (applies to the module path and the version).
#[cfg(feature = "golang")]
fn go_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// go.sum's `h1:` dirhash over a module zip: sha256 of the sorted
/// `"{sha256hex(content)}  {entry name}\n"` lines, base64-encoded
/// (golang.org/x/mod/sumdb/dirhash Hash1/HashZip). Computed in memory
/// BEFORE extraction.
#[cfg(feature = "golang")]
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
        total += file.size();
        if total > MAX_TOTAL_DECOMPRESSED_BYTES {
            return Err(format!(
                "module zip decompresses past the {MAX_TOTAL_DECOMPRESSED_BYTES}-byte cap"
            ));
        }
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| format!("cannot read module zip entry `{name}`: {e}"))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
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

/// Traversal-guarded zip extraction with an EXPLICIT required prefix
/// (`<module>@<version>/` — go module paths contain slashes, so a
/// first-component strip would be wrong). Same guard family as
/// [`extract_tgz`]; an entry outside the prefix fails the whole artifact.
#[cfg(feature = "golang")]
fn extract_zip_with_prefix(bytes: &[u8], dest: &Path, prefix: &str) -> Result<(), String> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| format!("unreadable module zip: {e}"))?;
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
        let target = dest.join(rel);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        let mut out = std::fs::File::create(&target)
            .map_err(|e| format!("cannot create {}: {e}", target.display()))?;
        std::io::copy(&mut file, &mut out).map_err(|e| format!("cannot extract `{rel}`: {e}"))?;
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

#[cfg(feature = "golang")]
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
            go_escape(&entry.name),
            go_escape(&entry.version)
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
    let url = entry
        .resolved
        .clone()
        .unwrap_or_else(|| npm_tarball_url(&npm_registry_base(), &entry.name, &entry.version));
    let bytes = download(client, &url).await.map_err(FetchError::Failed)?;
    match &entry.integrity {
        // yarn berry locks never hash the tarball itself — the checksum is
        // sha512 of the deterministic cache zip. Rebuild it from the fetched
        // bytes (the same spike-pinned recipe the berry wiring uses) and
        // compare. Only cacheKey 10c0 (yarn 4 default) is reproducible.
        LockIntegrity::BerryChecksum(expected) => {
            if !expected.starts_with("10c0/") {
                return Err(FetchError::Unverifiable(format!(
                    "yarn berry checksum `{expected}` uses a cacheKey other than 10c0; the \
                     cache-zip recipe is not reproducible for it"
                )));
            }
            let actual = super::berry_zip::berry_cache_checksum_10c0(&bytes, &entry.name)
                .map_err(FetchError::Failed)?;
            if &actual != expected {
                return Err(FetchError::Failed(format!(
                    "yarn berry cache checksum mismatch: lockfile records {expected}, the \
                     fetched tarball rebuilds to {actual}"
                )));
            }
        }
        other => verify_integrity(&bytes, other)?,
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
    let bytes = tokio::fs::read(tgz_path)
        .await
        .map_err(|e| FetchError::Failed(format!("cannot read {}: {e}", tgz_path.display())))?;
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
fn extract_tgz(bytes: &[u8], dest: &Path) -> Result<(), String> {
    extract_tar_gz(bytes, dest, /*strip_first=*/ true)
}

/// Like [`extract_tgz`] but keeps entry paths verbatim (gem `data.tar.gz`
/// archives carry package content at the root, no prefix dir).
#[allow(dead_code)] // used by the gem fetcher (feature-independent helper)
fn extract_tgz_no_strip(bytes: &[u8], dest: &Path) -> Result<(), String> {
    extract_tar_gz(bytes, dest, /*strip_first=*/ false)
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

    #[cfg(feature = "cargo")]
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
    #[cfg(feature = "golang")]
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
    #[cfg(feature = "golang")]
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

    #[cfg(feature = "golang")]
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

    #[cfg(feature = "golang")]
    #[test]
    fn go_escape_uppercase_and_zip_prefix_guards() {
        assert_eq!(
            go_escape("github.com/Azure/azure-sdk"),
            "github.com/!azure/azure-sdk"
        );
        assert_eq!(go_escape("v1.0.0-RC1"), "v1.0.0-!r!c1");

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

    #[cfg(feature = "composer")]
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
}
