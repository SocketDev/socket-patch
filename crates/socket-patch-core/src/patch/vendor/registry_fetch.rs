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
        other => Err(FetchError::Unverifiable(format!(
            "no registry fetcher for ecosystem `{other}`"
        ))),
    }
}

async fn fetch_npm(
    entry: &LockfileEntry,
    client: &reqwest::Client,
) -> Result<FetchedPackage, FetchError> {
    let url = entry.resolved.clone().unwrap_or_else(|| {
        npm_tarball_url(&npm_registry_base(), &entry.name, &entry.version)
    });
    let bytes = download(client, &url).await.map_err(FetchError::Failed)?;
    verify_integrity(&bytes, &entry.integrity)?;

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
        LockIntegrity::BerryChecksum(_) | LockIntegrity::GoH1(_) => {
            Err(FetchError::Unverifiable(
                "verifier handled by a dedicated ecosystem fetcher".to_string(),
            ))
        }
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
        let Some(rel) = strip_first_component(&raw) else {
            continue; // a bare prefix-level file — not package content
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
        assert!(verify_sri(bytes, "md5-abc=").is_err(), "unknown algos refuse");
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
