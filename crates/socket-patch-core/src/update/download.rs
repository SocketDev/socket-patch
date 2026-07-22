//! Download, verify, extract, stage, and sanity-check a release binary.
//!
//! Order is load-bearing and pinned by tests:
//!
//! 1. fetch `SHA256SUMS` and find our asset's entry (refuse before wasting
//!    a download on an asset the release cannot vouch for);
//! 2. fetch the archive (capped, explicit timeout);
//! 3. verify the SHA-256 of the raw archive bytes **before** extraction;
//! 4. extract exactly one member (`socket-patch`/`socket-patch.exe`);
//! 5. stage the binary INTO the destination directory (same-filesystem
//!    rename; system temp is frequently `noexec`, which would break the
//!    sanity exec; an `EACCES` here doubles as the permissions preflight);
//! 6. sanity-exec the staged file (`--version`) before any swap.
//!
//! Nothing in this module touches the destination path itself — the swap
//! lives in `swap.rs` and consumes the staged file this module returns.

use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::release::{UpdateEndpoints, UpdateTimeouts};
use super::UpdateError;
use crate::utils::http::read_capped;

/// Hard cap on the compressed archive (the real ones are ~5–10 MiB) —
/// matches the vendor artifact-download cap.
const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;

/// Hard cap on the single extracted binary, enforced during streaming
/// decompression so a decompression bomb can't balloon memory.
const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;

/// Prefix for staged-binary files in the destination directory. The
/// start-of-run sweep removes stale ones (crash leftovers).
pub(crate) const STAGE_PREFIX: &str = ".socket-patch.stage-";

/// A downloaded, verified, extracted, staged binary — everything but the
/// swap. Deleting the stage file on failure is the caller's job (the
/// [`StagedBinary::cleanup`] helper is best-effort).
#[derive(Debug)]
pub struct StagedBinary {
    pub path: PathBuf,
    pub asset: String,
    pub archive_bytes: u64,
    pub archive_sha256: String,
}

impl StagedBinary {
    pub fn cleanup(&self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Download client: credential-free (User-Agent only — the Socket bearer
/// must never reach GitHub/CDN hosts), explicit timeouts, and on the
/// default endpoints an HTTPS-only redirect policy — GitHub bounces asset
/// downloads to a CDN, and one `http://` hop would let a MITM serve both a
/// malicious archive and its matching SHA256SUMS. Overridden bases
/// (wiremock, mirrors) are plain-`http` on loopback by design, so the
/// policy only applies when `endpoints.is_default()`.
fn download_client(
    endpoints: &UpdateEndpoints,
    timeouts: &UpdateTimeouts,
) -> Result<reqwest::Client, UpdateError> {
    let redirect_policy = if endpoints.is_default() {
        reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() > 10 {
                attempt.error("too many redirects")
            } else if attempt.url().scheme() != "https" {
                attempt.error("refusing insecure (non-HTTPS) redirect for a release download")
            } else {
                attempt.follow()
            }
        })
    } else {
        reqwest::redirect::Policy::limited(10)
    };
    reqwest::Client::builder()
        .user_agent(crate::constants::USER_AGENT)
        .connect_timeout(timeouts.connect)
        .timeout(timeouts.download)
        .redirect(redirect_policy)
        .build()
        .map_err(|e| UpdateError::Network(format!("failed to build HTTP client: {e}")))
}

/// Fetch the release archive for `asset`, returning its raw bytes.
async fn fetch_archive(
    endpoints: &UpdateEndpoints,
    timeouts: &UpdateTimeouts,
    version: &semver::Version,
    asset: &str,
) -> Result<Vec<u8>, UpdateError> {
    let client = download_client(endpoints, timeouts)?;
    let url = endpoints.download_url(version, asset);
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| UpdateError::Network(format!("GET {url}: {e}")))?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(UpdateError::AssetNotFound {
            asset: asset.to_string(),
            version: version.to_string(),
        });
    }
    if !status.is_success() {
        return Err(UpdateError::DownloadFailed(format!(
            "GET {url} returned {status}"
        )));
    }
    read_capped(resp, MAX_ARCHIVE_BYTES, "release archive")
        .await
        .map_err(UpdateError::DownloadFailed)
}

/// Extract the single expected member from a `.tar.gz` (`socket-patch`) or
/// `.zip` (`socket-patch.exe`) archive. Exactly one candidate must exist;
/// paths are matched exactly, which rejects traversal names by
/// construction. Decompressed size is capped.
fn extract_binary(asset: &str, archive: &[u8]) -> Result<Vec<u8>, UpdateError> {
    if asset.ends_with(".zip") {
        extract_zip_member(archive, "socket-patch.exe")
    } else {
        extract_targz_member(archive, "socket-patch")
    }
}

fn extract_targz_member(archive: &[u8], member: &str) -> Result<Vec<u8>, UpdateError> {
    let gz = flate2::read::GzDecoder::new(archive);
    let mut tar = tar::Archive::new(gz);
    let mut found: Option<Vec<u8>> = None;
    let entries = tar
        .entries()
        .map_err(|e| UpdateError::VerifyFailed(format!("unreadable tar.gz archive: {e}")))?;
    for entry in entries {
        let entry =
            entry.map_err(|e| UpdateError::VerifyFailed(format!("corrupt tar entry: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| UpdateError::VerifyFailed(format!("undecodable tar path: {e}")))?;
        if path != Path::new(member) {
            continue;
        }
        if found.is_some() {
            return Err(UpdateError::VerifyFailed(format!(
                "archive contains multiple {member} entries"
            )));
        }
        let mut bytes = Vec::new();
        entry
            .take(MAX_BINARY_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| UpdateError::VerifyFailed(format!("error reading {member}: {e}")))?;
        if bytes.len() as u64 > MAX_BINARY_BYTES {
            return Err(UpdateError::VerifyFailed(format!(
                "{member} exceeds the {MAX_BINARY_BYTES}-byte cap"
            )));
        }
        found = Some(bytes);
    }
    found.ok_or_else(|| {
        UpdateError::VerifyFailed(format!("archive does not contain a {member} entry"))
    })
}

fn extract_zip_member(archive: &[u8], member: &str) -> Result<Vec<u8>, UpdateError> {
    let cursor = std::io::Cursor::new(archive);
    let mut zip = zip::ZipArchive::new(cursor)
        .map_err(|e| UpdateError::VerifyFailed(format!("unreadable zip archive: {e}")))?;
    let file = zip
        .by_name(member)
        .map_err(|_| UpdateError::VerifyFailed(format!("archive does not contain a {member} entry")))?;
    if file.size() > MAX_BINARY_BYTES {
        return Err(UpdateError::VerifyFailed(format!(
            "{member} exceeds the {MAX_BINARY_BYTES}-byte cap"
        )));
    }
    let mut bytes = Vec::new();
    file.take(MAX_BINARY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| UpdateError::VerifyFailed(format!("error reading {member}: {e}")))?;
    if bytes.len() as u64 > MAX_BINARY_BYTES {
        return Err(UpdateError::VerifyFailed(format!(
            "{member} exceeds the {MAX_BINARY_BYTES}-byte cap"
        )));
    }
    Ok(bytes)
}

/// Write the extracted binary into `dest_dir` as an executable stage file.
/// `EACCES` here is the permissions preflight: it means the eventual
/// rename would fail too, so it maps to the sudo-hint error before any
/// mutation.
fn stage_binary(dest_dir: &Path, bytes: &[u8]) -> Result<PathBuf, UpdateError> {
    let stage = dest_dir.join(format!("{STAGE_PREFIX}{}", uuid::Uuid::new_v4()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o755);
    }
    let mut file = opts.open(&stage).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            UpdateError::PermissionDenied {
                path: dest_dir.to_path_buf(),
            }
        } else {
            UpdateError::SwapFailed(format!("cannot stage into {}: {e}", dest_dir.display()))
        }
    })?;
    use std::io::Write;
    let write_result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&stage);
        return Err(UpdateError::SwapFailed(format!(
            "error writing staged binary: {e}"
        )));
    }
    Ok(stage)
}

/// Best-effort sweep of stale stage files (crash leftovers) in `dest_dir`.
pub(crate) fn sweep_stale_stages(dest_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dest_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(STAGE_PREFIX) || name.starts_with(".socket-patch.old-") {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Run `<staged> --version` and check the answer. Catches wrong-arch
/// assets, exec-format problems, and (in strict mode) a release whose
/// binary does not report the tag it was published under.
///
/// Strictness follows the endpoint trust model: against real GitHub the
/// reported version must equal `expected`; under a `SOCKET_UPDATE_BASE_URL`
/// override (mirror or test fixture — already a total-trust knob) a
/// mismatch only warns via the returned `Option<String>`.
async fn sanity_exec(
    staged: &Path,
    expected: &semver::Version,
    strict: bool,
) -> Result<Option<String>, UpdateError> {
    let mut cmd = tokio::process::Command::new(staged);
    cmd.arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(std::time::Duration::from_secs(10), cmd.output())
        .await
        .map_err(|_| {
            UpdateError::VerifyFailed(
                "downloaded binary hung during its --version self-check".to_string(),
            )
        })?
        .map_err(|e| {
            UpdateError::VerifyFailed(format!(
                "downloaded binary failed to execute (wrong architecture?): {e}"
            ))
        })?;
    if !output.status.success() {
        return Err(UpdateError::VerifyFailed(format!(
            "downloaded binary's --version self-check exited with {}",
            output.status
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let reported = stdout.trim();
    // clap prints "socket-patch <version>".
    if !reported.starts_with("socket-patch") {
        return Err(UpdateError::VerifyFailed(format!(
            "downloaded binary identifies as {reported:?}, not socket-patch"
        )));
    }
    let version_ok = reported
        .split_whitespace()
        .nth(1)
        .map(|v| v == expected.to_string())
        .unwrap_or(false);
    if version_ok {
        return Ok(None);
    }
    let detail = format!(
        "downloaded binary reports {reported:?} instead of version {expected}"
    );
    if strict {
        Err(UpdateError::VerifyFailed(detail))
    } else {
        Ok(Some(detail))
    }
}

/// The full pre-swap pipeline (module docs). On success the returned
/// [`StagedBinary`] sits executable in `dest_dir`, verified end to end.
/// `warnings` collects non-fatal notes (relaxed version check).
pub async fn download_and_stage(
    endpoints: &UpdateEndpoints,
    timeouts: &UpdateTimeouts,
    version: &semver::Version,
    asset: &str,
    dest_dir: &Path,
    warnings: &mut Vec<String>,
) -> Result<StagedBinary, UpdateError> {
    // 1. SHA256SUMS first: refuse before downloading an unvouched asset.
    let expected_sha =
        super::release::fetch_sha256sums_entry(endpoints, timeouts, version, asset).await?;

    // 2. Archive.
    let archive = fetch_archive(endpoints, timeouts, version, asset).await?;

    // 3. Checksum BEFORE extraction.
    let actual_sha = hex::encode(Sha256::digest(&archive));
    if actual_sha != expected_sha {
        return Err(UpdateError::ChecksumMismatch {
            asset: asset.to_string(),
            detail: format!("expected {expected_sha}, downloaded {actual_sha}"),
        });
    }

    // 4. Extract the one expected member.
    let binary = extract_binary(asset, &archive)?;

    // 5. Stage into the destination directory.
    let staged_path = stage_binary(dest_dir, &binary)?;
    let staged = StagedBinary {
        path: staged_path,
        asset: asset.to_string(),
        archive_bytes: archive.len() as u64,
        archive_sha256: actual_sha,
    };

    // 6. Sanity-exec before anything irreversible.
    match sanity_exec(&staged.path, version, endpoints.is_default()).await {
        Ok(None) => {}
        Ok(Some(warning)) => warnings.push(format!("{warning} (allowed: custom update base URL)")),
        Err(e) => {
            staged.cleanup();
            return Err(e);
        }
    }
    Ok(staged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;

    fn tgz_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        for (name, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append_data(&mut header, name, *bytes).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn zip_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut buf);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            for (name, bytes) in entries {
                use std::io::Write;
                writer.start_file(*name, opts).unwrap();
                writer.write_all(bytes).unwrap();
            }
            writer.finish().unwrap();
        }
        buf.into_inner()
    }

    #[test]
    fn targz_single_member_extracts() {
        let archive = tgz_with(&[("socket-patch", b"BINARY")]);
        assert_eq!(
            extract_binary("socket-patch-x.tar.gz", &archive).unwrap(),
            b"BINARY"
        );
    }

    #[test]
    fn targz_missing_member_is_error() {
        let archive = tgz_with(&[("README.md", b"nope")]);
        let err = extract_binary("socket-patch-x.tar.gz", &archive).unwrap_err();
        assert!(err.to_string().contains("does not contain"), "{err}");
    }

    /// Like [`tgz_with`], but writes entry names into the raw GNU header
    /// bytes, bypassing tar-rs's builder-side `..` sanitization — a hostile
    /// archive wouldn't have used a polite builder either.
    fn tgz_with_raw_names(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        for (name, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            let gnu = header.as_gnu_mut().unwrap();
            gnu.name[..name.len()].copy_from_slice(name.as_bytes());
            header.set_size(bytes.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append(&header, *bytes).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn targz_traversal_names_are_not_the_member() {
        // Exact-path matching rejects traversal spellings by construction:
        // none of these IS "socket-patch", so nothing extracts.
        let archive = tgz_with_raw_names(&[
            ("../socket-patch", b"evil"),
            ("./x/../../socket-patch", b"evil"),
            ("bin/socket-patch", b"nested"),
        ]);
        assert!(extract_binary("socket-patch-x.tar.gz", &archive).is_err());
    }

    #[test]
    fn targz_duplicate_members_refused() {
        let archive = tgz_with(&[("socket-patch", b"one"), ("socket-patch", b"two")]);
        let err = extract_binary("socket-patch-x.tar.gz", &archive).unwrap_err();
        assert!(err.to_string().contains("multiple"), "{err}");
    }

    #[test]
    fn targz_garbage_bytes_are_an_error_not_a_panic() {
        assert!(extract_binary("socket-patch-x.tar.gz", b"not a tarball").is_err());
    }

    #[test]
    fn zip_member_extracts_and_missing_errors() {
        let archive = zip_with(&[("socket-patch.exe", b"PEBYTES")]);
        assert_eq!(
            extract_binary("socket-patch-x.zip", &archive).unwrap(),
            b"PEBYTES"
        );
        let archive = zip_with(&[("other.exe", b"nope")]);
        assert!(extract_binary("socket-patch-x.zip", &archive).is_err());
    }

    #[test]
    fn stage_lands_executable_in_dest_dir_and_sweep_removes_stale() {
        let tmp = tempfile::tempdir().unwrap();
        let staged = stage_binary(tmp.path(), b"#!/bin/sh\nexit 0\n").unwrap();
        assert!(staged.starts_with(tmp.path()));
        assert!(staged
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(STAGE_PREFIX));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&staged).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755, "staged binary must be executable");
        }
        sweep_stale_stages(tmp.path());
        assert!(!staged.exists(), "sweep must remove stale stage files");
    }

    #[cfg(unix)]
    #[test]
    fn stage_into_readonly_dir_maps_to_permission_denied() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("ro");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        // Root ignores mode bits; skip there (CI containers sometimes run as root).
        if std::fs::File::create(dir.join("probe")).is_ok() {
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
            eprintln!("skipping: running as root, 0555 does not block writes");
            return;
        }
        let err = stage_binary(&dir, b"x").unwrap_err();
        assert!(
            matches!(err, UpdateError::PermissionDenied { .. }),
            "expected PermissionDenied, got: {err}"
        );
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sanity_exec_rejects_wrong_program_and_honors_strictness() {
        let tmp = tempfile::tempdir().unwrap();
        let expected = semver::Version::new(9, 9, 9);

        let write_script = |name: &str, body: &str| {
            use std::os::unix::fs::PermissionsExt;
            let path = tmp.path().join(name);
            std::fs::write(&path, body).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path
        };

        // Wrong program name: hard error in both modes.
        let imposter = write_script("imposter", "#!/bin/sh\necho other-tool 9.9.9\n");
        assert!(sanity_exec(&imposter, &expected, false).await.is_err());

        // Non-zero exit: hard error.
        let failing = write_script("failing", "#!/bin/sh\necho socket-patch 9.9.9\nexit 3\n");
        assert!(sanity_exec(&failing, &expected, true).await.is_err());

        // Version mismatch: fatal in strict mode, warning otherwise.
        let mismatched = write_script("mismatch", "#!/bin/sh\necho socket-patch 1.0.0\n");
        assert!(sanity_exec(&mismatched, &expected, true).await.is_err());
        let warning = sanity_exec(&mismatched, &expected, false).await.unwrap();
        assert!(warning.unwrap().contains("1.0.0"));

        // Exact match: clean pass in strict mode.
        let good = write_script("good", "#!/bin/sh\necho socket-patch 9.9.9\n");
        assert_eq!(sanity_exec(&good, &expected, true).await.unwrap(), None);

        // Exec-format failure (not executable at all): hard error.
        let garbage = tmp.path().join("garbage");
        std::fs::write(&garbage, b"\x00\x01\x02").unwrap();
        assert!(sanity_exec(&garbage, &expected, false).await.is_err());
    }
}
