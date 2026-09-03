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
/// must never reach GitHub/CDN hosts), explicit timeouts, and the shared
/// redirect policy (`release::follow_redirect_policy`): HTTPS-only hops on
/// the default endpoints, hop-count-limited on overridden (loopback/
/// mirror) bases.
fn download_client(
    endpoints: &UpdateEndpoints,
    timeouts: &UpdateTimeouts,
) -> Result<reqwest::Client, UpdateError> {
    reqwest::Client::builder()
        .user_agent(crate::constants::USER_AGENT)
        .connect_timeout(timeouts.connect)
        .timeout(timeouts.download)
        .redirect(super::release::follow_redirect_policy(endpoints))
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
    let file = zip.by_name(member).map_err(|_| {
        UpdateError::VerifyFailed(format!("archive does not contain a {member} entry"))
    })?;
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
    let write_result = file.write_all(bytes).and_then(|()| file.sync_all());
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
///
/// Age-gated: the update lock lives in the per-user state dir, so two
/// updaters with divergent state-dir resolution (different `$HOME`s
/// targeting one shared `/usr/local/bin`) can run concurrently — an
/// unconditional sweep would delete the other run's *live* stage mid-
/// pipeline and turn a benign race into a spurious failure. A genuine
/// crash leftover is minutes-to-days old; a live stage is seconds old.
pub(crate) fn sweep_stale_stages(dest_dir: &Path) {
    const MIN_STALE_AGE: std::time::Duration = std::time::Duration::from_secs(60 * 60);
    let Ok(entries) = std::fs::read_dir(dest_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(STAGE_PREFIX) && !name.starts_with(".socket-patch.old-") {
            continue;
        }
        let old_enough = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|mtime| mtime.elapsed().ok())
            .map(|age| age >= MIN_STALE_AGE)
            // Unreadable metadata/clock: assume stale — the pre-gate
            // behavior — rather than accumulating junk forever.
            .unwrap_or(true);
        if old_enough {
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
    // ETXTBSY retry: between a sibling thread's fork() and its exec(), the
    // child briefly inherits every open fd — including a write fd on the
    // binary staged moments ago — and exec'ing the file during that window
    // fails with "Text file busy". The window is real for any multi-threaded
    // process (and bites the parallel test binary under coverage), so ride
    // it out with short sleeps instead of failing a fully verified download
    // — the same dance Go's os/exec and cargo do.
    const ETXTBSY_ATTEMPTS: u64 = 10;
    let mut attempt = 0u64;
    let output = loop {
        let mut cmd = tokio::process::Command::new(staged);
        cmd.arg("--version")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let result = tokio::time::timeout(std::time::Duration::from_secs(10), cmd.output())
            .await
            .map_err(|_| {
                UpdateError::VerifyFailed(
                    "downloaded binary hung during its --version self-check".to_string(),
                )
            })?;
        match result {
            Ok(output) => break output,
            Err(e)
                if e.kind() == std::io::ErrorKind::ExecutableFileBusy
                    && attempt < ETXTBSY_ATTEMPTS =>
            {
                attempt += 1;
                tokio::time::sleep(std::time::Duration::from_millis(25 * attempt)).await;
            }
            Err(e) => {
                return Err(UpdateError::VerifyFailed(format!(
                    "downloaded binary failed to execute (wrong architecture?): {e}"
                )));
            }
        }
    };
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
    let detail = format!("downloaded binary reports {reported:?} instead of version {expected}");
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
    fn stage_lands_executable_in_dest_dir_and_sweep_is_age_gated() {
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
        // A seconds-old stage may belong to a CONCURRENT update whose lock
        // lives in a different state dir (shared install, divergent HOMEs)
        // — the sweep must leave it alone.
        sweep_stale_stages(tmp.path());
        assert!(
            staged.exists(),
            "sweep must not remove a freshly-created (possibly live) stage"
        );
        // Aged past the threshold it is a crash leftover and goes away.
        #[cfg(unix)]
        {
            let ok = std::process::Command::new("touch")
                .args(["-m", "-t", "202001010000"])
                .arg(&staged)
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            assert!(ok, "touch -t must succeed to age the stage file");
            sweep_stale_stages(tmp.path());
            assert!(!staged.exists(), "sweep must remove old stage leftovers");
        }
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

        // Each rejection asserts the REASON, not just is_err(): an unrelated
        // spawn failure (e.g. the ETXTBSY race covered by the test below)
        // must not masquerade as the expected rejection.
        // Wrong program name: hard error in both modes.
        let imposter = write_script("imposter", "#!/bin/sh\necho other-tool 9.9.9\n");
        let err = sanity_exec(&imposter, &expected, false).await.unwrap_err();
        assert!(err.to_string().contains("identifies as"), "got: {err}");

        // Non-zero exit: hard error.
        let failing = write_script("failing", "#!/bin/sh\necho socket-patch 9.9.9\nexit 3\n");
        let err = sanity_exec(&failing, &expected, true).await.unwrap_err();
        assert!(err.to_string().contains("exited with"), "got: {err}");

        // Version mismatch: fatal in strict mode, warning otherwise.
        let mismatched = write_script("mismatch", "#!/bin/sh\necho socket-patch 1.0.0\n");
        let err = sanity_exec(&mismatched, &expected, true).await.unwrap_err();
        assert!(err.to_string().contains("instead of version"), "got: {err}");
        let warning = sanity_exec(&mismatched, &expected, false).await.unwrap();
        assert!(warning.unwrap().contains("1.0.0"));

        // Exact match: clean pass in strict mode.
        let good = write_script("good", "#!/bin/sh\necho socket-patch 9.9.9\n");
        assert_eq!(sanity_exec(&good, &expected, true).await.unwrap(), None);

        // Exec-format failure (not executable at all): hard error.
        let garbage = tmp.path().join("garbage");
        std::fs::write(&garbage, b"\x00\x01\x02").unwrap();
        let err = sanity_exec(&garbage, &expected, false).await.unwrap_err();
        assert!(err.to_string().contains("failed to execute"), "got: {err}");
    }

    // Regression test for the coverage-job flake: between a sibling thread's
    // fork() and its exec(), the child inherits every open fd — including a
    // write fd on the just-staged binary — and exec'ing the binary during
    // that window fails with ETXTBSY ("Text file busy"). Simulate the
    // inherited fd with a write handle held open briefly on another thread;
    // sanity_exec must ride it out instead of failing a verified download.
    // Linux-only: other platforms don't reliably enforce ETXTBSY.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn sanity_exec_retries_when_binary_briefly_text_busy() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("busy");
        std::fs::write(&path, "#!/bin/sh\necho socket-patch 9.9.9\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let held = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        let dropper = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(150));
            drop(held);
        });

        let result = sanity_exec(&path, &semver::Version::new(9, 9, 9), true).await;
        dropper.join().unwrap();
        assert_eq!(result.unwrap(), None);
    }

    // ── 2026-09 coverage audit additions ────────────────────────────────

    /// Like [`tgz_with`], but streams `len` zero bytes from `io::repeat`
    /// so the input side never materializes — the archive stays tiny
    /// (gzip of zeros) and only the extraction side allocates.
    fn tgz_with_sized_member(name: &str, len: u64) -> Vec<u8> {
        use std::io::Read;
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        let mut header = tar::Header::new_gnu();
        header.set_size(len);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, name, std::io::repeat(0).take(len))
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    }

    /// Single-member zip whose `socket-patch.exe` entry is `len` zero
    /// bytes, streamed through the deflater (zeros deflate ~1000:1, so the
    /// archive stays small even for an over-cap member).
    fn zip_with_zero_member(len: u64) -> Vec<u8> {
        use std::io::Read;
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut buf);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            writer.start_file("socket-patch.exe", opts).unwrap();
            std::io::copy(&mut std::io::repeat(0).take(len), &mut writer).unwrap();
            writer.finish().unwrap();
        }
        buf.into_inner()
    }

    /// The decompressed-size cap on the tar.gz path — the zip-bomb defense
    /// for the primary (Unix) archive format. The member streams one byte
    /// past the cap; the read side transiently holds ~256 MiB, the archive
    /// itself is a few hundred KiB of gzipped zeros.
    #[test]
    fn targz_member_over_cap_refused() {
        let archive = tgz_with_sized_member("socket-patch", MAX_BINARY_BYTES + 1);
        let err = extract_binary("socket-patch-x.tar.gz", &archive).unwrap_err();
        assert!(err.to_string().contains("exceeds the"), "{err}");
    }

    /// The zip path's early refusal: an HONEST header declaring an
    /// over-cap uncompressed size is rejected before any decompression.
    #[test]
    fn zip_declared_size_over_cap_refused() {
        let archive = zip_with_zero_member(MAX_BINARY_BYTES + 1);
        let err = extract_binary("socket-patch-x.zip", &archive).unwrap_err();
        assert!(err.to_string().contains("exceeds the"), "{err}");
    }

    /// The zip path's post-read backstop: a LYING header. The zip crate's
    /// Deflated decompressor does not bound its output at the declared
    /// uncompressed size (verified against the vendored zip 8.6.0 source:
    /// only the LZMA/legacy decoders consume `uncompressed_size`, and
    /// `Crc32Reader` validates only at stream EOF), so a zip whose size
    /// fields are byte-patched down sails past the declared-size check and
    /// must be caught by the byte count after reading. If a future zip
    /// crate starts enforcing the declared size on read, this becomes a
    /// read error instead — keep the rejection assertion but re-audit the
    /// post-read branch's reachability then.
    #[test]
    fn zip_lying_size_fields_hit_post_read_cap() {
        let mut archive = zip_with_zero_member(MAX_BINARY_BYTES + 1);
        let lie = 64u32.to_le_bytes();
        // Local file header (PK\x03\x04 at 0): uncompressed size at +22.
        assert_eq!(&archive[0..4], b"PK\x03\x04", "unexpected zip layout");
        archive[22..26].copy_from_slice(&lie);
        // Central directory entry: uncompressed size at +24 from the
        // PK\x01\x02 signature (last occurrence — the deflate stream of
        // zeros cannot contain it, but scan from the end regardless).
        let cd = archive
            .windows(4)
            .rposition(|w| w == b"PK\x01\x02")
            .expect("central directory signature");
        archive[cd + 24..cd + 28].copy_from_slice(&lie);
        // Anti-vacuity: prove the patch landed — the entry now DECLARES 64
        // bytes, so the declared-size check at the top of the extraction
        // cannot be the branch that rejects; only the post-read cap can.
        {
            let mut probe = zip::ZipArchive::new(std::io::Cursor::new(&archive[..])).unwrap();
            assert_eq!(
                probe.by_name("socket-patch.exe").unwrap().size(),
                64,
                "central-directory size patch must have landed"
            );
        }
        let err = extract_binary("socket-patch-x.zip", &archive).unwrap_err();
        assert!(err.to_string().contains("exceeds the"), "{err}");
    }

    /// Non-EACCES open failures must stay `SwapFailed` — only the
    /// permissions preflight (`PermissionDenied`) earns the sudo hint.
    #[test]
    fn stage_open_failure_not_eacces_is_swap_failed() {
        let tmp = tempfile::tempdir().unwrap();
        // Missing destination dir: NotFound.
        let err = stage_binary(&tmp.path().join("nope"), b"x").unwrap_err();
        assert!(
            matches!(err, UpdateError::SwapFailed(_)),
            "NotFound must not masquerade as PermissionDenied: {err}"
        );
        assert!(err.to_string().contains("cannot stage into"), "{err}");
        // Destination "dir" is a regular file: NotADirectory (exact io
        // message differs per-OS, so only the variant is pinned).
        let file = tmp.path().join("file");
        std::fs::write(&file, b"").unwrap();
        let err = stage_binary(&file, b"x").unwrap_err();
        assert!(
            matches!(err, UpdateError::SwapFailed(_)),
            "NotADirectory must not masquerade as PermissionDenied: {err}"
        );
    }

    /// A destination dir that cannot be listed (vanished install dir) is a
    /// silent early return — the best-effort sweep must neither panic nor
    /// conjure the directory into existence.
    #[test]
    fn sweep_tolerates_unlistable_dest_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("never-existed");
        sweep_stale_stages(&missing);
        assert!(!missing.exists(), "sweep must not create the destination dir");
    }

    /// A write failure AFTER a successful open (EFBIG here, standing in
    /// for ENOSPC/EIO) must remove the stage file — no `.socket-patch.
    /// stage-*` husk next to the install — and map to `SwapFailed`.
    ///
    /// The capped body runs in a CHILD PROCESS: `RLIMIT_FSIZE` (and the
    /// ignored `SIGXFSZ`) are process-wide, and capping them in the shared
    /// test process killed the whole workspace suite before #227. Same
    /// re-exec choreography as
    /// `utils::fs::tests::atomic_write_failed_stage_write_errors_and_keeps_target`.
    #[cfg(unix)]
    #[test]
    fn stage_write_failure_cleans_up_stage_file() {
        const CHILD_ENV: &str = "SOCKET_PATCH_CORE_TEST_STAGE_FSIZE_CHILD";
        const TEST_NAME: &str =
            "update::download::tests::stage_write_failure_cleans_up_stage_file";
        if std::env::var_os(CHILD_ENV).is_none() {
            let exe = std::env::current_exe().expect("test binary path must resolve");
            let output = std::process::Command::new(exe)
                .args([TEST_NAME, "--exact", "--test-threads=1", "--nocapture"])
                .env(CHILD_ENV, "1")
                .output()
                .expect("the capped child test process must spawn");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success(),
                "the capped child run failed:\nstdout:\n{stdout}\nstderr:\n{}",
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

        struct FsizeGuard {
            prev: libc::rlimit,
            prev_handler: libc::sighandler_t,
        }
        impl Drop for FsizeGuard {
            fn drop(&mut self) {
                unsafe {
                    libc::setrlimit(libc::RLIMIT_FSIZE, &self.prev);
                    libc::signal(libc::SIGXFSZ, self.prev_handler);
                }
            }
        }

        let tmp = tempfile::tempdir().unwrap();

        // Exceeding RLIMIT_FSIZE delivers SIGXFSZ (default: kill); ignore
        // it so the write fails with EFBIG instead. Guard restores both.
        let guard = unsafe {
            let mut prev = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut prev), 0);
            let prev_handler = libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
            let capped = libc::rlimit {
                rlim_cur: 256 * 1024,
                rlim_max: prev.rlim_max,
            };
            assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &capped), 0);
            FsizeGuard { prev, prev_handler }
        };

        // stage_binary is synchronous std::fs, so write_all surfaces EFBIG
        // directly (no tokio background-write indirection here).
        let result = stage_binary(tmp.path(), &vec![0u8; 1024 * 1024]);
        drop(guard);

        let err = result.unwrap_err();
        assert!(
            matches!(err, UpdateError::SwapFailed(_)),
            "expected SwapFailed, got: {err}"
        );
        assert!(err.to_string().contains("error writing staged binary"), "{err}");
        let leftovers: Vec<String> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            leftovers.is_empty(),
            "the failed stage file must be removed, found: {leftovers:?}"
        );
    }

    /// The 10-second hang timeout — the only `sanity_exec` branch no other
    /// test executes: a wedged (or wrong-arch-but-execable) binary must be
    /// killed, not awaited. Costs ~10s wall clock (the timeout is
    /// hardcoded, no injection point); runs concurrently with siblings.
    /// The error message is the discriminator: had the timeout NOT fired,
    /// `sleep 30` would eventually exit 0 with empty stdout and produce
    /// the "identifies as" error instead.
    #[cfg(unix)]
    #[tokio::test]
    async fn sanity_exec_hung_binary_times_out() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("hung");
        std::fs::write(&script, "#!/bin/sh\nsleep 30\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let start = std::time::Instant::now();
        let err = sanity_exec(&script, &semver::Version::new(9, 9, 9), true)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("hung during its --version self-check"),
            "got: {err}"
        );
        // Generous bound — strictly under the child's 30s sleep — proving
        // the hardcoded 10s timeout fired rather than the sleep being
        // awaited. Do not tighten: coverage jobs run hot.
        assert!(
            start.elapsed() < std::time::Duration::from_secs(25),
            "timeout must bound the self-check, took {:?}",
            start.elapsed()
        );
    }
}
