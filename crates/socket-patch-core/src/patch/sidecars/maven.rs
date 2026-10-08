//! Maven / Gradle checksum sidecars.
//!
//! A `~/.m2` artifact may sit beside `<file>.sha1` / `<file>.md5`
//! checksum files (Maven writes them when the remote served them). After a
//! patch they describe bytes that are gone, which `mvn -C`
//! (`--strict-checksums`) and mirror tooling report as corruption. They are
//! rewritten — first hex token replaced, the rest of the file and the
//! token's case kept — but only when present AND describing the pre-patch
//! bytes: a checksum file that already disagreed with the jar is somebody
//! else's state, left alone. Rollback puts the same files back to the
//! restored bytes, which reproduces them exactly ([`snapshot`] +
//! [`resync`] on both sides).
//!
//! A Gradle `files-2.1` copy has no checksum file: its hash directory names
//! the download's sha1. Patching one gets Info advisories
//! ([`gradle_advisories`]) about what can undo or hide it instead.

use std::path::{Path, PathBuf};

use super::{
    SidecarAdvisory, SidecarAdvisoryCode, SidecarError, SidecarFile, SidecarFileAction,
    SidecarPayload, SidecarSeverity,
};
use crate::crawlers::gradle_cache;

/// A checksum file's algorithm, by its extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algo {
    Sha1,
    Md5,
}

impl Algo {
    const ALL: [Algo; 2] = [Algo::Sha1, Algo::Md5];

    fn ext(self) -> &'static str {
        match self {
            Algo::Sha1 => "sha1",
            Algo::Md5 => "md5",
        }
    }

    fn digest(self, bytes: &[u8]) -> String {
        match self {
            Algo::Sha1 => crate::utils::digest::sha1_hex_of(bytes),
            Algo::Md5 => hex::encode(md5(bytes)),
        }
    }
}

/// The checksum files of one artifact directory that described their
/// file's bytes when [`snapshot`] read them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    entries: Vec<(String, Algo)>,
}

impl Snapshot {
    /// Whether no checksum file qualified.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Bounded read of a checksum file: anything larger is not one.
const MAX_SIDECAR_BYTES: u64 = 4096;

/// The first whitespace-delimited token of a checksum file and the byte
/// range it spans.
fn first_token(text: &str) -> Option<(usize, usize)> {
    let start = text.find(|c: char| !c.is_whitespace())?;
    let len = text[start..]
        .find(char::is_whitespace)
        .unwrap_or(text.len() - start);
    Some((start, start + len))
}

/// `dir/<leaf>.<ext>` as text when it is a regular, small, UTF-8 file.
fn read_sidecar(path: &Path) -> Option<String> {
    // A symlinked sidecar is not followed; the read itself is the
    // non-blocking regular-file one, so a FIFO swapped in after the
    // `lstat` fails fast instead of wedging in open(2).
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_SIDECAR_BYTES {
        return None;
    }
    let bytes = crate::utils::fs::read_regular_to_bytes_sync(path).ok()?;
    if bytes.len() as u64 > MAX_SIDECAR_BYTES {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// The checksum files beside each of `leaves` (patch-file keys, `package/`
/// prefix allowed) in `dir` that exist and describe the file's CURRENT
/// bytes. Call before the write (apply) or before the restore (rollback):
/// [`resync`] then rewrites exactly these to the new bytes.
pub async fn snapshot(dir: &Path, leaves: &[String]) -> Snapshot {
    let dir = dir.to_path_buf();
    let leaves: Vec<String> = leaves
        .iter()
        .map(|k| crate::patch::apply::normalize_file_path(k).to_string())
        .filter(|leaf| !leaf.is_empty() && !leaf.contains(['/', '\\']) && leaf != "..")
        .collect();
    crate::utils::fs::run_blocking(move || {
        let mut out = Snapshot::default();
        for leaf in leaves {
            let Ok(bytes) = crate::utils::fs::read_regular_to_bytes_sync(&dir.join(&leaf)) else {
                continue;
            };
            for algo in Algo::ALL {
                let Some(text) = read_sidecar(&dir.join(format!("{leaf}.{}", algo.ext()))) else {
                    continue;
                };
                let Some((start, end)) = first_token(&text) else {
                    continue;
                };
                if text[start..end].eq_ignore_ascii_case(&algo.digest(&bytes)) {
                    out.entries.push((leaf.clone(), algo));
                }
            }
        }
        out
    })
    .await
}

/// Rewrite every checksum file of `snapshot` to its file's current bytes:
/// the first hex token replaced (its case kept), every other byte of the
/// file kept. A checksum file already right, or gone since, is skipped.
pub async fn resync(dir: &Path, snapshot: &Snapshot) -> Result<Vec<SidecarFile>, SidecarError> {
    let mut out = Vec::new();
    for (leaf, algo) in &snapshot.entries {
        let path = dir.join(format!("{leaf}.{}", algo.ext()));
        let Some(text) = read_sidecar(&path) else {
            continue;
        };
        let Some((start, end)) = first_token(&text) else {
            continue;
        };
        let bytes = crate::utils::fs::read_regular_to_bytes(&dir.join(leaf))
            .await
            .map_err(|source| SidecarError::Io {
                path: dir.join(leaf).display().to_string(),
                source,
            })?;
        let mut digest = algo.digest(&bytes);
        let old = &text[start..end];
        if old.eq_ignore_ascii_case(&digest) {
            continue;
        }
        if old.bytes().any(|b| b.is_ascii_uppercase()) {
            digest.make_ascii_uppercase();
        }
        let rewritten = format!("{}{digest}{}", &text[..start], &text[end..]);
        crate::utils::fs::atomic_write_bytes_preserving_mode(&path, rewritten.as_bytes())
            .await
            .map_err(|source| SidecarError::Io {
                path: path.display().to_string(),
                source,
            })?;
        out.push(SidecarFile {
            path: format!("{leaf}.{}", algo.ext()),
            action: SidecarFileAction::Rewritten,
        });
    }
    Ok(out)
}

/// The Maven arm of [`super::dispatch_fixup_with`]: a Gradle hash directory
/// gets [`gradle_advisories`]' first advisory (the others ride on extra
/// records, see [`gradle_extra_records`]); any other directory gets its
/// `pre` checksum files resynced.
pub(crate) async fn fixup(
    pkg_path: &Path,
    pre: Option<&Snapshot>,
) -> Result<Option<SidecarPayload>, SidecarError> {
    if is_gradle_hash_dir(pkg_path) {
        return Ok(gradle_advisories(pkg_path)
            .into_iter()
            .next()
            .map(|advisory| SidecarPayload {
                files: Vec::new(),
                advisory: Some(advisory),
            }));
    }
    let Some(pre) = pre.filter(|p| !p.is_empty()) else {
        return Ok(None);
    };
    let files = resync(pkg_path, pre).await?;
    Ok((!files.is_empty()).then_some(SidecarPayload {
        files,
        advisory: None,
    }))
}

/// Whether `dir` is a hash directory of a Gradle `files-2.1` version dir.
pub fn is_gradle_hash_dir(dir: &Path) -> bool {
    dir.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(gradle_cache::is_hash_dir_name)
        && dir
            .parent()
            .is_some_and(gradle_cache::is_gradle_version_dir)
}

/// The Gradle user home a writable `files-2.1` hash dir belongs to
/// (`<home>/caches/modules-2/files-2.1/<g>/<a>/<v>/<hash>`).
pub fn gradle_user_home_of(hash_dir: &Path) -> Option<PathBuf> {
    let files21 = hash_dir.ancestors().nth(4)?;
    let modules2 = files21.parent()?;
    let caches = modules2.parent()?;
    (modules2.file_name()? == "modules-2" && caches.file_name()? == "caches")
        .then(|| caches.parent().map(Path::to_path_buf))
        .flatten()
}

/// Whether a Gradle daemon of `user_home` has registered itself
/// (`daemon/<version>/registry.bin`): one may still hold pre-patch bytes.
fn daemon_registered(user_home: &Path) -> bool {
    std::fs::read_dir(user_home.join("daemon"))
        .into_iter()
        .flatten()
        .flatten()
        .any(|e| e.path().join("registry.bin").is_file())
}

/// What can undo or hide a patch written into the Gradle hash dir
/// `hash_dir` (all Info): a refresh re-downloads it; a registered daemon
/// may keep the old bytes loaded; the user home is shared by every build of
/// the account.
pub fn gradle_advisories(hash_dir: &Path) -> Vec<SidecarAdvisory> {
    let info = |code, message: String| SidecarAdvisory {
        code,
        severity: SidecarSeverity::Info,
        message,
    };
    let mut out = vec![info(
        SidecarAdvisoryCode::GradleRefreshReverts,
        "Gradle: `--refresh-dependencies` (or a changed upstream artifact) downloads this \
         artifact again into a new cache entry, which reverts the patch; re-run \
         `socket-patch apply` after a refresh."
            .to_string(),
    )];
    let home = gradle_user_home_of(hash_dir);
    if home.as_deref().is_some_and(daemon_registered) {
        out.push(info(
            SidecarAdvisoryCode::GradleDaemonStale,
            "Gradle: a daemon of this Gradle user home may still hold the pre-patch jar or \
             classes derived from it; run `gradle --stop` before the next build."
                .to_string(),
        ));
    }
    out.push(info(
        SidecarAdvisoryCode::GradleGlobalCacheShared,
        format!(
            "Gradle: the patched cache {} is shared by every build that uses this Gradle user \
             home, not only this project.",
            home.as_deref()
                .map(|h| h.display().to_string())
                .unwrap_or_else(|| "(files-2.1)".to_string())
        ),
    ));
    out
}

/// The [`gradle_advisories`] of `hash_dir` after the first (which the copy's
/// own [`super::SidecarRecord`] carries), each as its own record for
/// `package_key`.
pub fn gradle_extra_records(package_key: &str, hash_dir: &Path) -> Vec<super::SidecarRecord> {
    if !is_gradle_hash_dir(hash_dir) {
        return Vec::new();
    }
    gradle_advisories(hash_dir)
        .into_iter()
        .skip(1)
        .map(|advisory| super::SidecarRecord {
            purl: package_key.to_string(),
            ecosystem: "maven".to_string(),
            files: Vec::new(),
            advisory: Some(advisory),
        })
        .collect()
}

/// The Windows "file in use" errors of a write to `target`: a Gradle
/// daemon holding the jar open. `ERROR_SHARING_VIOLATION` (32),
/// `ERROR_LOCK_VIOLATION` (33) and `ERROR_DELETE_PENDING` (303) always;
/// `ERROR_ACCESS_DENIED` (5) when `target` exists and is not read-only —
/// the stage-and-rename write fails with it when another process holds
/// the target open without `FILE_SHARE_DELETE`, as a JVM `ZipFile` does
/// (the same codes `apply_lock` treats as "in use"). Always false
/// elsewhere.
pub fn is_locked_by_daemon(e: &std::io::Error, target: &Path) -> bool {
    if !cfg!(windows) {
        return false;
    }
    match e.raw_os_error() {
        Some(32 | 33 | 303) => true,
        Some(5) => {
            std::fs::metadata(target).is_ok_and(|m| m.is_file() && !m.permissions().readonly())
        }
        _ => false,
    }
}

/// The advisory for a write [`is_locked_by_daemon`] refused.
pub fn locked_by_daemon_advisory(path: &Path) -> SidecarAdvisory {
    SidecarAdvisory {
        code: SidecarAdvisoryCode::GradleJarLockedByDaemon,
        severity: SidecarSeverity::Error,
        message: format!(
            "Gradle: {} is held open by another process (normally a Gradle daemon); run \
             `gradle --stop` and apply again.",
            path.display()
        ),
    }
}

/// RFC 1321 MD5 (no md5 crate in the dependency set; Maven still writes
/// `.md5` checksum files).
fn md5(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: Vec<u32> = (0..64)
        .map(|i| ((i as f64 + 1.0).sin().abs() * 4294967296.0) as u32)
        .collect();
    let mut state: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    let mut msg = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());
    for chunk in msg.chunks(64) {
        let m: Vec<u32> = chunk
            .chunks(4)
            .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
            .collect();
        let [mut a, mut b, mut c, mut d] = state;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let rotated = a
                .wrapping_add(f)
                .wrapping_add(k[i])
                .wrapping_add(m[g])
                .rotate_left(S[i]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(rotated);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }
    let mut out = [0u8; 16];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B74: a FIFO sidecar reads as absent and returns at once.
    #[cfg(unix)]
    #[test]
    fn read_sidecar_rejects_a_fifo_without_blocking() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("lib-1.0.jar.sha1");
        let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert_eq!(read_sidecar(&path), None);
    }

    #[test]
    fn md5_matches_rfc1321_vectors() {
        assert_eq!(hex::encode(md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex::encode(md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex::encode(md5(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            )),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    fn setup(dir: &Path, sha1_text: Option<&str>, md5_text: Option<&str>) {
        std::fs::write(dir.join("lib-1.0.jar"), b"original").unwrap();
        if let Some(t) = sha1_text {
            std::fs::write(dir.join("lib-1.0.jar.sha1"), t).unwrap();
        }
        if let Some(t) = md5_text {
            std::fs::write(dir.join("lib-1.0.jar.md5"), t).unwrap();
        }
    }

    fn keys() -> Vec<String> {
        vec!["package/lib-1.0.jar".to_string()]
    }

    /// A checksum file matching the pre-patch bytes is rewritten to the
    /// patched bytes (format and case kept), and a rollback's resync puts
    /// back exactly the original text.
    #[tokio::test]
    async fn matching_sidecars_rewrite_and_restore_exactly() {
        let d = tempfile::tempdir().unwrap();
        let sha1_orig = format!("{}  lib-1.0.jar\n", Algo::Sha1.digest(b"original"));
        let md5_orig = Algo::Md5.digest(b"original").to_ascii_uppercase();
        setup(d.path(), Some(&sha1_orig), Some(&md5_orig));

        let pre = snapshot(d.path(), &keys()).await;
        assert_eq!(pre.entries.len(), 2);
        std::fs::write(d.path().join("lib-1.0.jar"), b"patched").unwrap();
        let payload = fixup(d.path(), Some(&pre)).await.unwrap().unwrap();
        assert_eq!(payload.files.len(), 2);
        assert_eq!(
            std::fs::read_to_string(d.path().join("lib-1.0.jar.sha1")).unwrap(),
            format!("{}  lib-1.0.jar\n", Algo::Sha1.digest(b"patched"))
        );
        assert_eq!(
            std::fs::read_to_string(d.path().join("lib-1.0.jar.md5")).unwrap(),
            Algo::Md5.digest(b"patched").to_ascii_uppercase()
        );

        // Rollback: snapshot against the patched bytes, restore, resync.
        let pre = snapshot(d.path(), &keys()).await;
        std::fs::write(d.path().join("lib-1.0.jar"), b"original").unwrap();
        resync(d.path(), &pre).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(d.path().join("lib-1.0.jar.sha1")).unwrap(),
            sha1_orig
        );
        assert_eq!(
            std::fs::read_to_string(d.path().join("lib-1.0.jar.md5")).unwrap(),
            md5_orig
        );
    }

    /// A checksum file that did not describe the pre-patch bytes is
    /// somebody else's state: never touched, by apply or rollback.
    #[tokio::test]
    async fn mismatched_sidecar_is_untouched() {
        let d = tempfile::tempdir().unwrap();
        setup(
            d.path(),
            Some("0000000000000000000000000000000000000000"),
            None,
        );
        let pre = snapshot(d.path(), &keys()).await;
        assert!(pre.is_empty());
        std::fs::write(d.path().join("lib-1.0.jar"), b"patched").unwrap();
        assert!(fixup(d.path(), Some(&pre)).await.unwrap().is_none());
        let pre = snapshot(d.path(), &keys()).await;
        std::fs::write(d.path().join("lib-1.0.jar"), b"original").unwrap();
        assert!(resync(d.path(), &pre).await.unwrap().is_empty());
        assert_eq!(
            std::fs::read_to_string(d.path().join("lib-1.0.jar.sha1")).unwrap(),
            "0000000000000000000000000000000000000000"
        );
    }

    /// No checksum files: nothing created.
    #[tokio::test]
    async fn absent_sidecars_stay_absent() {
        let d = tempfile::tempdir().unwrap();
        setup(d.path(), None, None);
        let pre = snapshot(d.path(), &keys()).await;
        std::fs::write(d.path().join("lib-1.0.jar"), b"patched").unwrap();
        assert!(fixup(d.path(), Some(&pre)).await.unwrap().is_none());
        assert!(!d.path().join("lib-1.0.jar.sha1").exists());
        assert!(!d.path().join("lib-1.0.jar.md5").exists());
    }

    /// A Gradle hash dir gets the refresh advisory on its record, the
    /// daemon advisory only when a daemon registered, and the shared-cache
    /// one always.
    #[tokio::test]
    async fn gradle_hash_dir_advisories() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path().join(".gradle");
        let hash = home.join("caches/modules-2/files-2.1/g/a/1.0/0abc");
        std::fs::create_dir_all(&hash).unwrap();
        assert!(is_gradle_hash_dir(&hash));
        assert_eq!(gradle_user_home_of(&hash).as_deref(), Some(home.as_path()));
        let payload = fixup(&hash, None).await.unwrap().unwrap();
        assert_eq!(
            payload.advisory.unwrap().code,
            SidecarAdvisoryCode::GradleRefreshReverts
        );
        let codes = |v: Vec<super::super::SidecarRecord>| {
            v.into_iter()
                .map(|r| r.advisory.unwrap().code)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            codes(gradle_extra_records("pkg:maven/g/a@1.0", &hash)),
            [SidecarAdvisoryCode::GradleGlobalCacheShared]
        );
        std::fs::create_dir_all(home.join("daemon/8.14.3")).unwrap();
        std::fs::write(home.join("daemon/8.14.3/registry.bin"), b"").unwrap();
        assert_eq!(
            codes(gradle_extra_records("pkg:maven/g/a@1.0", &hash)),
            [
                SidecarAdvisoryCode::GradleDaemonStale,
                SidecarAdvisoryCode::GradleGlobalCacheShared
            ]
        );
        assert!(gradle_extra_records("pkg:maven/g/a@1.0", d.path()).is_empty());
    }
}
