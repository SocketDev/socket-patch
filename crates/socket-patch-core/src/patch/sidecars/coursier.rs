//! Coursier checksum sidecars.
//!
//! Coursier keeps, beside each cached file `F`, `.<F>__<algo>` (lowercase
//! hex, no newline) and `.<F>__<algo>.computed` (raw digest) for sha1 /
//! sha256 / sha512 / md5, plus `.<F>.checked`. On every resolution it
//! compares `__sha1` with the `.computed` digest (recomputing that only
//! when it is missing) and, on a mismatch, silently deletes `F` and
//! downloads the pristine one again. So after a patch rewrites `F` in
//! place, a stale `__sha1` reverts the patch as soon as its `.computed`
//! goes away, and a fresh `__sha1` beside a stale `.computed` reverts it at
//! once (both probed).
//!
//! [`resync`] therefore first deletes every checksum sidecar of `F`, each
//! `__<algo>` before its `.computed` (no checksum file is the probed state
//! that keeps the patch), then, for sha1 / sha256 / sha512 where a
//! `__<algo>` existed, writes the new `.computed` and only then the new
//! `__<algo>`. Each step is an atomic stage + rename, so a crash or an I/O
//! error between any two leaves every algorithm either without a checksum
//! file or with a matching pair: never a stale checksum. md5 stays deleted
//! (Coursier verifies SHA-1); `.checked` (a TTL marker) is left alone.
//!
//! A Maven `~/.m2` or Ivy file has no such sidecars, so `resync` returns
//! `[]` there and the JSON envelope is unchanged. Rollback runs the same
//! `resync` over the restored bytes: the result is Coursier-consistent,
//! but md5 is not restored.

use std::path::{Path, PathBuf};

use sha1::Digest as _;

use super::{SidecarError, SidecarFile, SidecarFileAction, SidecarPayload};
use crate::crawlers::Ecosystem;
use crate::patch::apply::{is_safe_relative_subpath, normalize_file_path};

/// The checksum algorithms Coursier may keep a sidecar for, in the order
/// they are resynced.
const ALGORITHMS: &[&str] = &["sha1", "sha256", "sha512", "md5"];

/// The ones rewritten after the delete pass (md5 is not).
const REWRITTEN: &[&str] = &["sha1", "sha256", "sha512"];

/// Resync the Coursier sidecars of `file` to its current bytes; the
/// sidecars touched (relative to `file`'s directory), in the order they
/// were touched. Idempotent. A missing `file` (rollback removed a file the
/// patch added) gets its sidecars deleted and none rewritten.
pub fn resync(file: &Path) -> Result<Vec<SidecarFile>, SidecarError> {
    resync_with(file, false, &mut |_| Ok(()))
}

/// [`resync`] only where an earlier resync of `file`'s current bytes was
/// interrupted or never ran ([`interrupted`]): the retry an apply or
/// rollback that wrote nothing runs. A copy Coursier left consistent (a
/// pristine one a rollback finds already original, md5 and all) is not
/// touched and yields no record.
fn resync_if_stale(file: &Path) -> Result<Vec<SidecarFile>, SidecarError> {
    resync_with(file, true, &mut |_| Ok(()))
}

/// [`resync`] (or, with `stale_only`, [`resync_if_stale`]) with `before`
/// called ahead of every filesystem mutation (the fault-injection seam: an
/// `Err` aborts there, as a crash or I/O error would).
fn resync_with(
    file: &Path,
    stale_only: bool,
    before: &mut dyn FnMut(&Path) -> std::io::Result<()>,
) -> Result<Vec<SidecarFile>, SidecarError> {
    let (Some(dir), Some(name)) = (file.parent(), file.file_name().and_then(|n| n.to_str())) else {
        return Ok(Vec::new());
    };
    let sidecar = |algo: &str, computed: bool| {
        let suffix = if computed { ".computed" } else { "" };
        format!(".{name}__{algo}{suffix}")
    };
    let present = |rel: &str| std::fs::symlink_metadata(dir.join(rel)).is_ok();
    let had: Vec<&str> = ALGORITHMS
        .iter()
        .copied()
        .filter(|algo| present(&sidecar(algo, false)) || present(&sidecar(algo, true)))
        .collect();
    if had.is_empty() {
        return Ok(Vec::new());
    }
    // A lone `.computed` also counts: it is what an interrupted earlier
    // resync leaves between writing the digest and the checksum.
    let rewrite: Vec<&str> = REWRITTEN
        .iter()
        .copied()
        .filter(|algo| had.contains(algo))
        .collect();
    let bytes = match crate::utils::fs::read_regular_to_bytes_sync(file) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(source) => return Err(io_error(file, source)),
    };

    if bytes.as_deref().is_some_and(|bytes| {
        in_sync(dir, &sidecar, &had, bytes)
            || (stale_only && !interrupted(dir, &sidecar, &had, bytes))
    }) {
        return Ok(Vec::new());
    }

    let mut touched = Vec::new();
    // 1. Delete: the checksum before its cached digest, so a stale
    //    checksum never stands without the digest that masks it.
    for algo in &had {
        for computed in [false, true] {
            let rel = sidecar(algo, computed);
            let path = dir.join(&rel);
            if !present(&rel) {
                continue;
            }
            before(&path).map_err(|e| io_error(&path, e))?;
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(io_error(&path, e)),
            }
            touched.push((rel, SidecarFileAction::Deleted));
        }
    }
    // 2. Rewrite: the digest first, then the checksum that must match it.
    let Some(bytes) = bytes else {
        return Ok(finish(touched));
    };
    for algo in &rewrite {
        let digest = digest(algo, &bytes);
        for (computed, content) in [
            (true, digest.clone()),
            (false, hex::encode(&digest).into_bytes()),
        ] {
            let rel = sidecar(algo, computed);
            let path = dir.join(&rel);
            before(&path).map_err(|e| io_error(&path, e))?;
            crate::utils::fs::atomic_write_sync(&path, &content, false)
                .map_err(|e| io_error(&path, e))?;
            touched.push((rel, SidecarFileAction::Rewritten));
        }
    }
    Ok(finish(touched))
}

/// Whether the sidecars of `bytes` are already what a resync would leave
/// (no md5, every sha checksum matching with its digest), so a re-run
/// touches nothing.
fn in_sync(dir: &Path, sidecar: &dyn Fn(&str, bool) -> String, had: &[&str], bytes: &[u8]) -> bool {
    had.iter().all(|algo| {
        if !REWRITTEN.contains(algo) {
            return false;
        }
        let digest = digest(algo, bytes);
        let read = |computed| {
            crate::utils::fs::read_regular_to_bytes_sync(&dir.join(sidecar(algo, computed))).ok()
        };
        read(false).is_some_and(|sum| sum == hex::encode(&digest).into_bytes())
            && read(true).is_some_and(|raw| raw == digest)
    })
}

/// Whether `bytes`' sidecars show a resync to them was interrupted or never
/// ran: a sha checksum or cached digest that disagrees with them (every
/// step of an interrupted resync before its delete pass reached md5 leaves
/// one, the stale pair it started from or a lone stale `.computed`), or an
/// md5 sidecar without a matching `__sha1` (the delete pass stopped at
/// md5). A checksum is compared as Coursier reads a downloaded one: first
/// token, any case.
fn interrupted(
    dir: &Path,
    sidecar: &dyn Fn(&str, bool) -> String,
    had: &[&str],
    bytes: &[u8],
) -> bool {
    let read = |algo: &str, computed: bool| {
        crate::utils::fs::read_regular_to_bytes_sync(&dir.join(sidecar(algo, computed))).ok()
    };
    let sum_matches = |sum: &[u8], digest: &[u8]| {
        String::from_utf8_lossy(sum)
            .split_whitespace()
            .next()
            .is_some_and(|token| token.eq_ignore_ascii_case(&hex::encode(digest)))
    };
    let stale_sha = REWRITTEN
        .iter()
        .filter(|algo| had.contains(algo))
        .any(|algo| {
            let digest = digest(algo, bytes);
            read(algo, false).is_some_and(|sum| !sum_matches(&sum, &digest))
                || read(algo, true).is_some_and(|raw| raw != digest)
        });
    let sha1_ok = read("sha1", false).is_some_and(|sum| sum_matches(&sum, &digest("sha1", bytes)));
    stale_sha || (had.contains(&"md5") && !sha1_ok)
}

/// The sidecar record for a Maven package whose every file already holds
/// its target bytes (apply: all `AlreadyPatched`; rollback: all
/// `AlreadyOriginal`), where the engine writes nothing and so never
/// reaches its sidecar boundary: an earlier run that rewrote the bytes but
/// failed its resync gets it retried here. `None` for any other ecosystem
/// and when nothing needed resyncing; a failure becomes the uniform
/// `sidecar_fixup_failed` record, `failed` naming the direction.
pub(crate) fn retry_record(
    package_key: &str,
    pkg_path: &Path,
    keys: &[String],
    failed: &str,
) -> Option<super::SidecarRecord> {
    if Ecosystem::from_purl(package_key) != Some(Ecosystem::Maven) {
        return None;
    }
    match fixup_with(pkg_path, keys, resync_if_stale) {
        Ok(payload) => payload.map(|p| super::SidecarRecord {
            purl: package_key.to_string(),
            ecosystem: "maven".to_string(),
            files: p.files,
            advisory: p.advisory,
        }),
        Err(e) => Some(super::fixup_failed_record(
            package_key,
            format!("{failed}: {e}"),
        )),
    }
}

/// One entry per sidecar, with its final action (a deleted-then-rewritten
/// file is `rewritten`), in first-touch order.
fn finish(touched: Vec<(String, SidecarFileAction)>) -> Vec<SidecarFile> {
    let mut out: Vec<SidecarFile> = Vec::new();
    for (path, action) in touched {
        match out.iter_mut().find(|f| f.path == path) {
            Some(existing) => existing.action = action,
            None => out.push(SidecarFile { path, action }),
        }
    }
    out
}

fn digest(algo: &str, bytes: &[u8]) -> Vec<u8> {
    match algo {
        "sha1" => sha1::Sha1::digest(bytes).to_vec(),
        "sha256" => sha2::Sha256::digest(bytes).to_vec(),
        "sha512" => sha2::Sha512::digest(bytes).to_vec(),
        other => unreachable!("no rewrite for {other}"),
    }
}

fn io_error(path: &Path, source: std::io::Error) -> SidecarError {
    SidecarError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// [`resync`] over every patched file of a Maven package at `pkg_path`
/// (keys relative to it, `package/` prefix allowed); `None` when no
/// Coursier sidecar was touched. Sidecar paths come back relative to
/// `pkg_path`. An escaping key is refused before anything is touched.
pub(crate) fn fixup(
    pkg_path: &Path,
    patched: &[String],
) -> Result<Option<SidecarPayload>, SidecarError> {
    fixup_with(pkg_path, patched, resync)
}

/// [`fixup`] through `resync_one` ([`resync`], or [`resync_if_stale`] for
/// a retry).
fn fixup_with(
    pkg_path: &Path,
    patched: &[String],
    resync_one: fn(&Path) -> Result<Vec<SidecarFile>, SidecarError>,
) -> Result<Option<SidecarPayload>, SidecarError> {
    let mut targets: Vec<(PathBuf, &Path)> = Vec::new();
    for key in patched {
        let rel = normalize_file_path(key);
        // SECURITY: the sidecar paths are derived from the key and then
        // deleted / rewritten; an escaping key would aim them outside the
        // package directory.
        if !is_safe_relative_subpath(rel) {
            return Err(SidecarError::Io {
                path: key.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Unsafe patch path (escapes package directory): {key}"),
                ),
            });
        }
        let rel = Path::new(rel);
        targets.push((pkg_path.join(rel), rel.parent().unwrap_or(Path::new(""))));
    }
    let mut files = Vec::new();
    for (file, rel_dir) in targets {
        for mut touched in resync_one(&file)? {
            let joined = rel_dir.join(&touched.path);
            touched.path = joined.to_string_lossy().replace('\\', "/");
            files.push(touched);
        }
    }
    Ok((!files.is_empty()).then_some(SidecarPayload {
        files,
        advisory: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const JAR: &str = "a-1.jar";

    fn hexd(algo: &str, bytes: &[u8]) -> String {
        hex::encode(digest(algo, bytes))
    }

    /// A Coursier-shaped version dir: `a-1.jar` holding `old`, with every
    /// sidecar Coursier writes for it (stale relative to `new` bytes).
    fn coursier_dir(old: &[u8], algos: &[&str]) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(JAR), old).unwrap();
        for algo in algos {
            let raw = match *algo {
                "md5" => vec![0u8; 16],
                a => digest(a, old),
            };
            std::fs::write(d.path().join(format!(".{JAR}__{algo}")), hex::encode(&raw)).unwrap();
            std::fs::write(d.path().join(format!(".{JAR}__{algo}.computed")), &raw).unwrap();
        }
        std::fs::write(d.path().join(format!(".{JAR}.checked")), b"").unwrap();
        d
    }

    /// What Coursier would do with `algo`'s sidecars of `bytes`.
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    enum State {
        /// No checksum file: validation skipped, the bytes kept (V5).
        Absent,
        /// The checksum matches the bytes and the cached digest, or there
        /// is no cached digest yet (V3 / V2): kept.
        Consistent,
        /// The pre-resync state: checksum and cached digest agree with
        /// each other but not with the bytes (T1): kept only while the
        /// stale digest survives.
        StalePair,
        /// A stale checksum without its digest (T5) or a checksum the
        /// cached digest contradicts (V1): the bytes get re-downloaded.
        Reverts,
    }

    fn state(dir: &Path, algo: &str, bytes: &[u8]) -> State {
        let sum = std::fs::read_to_string(dir.join(format!(".{JAR}__{algo}"))).ok();
        let computed = std::fs::read(dir.join(format!(".{JAR}__{algo}.computed"))).ok();
        let Some(sum) = sum else {
            return State::Absent;
        };
        // md5 is never rewritten, so never matches the new bytes.
        let actual = if algo == "md5" {
            String::new()
        } else {
            hexd(algo, bytes)
        };
        match computed {
            None if sum == actual => State::Consistent,
            None => State::Reverts,
            Some(c) if hex::encode(&c) != sum => State::Reverts,
            Some(_) if sum == actual => State::Consistent,
            Some(_) => State::StalePair,
        }
    }

    #[test]
    fn resync_rewrites_sha_sidecars_and_deletes_md5() {
        let d = coursier_dir(b"old", &["sha1", "md5", "sha256"]);
        std::fs::write(d.path().join(JAR), b"new").unwrap();
        let touched = resync(&d.path().join(JAR)).unwrap();
        let rel = |s: &str| format!(".{JAR}{s}");
        assert_eq!(
            touched,
            vec![
                SidecarFile {
                    path: rel("__sha1"),
                    action: SidecarFileAction::Rewritten
                },
                SidecarFile {
                    path: rel("__sha1.computed"),
                    action: SidecarFileAction::Rewritten
                },
                SidecarFile {
                    path: rel("__sha256"),
                    action: SidecarFileAction::Rewritten
                },
                SidecarFile {
                    path: rel("__sha256.computed"),
                    action: SidecarFileAction::Rewritten
                },
                SidecarFile {
                    path: rel("__md5"),
                    action: SidecarFileAction::Deleted
                },
                SidecarFile {
                    path: rel("__md5.computed"),
                    action: SidecarFileAction::Deleted
                },
            ]
        );
        let p = d.path();
        assert_eq!(
            std::fs::read_to_string(p.join(rel("__sha1"))).unwrap(),
            hexd("sha1", b"new")
        );
        assert_eq!(
            std::fs::read(p.join(rel("__sha1.computed"))).unwrap(),
            digest("sha1", b"new")
        );
        assert_eq!(
            std::fs::read_to_string(p.join(rel("__sha256"))).unwrap(),
            hexd("sha256", b"new")
        );
        assert!(!p.join(rel("__md5")).exists() && !p.join(rel("__md5.computed")).exists());
        assert!(!p.join(rel("__sha512")).exists(), "never created");
        assert!(p.join(rel(".checked")).exists(), ".checked left alone");
        for algo in ["sha1", "sha256", "sha512", "md5"] {
            assert_ne!(state(p, algo, b"new"), State::Reverts, "{algo}");
        }
    }

    #[test]
    fn sha512_and_an_orphan_computed_are_handled() {
        let d = coursier_dir(b"old", &["sha512"]);
        // A lone `.computed` (an interrupted resync's leftover) gets a
        // fresh, matching pair.
        std::fs::write(d.path().join(format!(".{JAR}__sha1.computed")), b"junk").unwrap();
        std::fs::write(d.path().join(JAR), b"new").unwrap();
        resync(&d.path().join(JAR)).unwrap();
        assert_eq!(state(d.path(), "sha512", b"new"), State::Consistent);
        assert_eq!(state(d.path(), "sha1", b"new"), State::Consistent);
        assert_eq!(
            state(d.path(), "sha256", b"new"),
            State::Absent,
            "never created"
        );
    }

    #[test]
    fn no_coursier_sidecar_means_no_record() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(JAR), b"jar").unwrap();
        // Maven's `~/.m2` sidecars are not Coursier's and stay untouched.
        std::fs::write(d.path().join(format!("{JAR}.sha1")), b"stale").unwrap();
        std::fs::write(d.path().join(format!(".{JAR}.checked")), b"").unwrap();
        assert!(resync(&d.path().join(JAR)).unwrap().is_empty());
        assert!(fixup(d.path(), &[JAR.to_string()]).unwrap().is_none());
        assert_eq!(
            std::fs::read(d.path().join(format!("{JAR}.sha1"))).unwrap(),
            b"stale"
        );
    }

    #[test]
    fn resync_is_idempotent() {
        let d = coursier_dir(b"old", &["sha1", "md5"]);
        std::fs::write(d.path().join(JAR), b"new").unwrap();
        resync(&d.path().join(JAR)).unwrap();
        let snapshot = |p: &Path| {
            let mut v: Vec<(String, Vec<u8>)> = std::fs::read_dir(p)
                .unwrap()
                .map(|e| {
                    let e = e.unwrap();
                    (
                        e.file_name().to_string_lossy().into_owned(),
                        std::fs::read(e.path()).unwrap(),
                    )
                })
                .collect();
            v.sort();
            v
        };
        let first = snapshot(d.path());
        // The re-run finds everything in sync and touches nothing.
        assert!(resync(&d.path().join(JAR)).unwrap().is_empty());
        assert_eq!(snapshot(d.path()), first);
        // A sidecar knocked out of sync again is repaired.
        std::fs::remove_file(d.path().join(format!(".{JAR}__sha1.computed"))).unwrap();
        assert_eq!(resync(&d.path().join(JAR)).unwrap().len(), 2);
        assert_eq!(snapshot(d.path()), first);
    }

    #[test]
    fn rollback_resync_matches_the_restored_bytes() {
        let d = coursier_dir(b"old", &["sha1", "md5"]);
        std::fs::write(d.path().join(JAR), b"new").unwrap();
        resync(&d.path().join(JAR)).unwrap();
        std::fs::write(d.path().join(JAR), b"old").unwrap();
        resync(&d.path().join(JAR)).unwrap();
        assert_eq!(
            std::fs::read_to_string(d.path().join(format!(".{JAR}__sha1"))).unwrap(),
            hexd("sha1", b"old")
        );
        assert_eq!(state(d.path(), "sha1", b"old"), State::Consistent);
    }

    #[test]
    fn missing_file_gets_its_sidecars_deleted() {
        let d = coursier_dir(b"old", &["sha1"]);
        std::fs::remove_file(d.path().join(JAR)).unwrap();
        let touched = resync(&d.path().join(JAR)).unwrap();
        assert!(touched
            .iter()
            .all(|f| f.action == SidecarFileAction::Deleted));
        assert_eq!(touched.len(), 2);
        assert_eq!(state(d.path(), "sha1", b""), State::Absent);
    }

    /// Fault injection: abort before each mutation in turn. Whatever step
    /// failed, no algorithm is left in a state that makes Coursier revert
    /// the bytes; before the first step the pre-resync pair is untouched;
    /// and a clean re-run always converges.
    #[test]
    fn every_interrupted_resync_leaves_coursier_accepting_the_bytes() {
        let algos = ["sha1", "sha256", "sha512", "md5"];
        let total = {
            let d = coursier_dir(b"old", &algos);
            std::fs::write(d.path().join(JAR), b"new").unwrap();
            let mut count = 0;
            resync_with(&d.path().join(JAR), false, &mut |_| {
                count += 1;
                Ok(())
            })
            .unwrap();
            count
        };
        // 4 algos × 2 deletions + 3 algos × 2 writes.
        assert_eq!(total, 14);
        for fail_at in 0..total {
            let d = coursier_dir(b"old", &algos);
            std::fs::write(d.path().join(JAR), b"new").unwrap();
            let mut step = 0;
            let err = resync_with(&d.path().join(JAR), false, &mut |_| {
                step += 1;
                if step > fail_at {
                    Err(std::io::Error::other("injected"))
                } else {
                    Ok(())
                }
            });
            assert!(err.is_err(), "step {fail_at}");
            for algo in algos {
                // A stale pair (the pre-resync state of an algorithm not
                // reached yet) is allowed; a reverting state never is.
                let s = state(d.path(), algo, b"new");
                assert_ne!(s, State::Reverts, "{algo} after step {fail_at}");
            }
            // sha1 (the one Coursier verifies) goes first: once anything was
            // touched it is absent until its fresh pair is written (steps 8
            // and 9), and consistent from then on.
            let sha1 = state(d.path(), "sha1", b"new");
            match fail_at {
                0 => assert_eq!(sha1, State::StalePair),
                1..=9 => assert_eq!(sha1, State::Absent, "step {fail_at}"),
                _ => assert_eq!(sha1, State::Consistent, "step {fail_at}"),
            }
            // No stage file is left behind.
            assert!(std::fs::read_dir(d.path()).unwrap().all(|e| !e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".socket-stage")));
            // The retry (the stale-only one an apply or rollback that wrote
            // nothing runs) converges: every algorithm consistent, or (when
            // the failure fell between deleting both files and writing the
            // digest) without a checksum file, the probed state that keeps
            // the bytes.
            resync_if_stale(&d.path().join(JAR)).unwrap();
            for algo in ["sha1", "sha256", "sha512"] {
                let s = state(d.path(), algo, b"new");
                assert!(
                    matches!(s, State::Consistent | State::Absent),
                    "{algo}: {s:?}"
                );
            }
            assert_eq!(state(d.path(), "md5", b"new"), State::Absent);
        }
    }

    /// A copy Coursier itself left consistent (a pristine jar a rollback
    /// finds already original, with its md5 and a downloaded-format
    /// checksum) is not a retry: nothing is touched and no record is made.
    /// A real interruption beside it still is.
    #[test]
    fn retry_leaves_a_consistent_pristine_copy_alone() {
        let d = coursier_dir(b"old", &["sha1", "md5"]);
        let sum = d.path().join(format!(".{JAR}__sha1"));
        let downloaded = format!("{}  {JAR}\n", hexd("sha1", b"old").to_uppercase());
        std::fs::write(&sum, &downloaded).unwrap();
        let keys = [JAR.to_string()];
        assert!(retry_record("pkg:maven/g/a@1", d.path(), &keys, "x").is_none());
        assert_eq!(std::fs::read_to_string(&sum).unwrap(), downloaded);
        assert!(d.path().join(format!(".{JAR}__md5")).exists());
        // The delete pass stopped at md5 (sha1 already gone): retried.
        std::fs::remove_file(&sum).unwrap();
        std::fs::remove_file(d.path().join(format!(".{JAR}__sha1.computed"))).unwrap();
        let record = retry_record("pkg:maven/g/a@1", d.path(), &keys, "x").expect("resynced");
        assert!(record
            .files
            .iter()
            .any(|f| f.path == format!(".{JAR}__md5")));
        assert!(!d.path().join(format!(".{JAR}__md5")).exists());
        // The full resync (an apply that wrote the bytes) still normalizes
        // a pristine copy's md5 away.
        let d = coursier_dir(b"old", &["sha1", "md5"]);
        assert!(!resync(&d.path().join(JAR)).unwrap().is_empty());
        assert!(!d.path().join(format!(".{JAR}__md5")).exists());
    }

    #[test]
    fn fixup_paths_are_package_relative_and_escapes_refused() {
        let d = tempfile::tempdir().unwrap();
        let sub = d.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join(JAR), b"new").unwrap();
        std::fs::write(sub.join(format!(".{JAR}__sha1")), b"stale").unwrap();
        let payload = fixup(d.path(), &[format!("package/sub/{JAR}")])
            .unwrap()
            .expect("a record");
        assert_eq!(payload.files[0].path, format!("sub/.{JAR}__sha1"));
        assert!(payload.advisory.is_none());
        for key in ["../x.jar", "/etc/passwd", "package/../../x.jar"] {
            assert!(fixup(d.path(), &[key.to_string()]).is_err(), "{key}");
        }
    }

    #[test]
    fn retry_record_is_maven_only_and_reports_failures() {
        let d = coursier_dir(b"old", &["sha1"]);
        std::fs::write(d.path().join(JAR), b"new").unwrap();
        let keys = [JAR.to_string()];
        assert!(retry_record("pkg:npm/x@1", d.path(), &keys, "x").is_none());
        let record = retry_record("pkg:maven/g/a@1", d.path(), &keys, "x").expect("resynced");
        assert_eq!(
            (record.purl.as_str(), record.ecosystem.as_str()),
            ("pkg:maven/g/a@1", "maven")
        );
        assert_eq!(record.files.len(), 2);
        assert!(
            retry_record("pkg:maven/g/a@1", d.path(), &keys, "x").is_none(),
            "in sync"
        );
        let failed = retry_record(
            "pkg:maven/g/a@1",
            d.path(),
            &["../x".into()],
            "resync failed",
        )
        .expect("a failure record");
        let advisory = failed.advisory.expect("advisory");
        assert_eq!(
            advisory.code,
            super::super::SidecarAdvisoryCode::SidecarFixupFailed
        );
        assert!(advisory.message.starts_with("resync failed: "));
    }

    #[cfg(unix)]
    #[test]
    fn fifo_target_errors_promptly() {
        let d = coursier_dir(b"old", &["sha1"]);
        let jar = d.path().join(JAR);
        std::fs::remove_file(&jar).unwrap();
        let c = std::ffi::CString::new(jar.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(resync(&jar).is_err());
        });
        assert!(rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("a FIFO must not wedge the resync"));
        // Nothing was deleted before the read failed.
        assert!(d.path().join(format!(".{JAR}__sha1")).exists());
    }
}
