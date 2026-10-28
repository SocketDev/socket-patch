//! npm's install-time rewrite of a `bin` file's Windows shebang.
//!
//! On Linux and macOS, npm's `bin-links` runs `fixBin` on every file a
//! package lists in `bin` (`lib/fix-bin.js`): when the first 2048 bytes
//! match `^#![^\n]+\r\n`, it rewrites the file with that first `\r\n`
//! turned into `\n` (`dos2Unix`). pnpm links bins through the same
//! module. So an untouched install of a bin published from Windows
//! differs from the tarball, and from a patch's `beforeHash` /
//! `afterHash`, by exactly one byte (#1756).
//!
//! The hash checks accept that form of the recorded content, and the
//! writers keep it, so the shebang stays one `env` can run.

use std::path::Path;

use crate::hash::git_sha256::compute_git_sha256_from_bytes;

/// The bytes `fixBin` inspects.
const PROBE_LEN: usize = 2048;

/// What `fixBin` leaves on disk for `bytes`, or `None` when it leaves the
/// file alone (no `#!…\r\n` first line within its 2048-byte probe).
///
/// Also `None` for bytes that are not valid UTF-8: `dos2Unix` reads and
/// writes the file as UTF-8, so npm would replace them with U+FFFD, and
/// that form can't be traced back to the recorded hash. Such a file is
/// written as recorded.
pub(crate) fn fix_bin(bytes: &[u8]) -> Option<Vec<u8>> {
    let cr = first_newline(bytes)?.checked_sub(1)?;
    // `[^\n]+` needs one byte between `#!` and the `\r\n`.
    if cr < 3 || bytes[cr] != b'\r' || std::str::from_utf8(bytes).is_err() {
        return None;
    }
    let mut out = bytes.to_vec();
    out.remove(cr);
    Some(out)
}

/// The bytes to write for `content` (verified to hash to `expected_hash`
/// first, as `apply_file_patch_at` would) in `fixBin`'s form, and their
/// hash. `Ok(None)` when [`fix_bin`] leaves `content` alone.
pub(crate) fn fixed_for_write(
    content: &[u8],
    expected_hash: &str,
) -> Result<Option<(Vec<u8>, String)>, std::io::Error> {
    let Some(fixed) = fix_bin(content) else {
        return Ok(None);
    };
    let content_hash = compute_git_sha256_from_bytes(content);
    if content_hash != expected_hash {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Hash verification failed before patch. Expected: {expected_hash}, Got: {content_hash}"
            ),
        ));
    }
    let hash = compute_git_sha256_from_bytes(&fixed);
    Ok(Some((fixed, hash)))
}

/// The content `fixBin` turned into `bytes`, or `None` when `bytes` is not
/// something `fixBin` writes (a `#!` first line of at least one byte,
/// ending in `\n` early enough that its `\r\n` original fit the probe).
pub(crate) fn unfix_bin(bytes: &[u8]) -> Option<Vec<u8>> {
    let lf = first_newline(bytes)?;
    if lf < 3 || lf + 1 >= PROBE_LEN {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() + 1);
    out.extend_from_slice(&bytes[..lf]);
    out.push(b'\r');
    out.extend_from_slice(&bytes[lf..]);
    Some(out)
}

/// Whether `bytes` starts with a `#!` line that ends in a bare `\n`: the
/// shebang shape npm installs a bin with.
pub(crate) fn has_lf_shebang(bytes: &[u8]) -> bool {
    matches!(first_newline(bytes), Some(lf) if lf >= 3 && bytes[lf - 1] != b'\r')
}

/// The hash of the content npm installed as the file at `path`, when the
/// file is in `fixBin`'s form ([`unfix_bin`]). `None` when it is not, or
/// it can't be read. Only a file whose first bytes qualify is read whole,
/// so a mismatched jar or wheel is not read twice.
pub(crate) async fn source_hash(path: &Path) -> Option<String> {
    let path = path.to_path_buf();
    crate::utils::fs::run_blocking(move || source_hash_sync(&path)).await
}

/// Blocking twin of [`source_hash`].
pub(crate) fn source_hash_sync(path: &Path) -> Option<String> {
    use std::io::Read as _;
    let (file, _) = crate::utils::fs::open_regular_file_sync(path).ok()?;
    let mut prefix = Vec::with_capacity(PROBE_LEN);
    file.take(PROBE_LEN as u64).read_to_end(&mut prefix).ok()?;
    unfix_bin(&prefix)?;
    let bytes = crate::utils::fs::read_regular_to_bytes_sync(path).ok()?;
    source_hash_of(&bytes)
}

/// [`source_hash`] of bytes already read.
pub(crate) fn source_hash_of(bytes: &[u8]) -> Option<String> {
    unfix_bin(bytes).map(|src| compute_git_sha256_from_bytes(&src))
}

/// The index of the first `\n` of a file that starts with `#!`, within
/// the probe.
fn first_newline(bytes: &[u8]) -> Option<usize> {
    if !bytes.starts_with(b"#!") {
        return None;
    }
    let probe = &bytes[..bytes.len().min(PROBE_LEN)];
    probe.iter().position(|&b| b == b'\n')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fix_bin_drops_only_the_first_lines_cr() {
        assert_eq!(
            fix_bin(b"#!/usr/bin/env node\r\na();\r\n").as_deref(),
            Some(&b"#!/usr/bin/env node\na();\r\n"[..])
        );
        // The greedy `[^\n]+` keeps an earlier `\r`.
        assert_eq!(fix_bin(b"#!x\r\r\n").as_deref(), Some(&b"#!x\r\n"[..]));
    }

    #[test]
    fn fix_bin_leaves_what_bin_links_leaves() {
        for bytes in [
            &b"#!/usr/bin/env node\na();\r\n"[..],
            b"#!\r\n",
            b"// #!x\r\n",
            b"#!/usr/bin/env node",
            b"",
        ] {
            assert_eq!(fix_bin(bytes), None, "{bytes:?}");
        }
        // The `\r\n` must fall within the 2048-byte probe.
        let mut long = b"#!".to_vec();
        long.extend(vec![b'x'; 2044]);
        long.extend_from_slice(b"\r\n");
        assert_eq!(long.len(), 2048);
        assert!(fix_bin(&long).is_some());
        long.insert(2, b'x');
        assert_eq!(fix_bin(&long), None);
    }

    #[test]
    fn fix_bin_keeps_bytes_npm_would_mangle() {
        // npm would write U+FFFD for the 0xff, which nothing can trace
        // back to the recorded hash.
        assert_eq!(fix_bin(b"#!node\r\n\xff\n"), None);
    }

    #[test]
    fn fixed_for_write_checks_the_content_first() {
        let content = b"#!/usr/bin/env node\r\nx\r\n";
        let hash = compute_git_sha256_from_bytes(content);
        let (fixed, fixed_hash) = fixed_for_write(content, &hash).unwrap().unwrap();
        assert_eq!(fixed, b"#!/usr/bin/env node\nx\r\n");
        assert_eq!(fixed_hash, compute_git_sha256_from_bytes(&fixed));
        let err = fixed_for_write(content, &"0".repeat(64)).unwrap_err();
        assert!(
            err.to_string().contains("Hash verification failed"),
            "{err}"
        );
        assert!(fixed_for_write(b"x\r\n", &"0".repeat(64))
            .unwrap()
            .is_none());
    }

    #[test]
    fn unfix_bin_inverts_fix_bin() {
        for src in [
            &b"#!/usr/bin/env node\r\na();\r\n"[..],
            b"#!x\r\n",
            b"#!x\r\r\n",
        ] {
            let fixed = fix_bin(src).unwrap();
            assert_eq!(unfix_bin(&fixed).as_deref(), Some(src), "{src:?}");
        }
        for bytes in [&b"#!\n"[..], b"a\n", b"#!x"] {
            assert_eq!(unfix_bin(bytes), None, "{bytes:?}");
        }
        // Its original's `\r\n` would not have fit the probe.
        let mut long = b"#!".to_vec();
        long.extend(vec![b'x'; 2045]);
        long.push(b'\n');
        assert_eq!(unfix_bin(&long), None);
    }

    #[test]
    fn has_lf_shebang_wants_a_bare_lf() {
        assert!(has_lf_shebang(b"#!/bin/sh\necho\n"));
        assert!(!has_lf_shebang(b"#!/bin/sh\r\necho\n"));
        assert!(!has_lf_shebang(b"#!\n"));
        assert!(!has_lf_shebang(b"echo\n"));
    }

    #[tokio::test]
    async fn source_hash_is_the_tarball_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cli.js");
        tokio::fs::write(&path, b"#!/usr/bin/env node\nx\r\n")
            .await
            .unwrap();
        assert_eq!(
            source_hash(&path).await,
            Some(compute_git_sha256_from_bytes(
                b"#!/usr/bin/env node\r\nx\r\n"
            ))
        );
        tokio::fs::write(&path, b"x\n").await.unwrap();
        assert_eq!(source_hash(&path).await, None);
        assert_eq!(source_hash(&dir.path().join("missing")).await, None);
    }
}
