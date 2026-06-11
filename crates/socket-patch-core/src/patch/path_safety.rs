//! Coordinate-safety guards for paths derived from untrusted manifest data.
//!
//! Package names, versions, Go module paths, and patch UUIDs from
//! `.socket/manifest.json` / `.socket/vendor/state.json` key on-disk copy
//! directories (`.socket/go-patches/…`, `.socket/vendor/…`) and the
//! lockfile/config entries that point at them. Those files are committed and
//! tamper-able, so every coordinate must be validated **fail-closed before any
//! disk access**: a `..`/`.` segment, an absolute path, a backslash, a colon,
//! or a NUL would otherwise let a poisoned manifest copy, write, or delete a
//! tree at an arbitrary filesystem location outside the project.
//!
//! Colons are rejected because a leading `C:` makes the coordinate an
//! absolute Windows path that `Path::join` substitutes wholesale for the
//! base; no legitimate package name, version, or Go module path contains one.

/// A single path segment (cargo crate name, version string, gem name, …):
/// no separators, not `.`/`..`, no backslash/colon/NUL, non-empty.
pub(crate) fn is_safe_single_segment(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && !s.contains('/')
        && !s.contains('\\')
        && !s.contains(':')
        && !s.contains('\0')
}

/// A multi-segment relative path (Go module path `github.com/foo/bar`, npm
/// scoped name `@scope/name`, composer `vendor/name`): `/`-separated segments,
/// each non-empty and not `.`/`..`; no leading `/`, no backslash, no colon,
/// no NUL.
pub(crate) fn is_safe_multi_segment(s: &str) -> bool {
    if s.is_empty() || s.starts_with('/') || s.contains('\\') || s.contains(':') || s.contains('\0')
    {
        return false;
    }
    s.split('/')
        .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// The canonical lowercase hyphenated UUID grammar
/// (`9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f`). Patch UUIDs key a dedicated
/// `.socket/vendor/<eco>/<uuid>/` path level, so anything that is not exactly
/// this shape (36 chars, hex + hyphens in the fixed positions) is rejected —
/// uppercase included, since the dir name must match the lockfile string
/// byte-for-byte on case-sensitive filesystems.
pub(crate) fn is_canonical_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if c != b'-' {
                    return false;
                }
            }
            _ => {
                if !c.is_ascii_hexdigit() || c.is_ascii_uppercase() {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_segment_accepts_names_and_versions() {
        assert!(is_safe_single_segment("serde"));
        assert!(is_safe_single_segment("left-pad"));
        assert!(is_safe_single_segment("1.0.200"));
        assert!(is_safe_single_segment("v2.0.0-20210101000000-abcdef123456"));
    }

    #[test]
    fn single_segment_rejects_traversal_and_separators() {
        assert!(!is_safe_single_segment(""));
        assert!(!is_safe_single_segment("."));
        assert!(!is_safe_single_segment(".."));
        assert!(!is_safe_single_segment("a/b"));
        assert!(!is_safe_single_segment("a\\b"));
        assert!(!is_safe_single_segment("a\0b"));
        // A leading `C:` is an absolute Windows path under `Path::join`.
        assert!(!is_safe_single_segment("C:evil"));
        assert!(!is_safe_single_segment("c:"));
    }

    #[test]
    fn multi_segment_accepts_module_and_scoped_names() {
        assert!(is_safe_multi_segment("github.com/foo/bar"));
        assert!(is_safe_multi_segment("github.com/foo/bar/v2"));
        assert!(is_safe_multi_segment("gopkg.in/inf.v0"));
        assert!(is_safe_multi_segment("@scope/name"));
        assert!(is_safe_multi_segment("monolog/monolog"));
    }

    #[test]
    fn multi_segment_rejects_traversal() {
        assert!(!is_safe_multi_segment(""));
        assert!(!is_safe_multi_segment("/abs/path"));
        assert!(!is_safe_multi_segment("../../../etc"));
        assert!(!is_safe_multi_segment("github.com/../../../etc"));
        assert!(!is_safe_multi_segment("github.com//bar"));
        assert!(!is_safe_multi_segment("foo/./bar"));
        assert!(!is_safe_multi_segment("foo\\bar"));
        assert!(!is_safe_multi_segment("foo\0bar"));
        // Windows drive-letter escapes: `C:/…` joins as an absolute path.
        assert!(!is_safe_multi_segment("C:/evil"));
        assert!(!is_safe_multi_segment("c:/evil"));
        assert!(!is_safe_multi_segment("C:"));
    }

    #[test]
    fn uuid_grammar_is_exact() {
        assert!(is_canonical_uuid("9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f"));
        // Wrong length / shape / case / traversal payloads.
        assert!(!is_canonical_uuid(""));
        assert!(!is_canonical_uuid("9f6b2c4e1d3a4f6b8c2d7e5a9b1c3d5f")); // no hyphens
        assert!(!is_canonical_uuid("9F6B2C4E-1D3A-4F6B-8C2D-7E5A9B1C3D5F")); // uppercase
        assert!(!is_canonical_uuid("9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5")); // 35 chars
        assert!(!is_canonical_uuid("9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5ff")); // 37 chars
        assert!(!is_canonical_uuid("../../../etc/passwd/aaaaaaaaaaaaaaaa"));
        assert!(!is_canonical_uuid("9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d/f"));
    }
}
