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

/// A `name` + `version` pair that each key one path segment: the cargo
/// `<name>-<version>` registry dir, the gem `<name>-<version>` dir, the
/// NuGet `<id>/<version>` and legacy `<Id>.<Version>` dirs, and the purls
/// built from them. Every crawler that resolves a manifest purl to a
/// directory it then patches in place checks both halves here, fail closed.
pub(crate) fn is_safe_name_version(name: &str, version: &str) -> bool {
    is_safe_single_segment(name) && is_safe_single_segment(version)
}

/// A multi-segment relative path (Go module path `github.com/foo/bar`, npm
/// scoped name `@scope/name`, composer `vendor/name`): every `/`-separated
/// segment must be safe on its own, which also rejects the empty string, a
/// leading/trailing `/`, and `//` (each yields an empty segment).
pub(crate) fn is_safe_multi_segment(s: &str) -> bool {
    s.split('/').all(is_safe_single_segment)
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

    /// The cargo, gem and NuGet coordinates the crawlers' former
    /// `is_safe_{cargo,gem,nuget}_coordinate` copies were pinned on.
    const SAFE_NAME_VERSIONS: &[(&str, &str)] = &[
        ("serde", "1.0.200"),
        ("serde_json", "1.0.120"),
        ("sha-1", "0.10.0"),
        ("crate", "1.0.0-rc.1"),
        ("wasi", "0.11.0+wasi-snapshot-preview1"),
        ("rails", "7.1.0"),
        ("aws-sdk-s3", "1.143.0"),
        ("ruby2_keywords", "0.0.5"),
        ("nokogiri", "1.16.5.pre.rc1"),
        ("Newtonsoft.Json", "13.0.3"),
        ("Contoso.Widgets", "2.0.0-RC1"),
        ("xunit", "2.6.2+build.5"),
    ];

    /// Traversal, separator, NUL, empty and drive-relative (`C:`) halves:
    /// the union of the three crawler test copies.
    const UNSAFE_NAME_VERSIONS: &[(&str, &str)] = &[
        ("", "1.0.0"),
        ("a", ""),
        ("..", "1.0.0"),
        (".", "1.0.0"),
        ("a", ".."),
        ("a", "."),
        ("../escaped", "1.0.0"),
        ("/abs/evil", "1.0.0"),
        ("a/b", "1.0.0"),
        ("a", "1/0"),
        ("a", "../../escaped/1.0.0"),
        ("rails", "1.0/../../x"),
        ("a\\b", "1.0.0"),
        ("a\0b", "1.0.0"),
        ("C:evil", "1.0.0"),
        ("a", "C:1.0.0"),
    ];

    #[test]
    fn name_version_accepts_real_coordinates_and_fails_closed() {
        for &(name, version) in SAFE_NAME_VERSIONS {
            assert!(is_safe_name_version(name, version), "{name:?} {version:?}");
        }
        for &(name, version) in UNSAFE_NAME_VERSIONS {
            assert!(!is_safe_name_version(name, version), "{name:?} {version:?}");
        }
    }

    /// The purl builders that inlined the same check now share it: each
    /// builds exactly the pairs the guard accepts.
    #[test]
    fn purl_builders_agree_with_the_name_version_guard() {
        use crate::utils::purl::{pypi_purl, simple_purl};
        for &(name, version) in SAFE_NAME_VERSIONS.iter().chain(UNSAFE_NAME_VERSIONS) {
            let safe = is_safe_name_version(name, version);
            for ty in ["cargo", "gem", "nuget"] {
                assert_eq!(
                    simple_purl(ty, name, version).is_some(),
                    safe,
                    "{ty} {name:?} {version:?}"
                );
            }
            // PyPI canonicalizes the name first; `.`/`..` and `_` names
            // change shape, so only compare the names it keeps verbatim.
            let canonical = crate::crawlers::python_crawler::canonicalize_pypi_name(name);
            if canonical == name {
                assert_eq!(
                    pypi_purl(name, version).is_some(),
                    safe,
                    "pypi {name:?} {version:?}"
                );
            }
        }
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
