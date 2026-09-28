//! The patched-package version of the NuGet fallback layout
//! ([`super::nuget_fallback`]).
//!
//! A vendored NuGet package keeps its id and gets a version of its own,
//! `V′ = A.B.C.N`, so the patched bytes never share an identity with the
//! upstream `A.B.C` in any package cache. `N` is derived from the patch uuid:
//! `2^30 + (u32(uuid[0..8]) >> 2)`, which always lies in `[2^30, 2^31 − 1]`
//! (a valid int32 NuGet version part, far above any real revision number).
//! Only a stable upstream with at most three significant parts (a zero or
//! absent 4th part) is suffixable; everything else is refused by the caller.

use super::nuget_feed::normalize_nuget_version;

/// The smallest revision a Socket version carries (`2^30`).
const SOCKET_REVISION_MIN: u32 = 1 << 30;

/// The largest revision a Socket version carries (`i32::MAX`).
const SOCKET_REVISION_MAX: u32 = i32::MAX as u32;

/// The revision part NuGet parses as an int32: plain ASCII digits that fit.
fn version_part(part: &str) -> Option<u32> {
    if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    part.parse::<u32>()
        .ok()
        .filter(|n| *n <= SOCKET_REVISION_MAX)
}

/// `V′` for the normalized upstream `version_norm` and patch `uuid`, or
/// `None` when the upstream has no free 4th part (a prerelease, build
/// metadata, a non-zero revision) or the uuid is not canonical.
pub(crate) fn socket_nuget_version(version_norm: &str, uuid: &str) -> Option<String> {
    if !crate::patch::path_safety::is_canonical_uuid(uuid) {
        return None;
    }
    if normalize_nuget_version(version_norm) != version_norm {
        return None;
    }
    let parts: Vec<&str> = version_norm.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| version_part(p).is_none()) {
        return None;
    }
    let prefix = u32::from_str_radix(uuid.get(0..8)?, 16).ok()?;
    let revision = SOCKET_REVISION_MIN + (prefix >> 2);
    Some(format!("{version_norm}.{revision}"))
}

/// Split a Socket version back into `(normalized upstream, revision)`, or
/// `None` when `version` is not one (any 4-part version whose revision lies
/// in the Socket range decodes, whichever uuid produced it).
pub(crate) fn parse_socket_nuget_version(version: &str) -> Option<(String, u32)> {
    let norm = normalize_nuget_version(version);
    let parts: Vec<&str> = norm.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let numbers: Vec<u32> = parts
        .iter()
        .map(|p| version_part(p))
        .collect::<Option<_>>()?;
    let revision = numbers[3];
    if revision < SOCKET_REVISION_MIN {
        return None;
    }
    Some((parts[..3].join("."), revision))
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "3f9a01bc-1111-4222-8333-444455556666";

    #[test]
    fn derivation_vectors() {
        assert_eq!(
            socket_nuget_version("13.0.1", UUID).as_deref(),
            Some("13.0.1.1340506223")
        );
        for (uuid, want) in [
            ("00000000-0000-4000-8000-000000000000", "1.2.3.1073741824"),
            ("ffffffff-0000-4000-8000-000000000000", "1.2.3.2147483647"),
            ("00000003-0000-4000-8000-000000000000", "1.2.3.1073741824"),
            ("00000004-0000-4000-8000-000000000000", "1.2.3.1073741825"),
        ] {
            assert_eq!(socket_nuget_version("1.2.3", uuid).as_deref(), Some(want));
        }
    }

    #[test]
    fn unsuffixable_versions_are_refused() {
        for v in [
            "13.0.1-beta.1",
            "13.0.1.5",
            "13.0",
            "013.0.1",
            "13.0.1+build",
            "",
            "a.b.c",
            "3000000000.0.1",
        ] {
            assert_eq!(socket_nuget_version(v, UUID), None, "{v}");
        }
        assert_eq!(socket_nuget_version("13.0.1", "not-a-uuid"), None);
        assert_eq!(socket_nuget_version("13.0.1", &UUID.to_uppercase()), None);
    }

    #[test]
    fn parse_round_trips_and_rejects() {
        let v = socket_nuget_version("13.0.1", UUID).unwrap();
        assert_eq!(
            parse_socket_nuget_version(&v),
            Some(("13.0.1".to_string(), 1_340_506_223))
        );
        assert_eq!(
            parse_socket_nuget_version("13.0.01.1340506223"),
            Some(("13.0.1".to_string(), 1_340_506_223))
        );
        for v in [
            "13.0.1",
            "13.0.1.0",
            "13.0.1.1073741823",
            "13.0.1.2147483648",
            "13.0.1.1340506223-rc",
            "13.0.1.x",
        ] {
            assert_eq!(parse_socket_nuget_version(v), None, "{v}");
        }
    }
}
