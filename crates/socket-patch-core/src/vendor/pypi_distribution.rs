use std::collections::HashMap;

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::manifest::schema::PatchRecord;
use crate::patch::apply::normalize_file_path;

pub(crate) fn supported(name: &str) -> bool {
    [".whl", ".tar.gz", ".tgz", ".zip"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'!' | b'-'))
}

pub(crate) fn matches(name: &str, package: &str, version: &str) -> bool {
    if !supported(name) {
        return false;
    }
    if let Some(stem) = name.strip_suffix(".whl") {
        let parts: Vec<_> = stem.split('-').collect();
        return (parts.len() == 5 || parts.len() == 6)
            && parts.iter().all(|p| !p.is_empty())
            && canonicalize_pypi_name(parts[0]) == canonicalize_pypi_name(package)
            && parts[1].eq_ignore_ascii_case(&super::pypi_wheel::escape_wheel_version(version));
    }
    [".tar.gz", ".tgz", ".zip"]
        .iter()
        .filter_map(|suffix| name.strip_suffix(suffix))
        .any(|stem| {
            stem.rsplit_once('-').is_some_and(|(n, v)| {
                canonicalize_pypi_name(n) == canonicalize_pypi_name(package)
                    && v.eq_ignore_ascii_case(version)
            })
        })
}

pub(crate) fn read_members(bytes: &[u8], name: &str) -> Result<HashMap<String, Vec<u8>>, String> {
    let members = if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        crate::patch::package::read_sdist_tar_bytes_to_map_strict(bytes)
            .map_err(|e| e.to_string())?
    } else {
        super::verify::read_zip_bytes_to_map_strict(bytes)?
    };
    if name.ends_with(".whl") {
        return Ok(members);
    }
    strip_sdist_root(members)
}

fn strip_sdist_root(members: HashMap<String, Vec<u8>>) -> Result<HashMap<String, Vec<u8>>, String> {
    let root = members
        .keys()
        .next()
        .and_then(|name| name.split_once('/'))
        .map(|(root, _)| format!("{root}/"));
    if let Some(root) = root.filter(|root| members.keys().all(|name| name.starts_with(root))) {
        Ok(members
            .into_iter()
            .map(|(name, bytes)| (name[root.len()..].to_string(), bytes))
            .collect())
    } else {
        Ok(members)
    }
}

pub(crate) fn verify_members(
    members: &HashMap<String, Vec<u8>>,
    name: &str,
    record: &PatchRecord,
) -> Result<(), String> {
    if name.ends_with(".whl") {
        return super::verify::verify_member_map(members, record);
    }
    for (path, info) in &record.files {
        let key = normalize_file_path(path);
        let prefixed = format!("src/{key}");
        let candidates: Vec<_> = [members.get(key), members.get(&prefixed)]
            .into_iter()
            .flatten()
            .collect();
        if candidates.len() != 1 {
            return Err("vendor_sdist_layout_ambiguous".into());
        }
        if !crate::hash::git_sha256::compute_git_sha256_from_bytes(candidates[0])
            .eq_ignore_ascii_case(&info.after_hash)
        {
            return Err("vendor_hash_mismatch".into());
        }
    }
    Ok(())
}

/// Whether a wheel filename binds an interpreter, ABI or platform, and its
/// tag triple for messages. Shared by vendored mode
/// (`vendor_platform_locked`) and the hosted redirect
/// (`redirect_pypi_platform_wheel`), so both modes call the same wheels
/// portable.
pub(crate) fn wheel_platform_from_filename(wheel_name: &str) -> (bool, String) {
    let stem = wheel_name.strip_suffix(".whl").unwrap_or(wheel_name);
    let parts: Vec<&str> = stem.split('-').collect();
    if parts.len() >= 3 {
        let triple = parts[parts.len() - 3..].join("-");
        (tag_is_platform_specific(&triple), triple)
    } else {
        // Unparseable → cannot prove portability.
        (true, stem.to_string())
    }
}

/// Whether a lock artifact URL (or bare filename) names a wheel every
/// Python 3 interpreter on every platform installs: `?query` / `#fragment`
/// stripped, the last path segment a `.whl` that
/// [`wheel_platform_from_filename`] calls portable. Ledger recovery's pick
/// of a "pure" wheel, so it agrees with vendored and hosted mode.
pub(crate) fn is_portable_wheel_url(url: &str) -> bool {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let file = path.rsplit('/').next().unwrap_or(path);
    file.ends_with(".whl") && !wheel_platform_from_filename(file).0
}

/// Platform-specific unless every Python 3 interpreter on every platform
/// installs the wheel: the ABI must be `none`, the platform `any`, and the
/// python tag set must hold a generic Python 3 tag. pip accepts `py3` and
/// `pyXY` (major 3) on any later 3.x, but an interpreter tag (`cp311`,
/// `pp310`) only on that interpreter version, and `py2` never on Python 3
/// (#1048). `*-cp311-*` / `*-manylinux*` lock the artifact to this
/// machine's platform.
pub(crate) fn tag_is_platform_specific(tag: &str) -> bool {
    let parts: Vec<&str> = tag.split('-').collect();
    match parts.as_slice() {
        [py, abi, plat] => {
            *abi != "none" || *plat != "any" || !py.split('.').any(is_generic_py3_tag)
        }
        // Malformed tags can't prove portability — claim platform-locked.
        _ => true,
    }
}

/// `py3` or `py3<minor>`: a python tag every later Python 3 accepts.
fn is_generic_py3_tag(tag: &str) -> bool {
    tag.strip_prefix("py3")
        .is_some_and(|minor| minor.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::schema::PatchFileInfo;

    fn tar(entries: &[(&str, &[u8], tar::EntryType)]) -> Vec<u8> {
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (path, bytes, kind) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(bytes.len() as u64);
            header.set_entry_type(*kind);
            header.set_cksum();
            archive.append_data(&mut header, path, *bytes).unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn sdist_tar_preserves_package_layout_and_strips_distribution_root() {
        let bytes = tar(&[("six-1.16.0/src/six.py", b"patched", tar::EntryType::Regular)]);
        let members = read_members(&bytes, "six-1.16.0.tar.gz").unwrap();
        assert_eq!(members.get("src/six.py").unwrap(), b"patched");
        assert!(matches("six-1.16.0.tar.gz", "six", "1.16.0"));
        assert!(!matches("six-1.16.0.tar.gz", "six", "1.17.0"));
    }

    #[test]
    fn sdist_tar_rejects_aliases_links_and_oversized_members() {
        let aliases = tar(&[
            ("six-1/six.py", b"one", tar::EntryType::Regular),
            ("six-1/SIX.py", b"two", tar::EntryType::Regular),
        ]);
        assert!(read_members(&aliases, "six-1.tar.gz").is_err());
        let link = tar(&[("six-1/six.py", b"", tar::EntryType::Symlink)]);
        assert!(read_members(&link, "six-1.tar.gz").is_err());
        let bytes = vec![0; 16 * 1024 * 1024 + 1];
        let oversized = tar(&[("six-1/six.py", &bytes, tar::EntryType::Regular)]);
        assert!(read_members(&oversized, "six-1.tar.gz").is_err());
    }

    #[test]
    fn sdist_member_verification_rejects_ambiguous_src_layout() {
        let record: PatchRecord = serde_json::from_value(serde_json::json!({
            "uuid":"11111111-1111-1111-1111-111111111111", "exportedAt": "2026-01-01T00:00:00Z", "vulnerabilities": {}, "description": "test", "license": "MIT", "tier": "free",
            "files": { "six.py": { "beforeHash": "old", "afterHash": crate::hash::git_sha256::compute_git_sha256_from_bytes(b"patched") } }
        })).unwrap();
        let members = HashMap::from([("six.py".to_string(), b"patched".to_vec())]);
        assert!(verify_members(&members, "six-1.tar.gz", &record).is_ok());
        let mut ambiguous = members.clone();
        ambiguous.insert("src/six.py".into(), b"patched".to_vec());
        assert!(verify_members(&ambiguous, "six-1.tar.gz", &record).is_err());
        assert!(verify_members(
            &members,
            "six-1.tar.gz",
            &PatchRecord {
                files: HashMap::from([(
                    "six.py".into(),
                    PatchFileInfo {
                        after_hash: "wrong".into(),
                        ..record.files["six.py"].clone()
                    }
                )]),
                ..record
            }
        )
        .is_err());
    }
}
