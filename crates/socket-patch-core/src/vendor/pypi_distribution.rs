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
