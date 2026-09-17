use toml_edit::{value, Array, DocumentMut, InlineTable, Item, Table, Value};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::python_lock::preserve_line_endings;

pub fn lock_version(lock: &DocumentMut) -> Result<&str, String> {
    let version = lock
        .get("metadata")
        .and_then(|metadata| metadata.get("lock_version"))
        .and_then(Item::as_str)
        .ok_or("missing PDM lock_version")?;
    if matches!(version, "2" | "4.3" | "4.4" | "4.4.1" | "4.5.0" | "4.5.1") {
        Ok(version)
    } else {
        Err(format!("unsupported PDM lock_version {version:?}"))
    }
}

pub fn validate_strategy(lock: &DocumentMut) -> Result<Vec<String>, String> {
    let mut result = Vec::new();
    if let Some(strategy) = lock
        .get("metadata")
        .and_then(|metadata| metadata.get("strategy"))
    {
        for item in strategy.as_array().ok_or("invalid PDM strategy")? {
            let value = item.as_str().ok_or("invalid PDM strategy flag")?;
            if !matches!(
                value,
                "inherit_metadata" | "static_urls" | "cross_platform" | "direct_minimal_versions"
            ) {
                return Err(format!("unsupported PDM lock strategy {value:?}"));
            }
            result.push(value.to_string());
        }
    }
    Ok(result)
}

pub fn legacy_files_key(package: &Table) -> Option<String> {
    let name = canonicalize_pypi_name(package.get("name")?.as_str()?);
    let version = package.get("version")?.as_str()?;
    let mut extras: Vec<&str> = package
        .get("extras")
        .and_then(Item::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    extras.sort();
    let suffix = if extras.is_empty() {
        String::new()
    } else {
        format!("[{}]", extras.join(","))
    };
    Some(format!("{name}{suffix} {version}"))
}

pub fn files_for<'a>(lock: &'a DocumentMut, package: &'a Table) -> Option<&'a Array> {
    package.get("files").and_then(Item::as_array).or_else(|| {
        lock.get("metadata")?
            .get("files")?
            .get(&legacy_files_key(package)?)?
            .as_array()
    })
}

pub fn wheel_matches(filename: &str, name: &str, version: &str) -> bool {
    let parts: Vec<_> = filename.split('-').collect();
    filename.ends_with(".whl")
        && !filename.contains(['/', '\\'])
        && matches!(parts.len(), 5 | 6)
        && canonicalize_pypi_name(parts[0]) == canonicalize_pypi_name(name)
        && parts[1] == version
}

pub fn rewrite_pdm_lock(
    text: &str,
    name: &str,
    version: &str,
    source: (&str, &str),
    filename: &str,
    sha256: &str,
) -> Result<String, String> {
    let (kind, location) = source;
    if !matches!(kind, "url" | "path")
        || sha256.len() != 64
        || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid PDM artifact source or SHA-256".into());
    }
    if !wheel_matches(filename, name, version) {
        return Err("PDM patch wheel does not match package".into());
    }
    let mut lock: DocumentMut = text.parse().map_err(|e| format!("invalid PDM lock: {e}"))?;
    lock_version(&lock)?;
    validate_strategy(&lock)?;
    let packages = lock
        .get("package")
        .and_then(Item::as_array_of_tables)
        .ok_or("missing PDM packages")?;
    let indices: Vec<_> = packages
        .iter()
        .enumerate()
        .filter(|(_, package)| {
            package
                .get("name")
                .and_then(Item::as_str)
                .is_some_and(|candidate| {
                    canonicalize_pypi_name(candidate) == canonicalize_pypi_name(name)
                })
        })
        .map(|(index, _)| index)
        .collect();
    if indices.is_empty() {
        return Err("missing PDM package".into());
    }
    let mut variants = std::collections::BTreeSet::new();
    let mut edits = Vec::new();
    for index in indices {
        let package = packages.get(index).ok_or("missing PDM package")?;
        if package.get("version").and_then(Item::as_str) != Some(version) {
            return Err("PDM locked version differs from installed version".into());
        }
        let mut extras = Vec::new();
        if let Some(value) = package.get("extras") {
            for extra in value.as_array().ok_or("invalid PDM extras")? {
                extras.push(extra.as_str().ok_or("invalid PDM extra")?.to_string());
            }
        }
        extras.sort();
        if !variants.insert(extras) {
            return Err("forked PDM package".into());
        }
        for field in [
            "url", "path", "git", "hg", "svn", "bzr", "editable", "source",
        ] {
            if let Some(existing) = package.get(field) {
                if field != kind || existing.as_str() != Some(location) {
                    return Err(format!("refusing existing PDM {field} source"));
                }
            }
        }
        let original_files = files_for(&lock, package).ok_or("missing PDM file hashes")?;
        if original_files.is_empty()
            || original_files.iter().any(|file| {
                !file
                    .as_inline_table()
                    .and_then(|file| file.get("hash"))
                    .and_then(Value::as_str)
                    .is_some_and(|hash| {
                        hash.strip_prefix("sha256:").is_some_and(|hex| {
                            hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                        })
                    })
            })
        {
            return Err("invalid PDM file hashes".into());
        }
        let files_key = legacy_files_key(package).ok_or("missing PDM files key")?;
        edits.push((index, package.contains_key("files"), files_key));
    }
    for (index, inline_files, files_key) in edits {
        let mut file = InlineTable::new();
        file.insert("file", Value::from(filename));
        file.insert(
            "hash",
            Value::from(format!("sha256:{}", sha256.to_ascii_lowercase())),
        );
        let mut files = Array::new();
        files.push(file);
        let package = lock
            .get_mut("package")
            .and_then(Item::as_array_of_tables_mut)
            .and_then(|packages| packages.get_mut(index))
            .ok_or("missing PDM package")?;
        package.insert(kind, value(location));
        if inline_files {
            package.insert("files", value(files));
        } else {
            let table = lock
                .get_mut("metadata")
                .and_then(|metadata| metadata.get_mut("files"))
                .and_then(Item::as_table_like_mut)
                .ok_or("missing PDM metadata.files")?;
            table.insert(&files_key, value(files));
        }
    }
    let rendered = preserve_line_endings(text, lock.to_string());
    let mut result = text.to_string();
    for (old, new) in pdm_lock_edits(text, &rendered, name)? {
        result = result.replacen(&old, &new, 1);
    }
    Ok(result)
}

pub fn pdm_lock_edits(
    original: &str,
    rewritten: &str,
    name: &str,
) -> Result<Vec<(String, String)>, String> {
    fn fragments(text: &str, name: &str) -> Result<Vec<String>, String> {
        let lock = toml_edit::Document::parse(text).map_err(|e| e.to_string())?;
        let packages = lock
            .get("package")
            .and_then(Item::as_array_of_tables)
            .ok_or("missing PDM packages")?;
        let mut result = Vec::new();
        let mut integrity_keys = std::collections::BTreeSet::new();
        for package in packages.iter().filter(|package| {
            package
                .get("name")
                .and_then(Item::as_str)
                .is_some_and(|candidate| {
                    canonicalize_pypi_name(candidate) == canonicalize_pypi_name(name)
                })
        }) {
            fn extend_span(table: &Table, span: &mut std::ops::Range<usize>) {
                for (_, item) in table.iter() {
                    if let Some(own) = item.span() {
                        span.start = span.start.min(own.start);
                        span.end = span.end.max(own.end);
                    }
                    if let Some(child) = item.as_table() {
                        extend_span(child, span);
                    }
                }
            }
            let mut span = package.span().ok_or("missing PDM package span")?;
            extend_span(package, &mut span);
            span.end += text[span.end..]
                .find(['\r', '\n'])
                .unwrap_or(text.len() - span.end);
            result.push(text[span].to_string());
            if !package.contains_key("files") {
                let key = legacy_files_key(package).ok_or("missing PDM files key")?;
                if !integrity_keys.insert(key.clone()) {
                    continue;
                }
                let table = lock
                    .get("metadata")
                    .and_then(|metadata| metadata.get("files"))
                    .and_then(Item::as_table)
                    .ok_or("missing PDM metadata.files")?;
                let start = table
                    .key(&key)
                    .and_then(|key| key.span())
                    .ok_or("missing PDM files key")?
                    .start;
                let end = table
                    .get(&key)
                    .and_then(Item::span)
                    .ok_or("missing PDM files span")?
                    .end;
                result.push(text[start..end].to_string());
            }
        }
        if result.is_empty() {
            return Err("missing PDM package fragments".into());
        }
        Ok(result)
    }
    let before = fragments(original, name)?;
    let after = fragments(rewritten, name)?;
    if before.len() != after.len() {
        return Err("PDM package fragments changed shape".into());
    }
    let mut edits = Vec::new();
    for (old, new) in before.into_iter().zip(after) {
        if old == new {
            continue;
        }
        if original.matches(&old).count() != 1 || rewritten.matches(&new).count() != 1 {
            return Err("ambiguous PDM rollback fragment".into());
        }
        edits.push((old, new));
    }
    Ok(edits)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WHEEL: &str = "urllib3-1.26.18-py2.py3-none-any.whl";
    const PATH: &str = "./.socket/vendor/pypi/e828efa5-5c6d-43f3-9909-03f5ac232b98/urllib3-1.26.18-py2.py3-none-any.whl";

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/pdm-native")
                .join(format!("{name}.lock")),
        )
        .unwrap()
    }

    #[test]
    fn native_formats_rewrite_and_reverse_byte_exactly() {
        for version in [
            "0.12.3",
            "2.8.2",
            "2.9.3",
            "2.10.4",
            "2.11.2",
            "2.17.3",
            "2.29.2",
            "0.12.3-extras",
            "2.29.2-extras",
        ] {
            for ending in ["\n", "\r\n"] {
                let original = fixture(version).replace('\n', ending);
                for (kind, source) in [("path", PATH), ("path", &PATH.replace('/', "\\")), ("url", "https://patch.socket.dev/patch/pypi/urllib3/1.26.18/7e52b8b6-53f2-4dc8-860a-1ae7ebd8be0e/e828efa5-5c6d-43f3-9909-03f5ac232b98/urllib3-1.26.18-py2.py3-none-any.whl")] {
                    let rewritten = rewrite_pdm_lock(&original, "urllib3", "1.26.18", (kind, source), WHEEL, &"a".repeat(64)).unwrap();
                    let lock: DocumentMut = rewritten.parse().unwrap();
                    let old: DocumentMut = original.parse().unwrap();
                    assert_eq!(old["metadata"]["content_hash"].as_str(), lock["metadata"]["content_hash"].as_str());
                    for pkg in lock["package"].as_array_of_tables().unwrap() {
                        if pkg["name"].as_str() != Some("urllib3") { continue; }
                        assert_eq!(pkg[kind].as_str(), Some(source));
                        let files = files_for(&lock, pkg).unwrap();
                        assert_eq!(files.len(), 1);
                        assert_eq!(files.get(0).unwrap().as_inline_table().unwrap()["hash"].as_str(), Some(format!("sha256:{}", "a".repeat(64)).as_str()));
                    }
                    assert_eq!(rewrite_pdm_lock(&rewritten, "urllib3", "1.26.18", (kind, source), WHEEL, &"a".repeat(64)).unwrap(), rewritten);
                    let mut reverted = rewritten.clone();
                    for (before, after) in pdm_lock_edits(&original, &rewritten, "urllib3").unwrap().into_iter().rev() {
                        reverted = reverted.replacen(&after, &before, 1);
                    }
                    assert_eq!(reverted, original);
                    if ending == "\r\n" { assert!(!rewritten.replace("\r\n", "").contains('\n')); }
                }
            }
        }
    }

    #[test]
    fn native_installers_that_lose_source_identity_refuse() {
        for version in ["1.15.5", "2.0.3", "2.1.5", "2.3.4", "2.6.1", "2.7.4"] {
            let original = fixture(version);
            assert!(rewrite_pdm_lock(
                &original,
                "urllib3",
                "1.26.18",
                ("path", PATH),
                WHEEL,
                &"a".repeat(64)
            )
            .unwrap_err()
            .contains("unsupported PDM lock_version"));
        }
    }

    #[test]
    fn unsafe_sources_forks_and_integrity_refuse_transactionally() {
        let original = fixture("2.29.2");
        for field in [
            "url = 'https://example.com/archive.whl'",
            "path = '../custom.whl'",
            "git = 'https://example.com/repo'",
            "hg = 'https://example.com/repo'",
            "svn = 'https://example.com/repo'",
            "bzr = 'https://example.com/repo'",
            "editable = false",
            "source = 'private'",
        ] {
            let text = original.replace(
                "name = \"urllib3\"",
                &format!("name = \"urllib3\"\n{field}"),
            );
            assert!(
                rewrite_pdm_lock(
                    &text,
                    "urllib3",
                    "1.26.18",
                    ("path", PATH),
                    WHEEL,
                    &"a".repeat(64)
                )
                .is_err(),
                "{field}"
            );
        }
        let duplicate = format!("{original}\n[[package]]\nname = 'urllib3'\nversion = '1.26.18'\n");
        assert!(rewrite_pdm_lock(
            &duplicate,
            "urllib3",
            "1.26.18",
            ("path", PATH),
            WHEEL,
            &"a".repeat(64)
        )
        .is_err());
        for text in [
            original.replace("sha256:", "md5:"),
            original.replace("4.5.1", "4.6.0"),
            original.replace("inherit_metadata", "unknown"),
            original.replace("version = \"1.26.18\"", "version = '1.26.19'"),
            original.replace("files = [", "files = 42\ninvalid = ["),
        ] {
            assert!(rewrite_pdm_lock(
                &text,
                "urllib3",
                "1.26.18",
                ("path", PATH),
                WHEEL,
                &"a".repeat(64)
            )
            .is_err());
        }
        assert!(rewrite_pdm_lock(
            &original,
            "requests",
            "1.26.18",
            ("path", PATH),
            WHEEL,
            &"a".repeat(64)
        )
        .is_err());
        assert!(rewrite_pdm_lock(
            &original,
            "urllib3",
            "1.26.18",
            ("path", PATH),
            WHEEL,
            "invalid"
        )
        .is_err());
    }
}
