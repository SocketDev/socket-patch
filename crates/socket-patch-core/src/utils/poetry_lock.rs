use toml_edit::{value, Array, DocumentMut, InlineTable, Item, Table, Value};

use crate::crawlers::python_crawler::canonicalize_pypi_name;

pub fn lock_version(lock: &DocumentMut) -> Result<&str, String> {
    let metadata = lock.get("metadata").ok_or("missing Poetry lock metadata")?;
    match metadata.get("lock-version").and_then(Item::as_str) {
        Some(version @ ("1.0" | "1.1" | "2.0" | "2.1")) => Ok(version),
        None if metadata
            .get("hashes")
            .and_then(Item::as_table_like)
            .is_some() =>
        {
            Ok("0")
        }
        _ => Err("unsupported Poetry lock version".into()),
    }
}

pub fn rewrite_poetry_lock(
    text: &str,
    name: &str,
    version: &str,
    source_type: &str,
    source_url: &str,
    filename: &str,
    sha256: &str,
) -> Result<Option<String>, String> {
    if !matches!(source_type, "file" | "url")
        || sha256.len() != 64
        || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid Poetry artifact source or SHA-256".into());
    }
    let parts: Vec<_> = filename.split('-').collect();
    if !filename.ends_with(".whl")
        || !matches!(parts.len(), 5 | 6)
        || canonicalize_pypi_name(parts[0]) != canonicalize_pypi_name(name)
        || parts[1] != version
        || filename.contains(['/', '\\'])
    {
        return Err("Poetry patch wheel does not match the locked package".into());
    }
    let mut lock: DocumentMut = text
        .parse()
        .map_err(|e| format!("invalid Poetry lock: {e}"))?;
    let format = lock_version(&lock)?.to_string();
    if format == "0" && source_type == "url" {
        return Err("Poetry 0.x ignores URL sources; hosted patches require Poetry >= 1.0".into());
    }
    let effective_url = if format == "1.0" && source_type == "url" {
        // Poetry 1.0 appends #egg without checking for an existing fragment.
        format!("{source_url}#sha256={sha256}&")
    } else {
        source_url.to_string()
    };
    let packages = lock
        .get_mut("package")
        .and_then(Item::as_array_of_tables_mut)
        .ok_or("missing Poetry packages")?;
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
        return Ok(None);
    }
    if indices.len() != 1 {
        return Err("forked Poetry package requires an unambiguous source".into());
    }
    let package = packages
        .get_mut(indices[0])
        .ok_or("missing Poetry package")?;
    if package.get("version").and_then(Item::as_str) != Some(version) {
        return Ok(None);
    }
    let package_name = package
        .get("name")
        .and_then(Item::as_str)
        .unwrap_or(name)
        .to_string();
    if let Some(source) = package.get("source") {
        if source.get("type").and_then(Item::as_str) != Some(source_type)
            || source.get("url").and_then(Item::as_str) != Some(effective_url.as_str())
        {
            return Err("refusing to replace an existing Poetry source".into());
        }
    }
    let mut entry = InlineTable::new();
    entry.insert("file", Value::from(filename));
    entry.insert("hash", Value::from(format!("sha256:{sha256}")));
    let mut files = Array::new();
    files.push(entry);
    let mut source = Table::new();
    source.insert("type", value(source_type));
    source.insert("url", value(effective_url));
    if matches!(format.as_str(), "0" | "1.0") {
        source.insert("reference", value(""));
    }
    package.insert("source", Item::Table(source));
    if format == "1.1" && source_type == "url" {
        package.insert("files", value(files.clone()));
    }
    if format.starts_with('2') {
        package.insert("files", value(files));
    } else if format == "0" {
        let mut hashes = Array::new();
        hashes.push(sha256);
        lock["metadata"]["hashes"][&package_name] = value(hashes);
    } else {
        lock["metadata"]["files"][&package_name] = value(files);
    }
    let mut rewritten = lock.to_string();
    if text.contains("\r\n") {
        rewritten = rewritten.replace("\r\n", "\n").replace('\n', "\r\n");
    }
    let edits = poetry_lock_edits(text, &rewritten, name)?;
    let mut result = text.to_string();
    for (original, replacement) in edits {
        result = result.replacen(&original, &replacement, 1);
    }
    Ok(Some(result))
}

pub fn poetry_lock_edits(
    original: &str,
    rewritten: &str,
    name: &str,
) -> Result<Vec<(String, String)>, String> {
    fn fragments(text: &str, name: &str) -> Result<Vec<String>, String> {
        let lock = toml_edit::Document::parse(text).map_err(|e| e.to_string())?;
        let package = lock
            .get("package")
            .and_then(Item::as_array_of_tables)
            .and_then(|packages| {
                packages.iter().find(|package| {
                    package
                        .get("name")
                        .and_then(Item::as_str)
                        .is_some_and(|value| {
                            canonicalize_pypi_name(value) == canonicalize_pypi_name(name)
                        })
                })
            })
            .ok_or("missing Poetry package")?;
        fn extend_span(table: &Table, span: &mut std::ops::Range<usize>) {
            if let Some(own) = table.span() {
                span.start = span.start.min(own.start);
                span.end = span.end.max(own.end);
            }
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
        let mut span = package.span().ok_or("missing Poetry package span")?;
        extend_span(package, &mut span);
        span.end += text[span.end..]
            .find(['\r', '\n'])
            .unwrap_or(text.len() - span.end);
        let mut result = vec![text[span].to_string()];
        let metadata = lock.get("metadata").ok_or("missing Poetry metadata")?;
        let format = metadata
            .get("lock-version")
            .and_then(Item::as_str)
            .unwrap_or("0");
        if !format.starts_with('2') {
            let field = if format == "0" { "hashes" } else { "files" };
            let table = metadata
                .get(field)
                .and_then(Item::as_table)
                .ok_or("missing Poetry integrity table")?;
            let package_name = package["name"].as_str().ok_or("missing package name")?;
            let start = table
                .key(package_name)
                .and_then(|key| key.span())
                .ok_or("missing Poetry integrity key")?
                .start;
            let end = table
                .get(package_name)
                .and_then(Item::span)
                .ok_or("missing Poetry integrity span")?
                .end;
            result.push(text[start..end].to_string());
        }
        Ok(result)
    }
    let before = fragments(original, name)?;
    let after = fragments(rewritten, name)?;
    let mut edits = Vec::new();
    for (old, new) in before.into_iter().zip(after) {
        if old == new {
            continue;
        }
        if original.matches(&old).count() != 1 || rewritten.matches(&new).count() != 1 {
            return Err("ambiguous Poetry rollback fragment".into());
        }
        edits.push((old, new));
    }
    Ok(edits)
}
